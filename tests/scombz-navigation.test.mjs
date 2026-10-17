import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const start = source.indexOf("const scombzPendingTabs = new Map();");
assert.ok(start > 0);
const navigationSource = source.slice(start);
const ORIGIN = "https://scombz.shibaura-it.ac.jp";
const MOBILE = "https://mobile.scombz.shibaura-it.ac.jp";
const HOME = ORIGIN + "/portal/home";

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
}

function harness({ cookie = null, connected = true, enabled = true, pausedOtkey = false, apiFails = false, passkey = false } = {}) {
  const visits = [], removals = [], fetched = [], approvals = [];
  let now = 1000000;
  let tabUrl = ORIGIN + "/portal/home";
  let releaseOtkey = () => {};
  const otkeyGate = new Promise((resolve) => {
    releaseOtkey = resolve;
  });
  if (!pausedOtkey) releaseOtkey();
  class FakeDate extends Date {
    static now() { return now; }
  }
  const events = {};
  const context = vm.createContext({
    URL, Map, Set, Date: FakeDate,
    SCOMBZ_ORIGIN: ORIGIN,
    SCOMBZ_HOST: "scombz.shibaura-it.ac.jp",
    getEncryptedVault: async () => ({ unlockMode: "device" }),
    getUnlockMode: vault => vault?.unlockMode || "password",
    requireUnlocked: async () => ({
      vault: {}, key: {},
      data: {
        scombzToken: connected ? "test-bearer" : "",
        settings: { scombzAutoLogin: enabled }
      }
    }),
    normalizeSettings: (settings) => settings,
    queueVaultOperation: operation => operation(),
    withActiveScombzToken: async (_v, _k, data, callback) =>
      callback(data.scombzToken),
    passkeyCancelTarget: async () => {},
    passkeyTabRemoved: async () => {},
    passkeyConfig: async () => passkey ? { credentialId: "registered" } : null,
    hasRiskConsent: async () => true,
    passkeyRequestLogin: async (tabId, resumeUrl, failed401, targetUrl) => {
      approvals.push({ tabId, resumeUrl, failed401, targetUrl });
    },
    scombzGetOtkey: async (token) => {
      fetched.push(token);
      await otkeyGate;
      if (apiFails) throw new Error("API unavailable");
      return "mock-otkey";
    },
    scombzBridgeUrl: (otkey, ...args) => {
      // The bridge MUST always use home; no arbitrary course or query path.
      assert.equal(otkey, "mock-otkey");
      assert.deepEqual(args, []);
      return MOBILE + "/" + otkey + "/portal/home";
    },
    chrome: {
      runtime: {
        onInstalled: { addListener: () => {} },
        onStartup: { addListener: () => {} }
      },
      cookies: {
        onChanged: { addListener: (fn) => { events.cookieChanged = fn; } },
        get: async () => cookie,
        remove: async (options) => {
          removals.push(options);
          cookie = null;
        }
      },
      tabs: {
        get: async (id) => ({ id, url: id === 4 ? tabUrl : ORIGIN + "/login" }),
        update: async (_tabId, options) => {
          if (options.url) {
            tabUrl = options.url;
            visits.push(options.url);
          }
        },
        onRemoved: { addListener: (fn) => { events.removed = fn; } }
      },
      webRequest: {
        onBeforeRedirect: { addListener: (fn) => { events.redirect = fn; } },
        onCompleted: { addListener: (fn) => { events.complete = fn; } }
      },
      webNavigation: {
        onBeforeNavigate: { addListener: (fn) => { events.before = fn; } },
        onCommitted: { addListener: (fn) => { events.commit = fn; } },
        onCompleted: { addListener: (fn) => { events.navCompleted = fn; } }
      }
    }
  });
  vm.runInContext(navigationSource, context);
  return {
    events, visits, removals, fetched, approvals,
    approve: () => vm.runInContext("passkeyResumeLogin", context)(approvals.at(-1)),
    get url() { return tabUrl; },
    set url(value) { tabUrl = value; },
    setCookie: (value) => { cookie = value; },
    advance: (ms) => { now += ms; },
    releaseOtkey,
    redirect: async (url, redirectUrl = ORIGIN + "/login", method = "GET") => {
      events.redirect({
        type: "main_frame", statusCode: 302, tabId: 4, url, redirectUrl, method
      });
      await settle();
    },
    commit: async (url) => {
      tabUrl = url;
      events.commit({ frameId: 0, tabId: 4, url });
      await settle();
    },
    // Simulate a browser where onCommitted fires before chrome.tabs.get()
    // reports the new /login URL (most relevant on page reloads).
    commitBeforeTabUrlUpdates: async (url) => {
      events.commit({ frameId: 0, tabId: 4, url });
      await settle();
    },
    completeLogin: async (url = ORIGIN + "/login") => {
      tabUrl = url;
      events.navCompleted({ frameId: 0, tabId: 4, url });
      await settle();
    },
    completeHome: async () => {
      tabUrl = HOME;
      events.navCompleted({ frameId: 0, tabId: 4, url: HOME });
      await settle();
    },
    completed401: async (url, method = "GET") => {
      tabUrl = url;
      events.complete({
        type: "main_frame", tabId: 4, url,
        method, statusCode: 401
      });
      await settle();
    }
  };
}

test("server redirect only prefetches OTKEY and never hijacks pending navigation", async () => {
  const h = harness({ cookie: { name: "SESSION", value: "stale", storeId: "store1" } });
  await h.redirect(ORIGIN + "/lms/course?idnumber=course123");
  assert.equal(h.fetched.length, 1);
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.removals, []);
  // Only after Chrome/Firefox finishes the redirect to login may we navigate.
  await h.commit(ORIGIN + "/login");
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
  assert.equal(h.removals.length, 1);
  assert.equal(h.removals[0].storeId, "store1");
  // On authenticated home, the original GET destination is restored.
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.deepEqual(h.visits, [
    MOBILE + "/mock-otkey/portal/home",
    ORIGIN + "/lms/course?idnumber=course123"
  ]);
});

test("original GET page is restored even when home onCommitted has stale tab.url", async () => {
  const h = harness({ cookie: { name: "SESSION", value: "expired" } });
  const deepLink = ORIGIN + "/lms/course?idnumber=restorable";
  await h.redirect(deepLink);
  await h.commit(ORIGIN + "/login");
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
  h.setCookie({ name: "SESSION", value: "fresh" });
  // onCommitted fires before tabs.get learns that /portal/home has loaded.
  await h.commitBeforeTabUrlUpdates(HOME);
  assert.equal(h.visits.length, 2);
  await h.completeHome();
  assert.deepEqual(h.visits, [
    MOBILE + "/mock-otkey/portal/home",
    deepLink
  ]);
  // A duplicate completion must not navigate again.
  h.events.navCompleted({ frameId: 0, tabId: 4, url: HOME });
  await settle();
  assert.equal(h.visits.length, 2);
});

test("reloading /login recovers even if tab.url lags behind onCommitted", async () => {
  const h = harness({ cookie: { name: "SESSION", value: "expired" } });
  // The browser reloads /login, but chrome.tabs.get() is stale at commit.
  h.url = ORIGIN + "/portal/home";
  await h.commitBeforeTabUrlUpdates(ORIGIN + "/login");
  assert.equal(h.visits.length, 1);
  assert.equal(h.fetched.length, 1);
  // Commit is authoritative even when tabs.get still has the old URL.
  const attempts = h.events; // only event listeners, no hidden test hooks
  assert.ok(attempts.navCompleted);
  await h.completeLogin(ORIGIN + "/login");
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
  assert.equal(h.fetched.length, 1);
});

test("a direct /login reload without an upstream redirect still renews", async () => {
  const h = harness({ cookie: null });
  h.url = ORIGIN + "/login";
  await h.commit(ORIGIN + "/login");
  // A real reload may report the same address for both events; renewal must
  // start once and not make a duplicate bridge navigation.
  await h.completeLogin(ORIGIN + "/login");
  assert.equal(h.fetched.length, 1);
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
});

test("normal navigation without SESSION does not prematurely rewrite the URL", async () => {
  const h = harness({ cookie: null });
  await h.commit(HOME);
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.fetched, []);
});

test("direct login fallback renews using home bridge", async () => {
  const h = harness({ cookie: { name: "SESSION", value: "stale" } });
  await h.commit(ORIGIN + "/login?returnUrl=%2Flms%2Fcourse");
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
});

test("401 main frame triggers renewal only once response completes", async () => {
  const h = harness({ cookie: { name: "SESSION", value: "stale" } });
  await h.completed401(ORIGIN + "/portal/home");
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
  const no401 = harness({ cookie: { name: "SESSION", value: "good" } });
  no401.events.complete({
    type: "main_frame", tabId: 4,
    url: ORIGIN + "/portal/home", method: "GET", statusCode: 200
  });
  await settle();
  assert.deepEqual(no401.visits, []);
});

test("POST redirect does not replay a form submission", async () => {
  const h = harness({ cookie: null });
  await h.redirect(ORIGIN + "/lms/submit", ORIGIN + "/login", "POST");
  await h.commit(ORIGIN + "/login");
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
});

test("user navigating away while OTKEY is fetching is never taken back to login", async () => {
  const h = harness({ cookie: null, pausedOtkey: true });
  await h.redirect(ORIGIN + "/lms/task");
  await h.commit(ORIGIN + "/login");
  h.url = "https://example.com/somewhere";
  h.releaseOtkey();
  await settle();
  assert.deepEqual(h.visits, []);
});

test("duplicate commits and redirects do not generate simultaneous OTKEY exchanges", async () => {
  const h = harness({ cookie: null, pausedOtkey: true });
  await h.redirect(ORIGIN + "/portal/home");
  await h.commit(ORIGIN + "/login");
  await h.commit(ORIGIN + "/login");
  assert.equal(h.fetched.length, 1);
  h.releaseOtkey();
  await settle();
  assert.equal(h.visits.length, 1);
});

test("rate limiting permits two renewals per minute before halting", async () => {
  const h = harness({ cookie: null });
  await h.commit(ORIGIN + "/login");
  assert.equal(h.visits.length, 1);
  h.advance(2600);
  await h.commit(ORIGIN + "/login");
  assert.equal(h.visits.length, 2);
  h.advance(2600);
  await h.commit(ORIGIN + "/login");
  assert.equal(h.visits.length, 2);
  h.advance(61000);
  await h.commit(ORIGIN + "/login");
  assert.equal(h.visits.length, 3);
});

test("ignores cross-origin, logout and subresource authentication events", async () => {
  const h = harness();
  await h.redirect(ORIGIN + "/logout", ORIGIN + "/login");
  await h.redirect(ORIGIN + "/portal/home", "https://example.com/login");
  await h.redirect("https://example.com/home", ORIGIN + "/login");
  h.events.redirect({
    type: "xmlhttprequest", tabId: 4,
    url: ORIGIN + "/lms/task",
    redirectUrl: ORIGIN + "/login", method: "GET"
  });
  await h.commit(ORIGIN + "/logout");
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.fetched, []);
  for (const options of [{ enabled: false }, { connected: false }]) {
    const disabled = harness(options);
    await disabled.commit(ORIGIN + "/login");
    assert.deepEqual(disabled.visits, []);
  }
});

test("explicit logout does not initiate reauthentication or restore unsafe destinations", async () => {
  const h = harness();
  await h.redirect(ORIGIN + "/portal/logout");
  await h.commit(ORIGIN + "/login");
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.fetched, []);
});



test("API failure leaves university login usable and suppresses duplicate requests", async () => {
  const h = harness({ apiFails: true });
  await h.redirect(ORIGIN + "/lms/task");
  await h.commit(ORIGIN + "/login");
  await h.completeLogin();
  assert.equal(h.fetched.length, 1);
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.removals, []);
  assert.equal(h.url, ORIGIN + "/login");
});

test("overlapping commit and completion reserve one exchange before tabs.get resolves", async () => {
  const h = harness({ pausedOtkey: true });
  h.url = ORIGIN + "/login";
  const details = { tabId: 4, frameId: 0, url: h.url };
  h.events.commit(details);
  h.events.navCompleted(details);
  h.events.redirect({ type: "main_frame", tabId: 4, method: "GET",
    url: HOME, redirectUrl: h.url, statusCode: 302 });
  await settle();
  h.releaseOtkey();
  await settle();
  assert.equal(h.fetched.length, 1);
  assert.equal(h.visits.length, 1);
});

test("logout during OTKEY acquisition cancels the pending authentication", async () => {
  const h = harness({ pausedOtkey: true });
  await h.redirect(ORIGIN + "/lms/task");
  await h.commit(ORIGIN + "/login");
  h.events.before({ tabId: 4, frameId: 0, url: ORIGIN + "/logout" });
  h.releaseOtkey();
  await settle();
  await h.commit(ORIGIN + "/login");
  assert.deepEqual(h.visits, []);
  assert.deepEqual(h.removals, []);
});

test("separate tabs acquire independently while each tab deduplicates", async () => {
  const h = harness({ pausedOtkey: true });
  await h.redirect(ORIGIN + "/lms/task");
  await h.commit(ORIGIN + "/login");
  h.events.commit({ tabId: 5, frameId: 0, url: ORIGIN + "/login" });
  h.events.navCompleted({ tabId: 5, frameId: 0, url: ORIGIN + "/login" });
  await settle();
  assert.equal(h.fetched.length, 2);
  h.releaseOtkey();
  await settle();
  assert.equal(h.visits.length, 2);
});

test("POST 401 recovers without saving the POST destination", async () => {
  const h = harness();
  await h.completed401(ORIGIN + "/lms/submit", "POST");
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
});

test("mobile bridge navigation preserves the original GET destination", async () => {
  const h = harness();
  const original = ORIGIN + "/lms/course?idnumber=bridge";
  await h.redirect(original);
  await h.commit(ORIGIN + "/login");
  const bridge = MOBILE + "/mock-otkey/portal/home";
  h.events.before({ tabId: 4, frameId: 0, url: bridge });
  await h.commit(bridge);
  h.events.before({ tabId: 4, frameId: 0, url: HOME });
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commitBeforeTabUrlUpdates(HOME);
  assert.deepEqual(h.visits, [bridge, original]);
});

test("navigation away before commit cancels fetching even with a stale tab URL", async () => {
  const h = harness({ pausedOtkey: true });
  await h.commit(ORIGIN + "/login");
  h.events.before({ tabId: 4, frameId: 0, url: "https://example.com/" });
  h.releaseOtkey();
  await settle();
  assert.deepEqual(h.visits, []);
});

test("optional local passkey mode waits for fresh approval before every OTKEY request", async () => {
  const h = harness({ passkey: true });
  const original = ORIGIN + "/lms/course?idnumber=protected";
  await h.redirect(original);
  assert.deepEqual(h.fetched, []);
  assert.equal(h.approvals.length, 0);
  await h.commit(ORIGIN + "/login");
  await h.completeLogin();
  assert.equal(h.approvals.length, 1);
  assert.deepEqual(h.fetched, []);
  assert.deepEqual(h.visits, []);
  await h.approve();
  assert.equal(h.fetched.length, 1);
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.equal(h.visits.at(-1), original);
  h.advance(3000);
  await h.redirect(original);
  await h.commit(ORIGIN + "/login");
  assert.equal(h.approvals.length, 2);
  assert.equal(h.fetched.length, 1);
});

test("approval cannot resume a tab that navigated away or logged out", async () => {
  for (const url of ["https://example.com/", ORIGIN + "/logout"]) {
    const h = harness({ passkey: true });
    await h.commit(ORIGIN + "/login");
    h.events.before({ tabId: 4, frameId: 0, url });
    await assert.rejects(h.approve());
    assert.deepEqual(h.fetched, []);
    assert.deepEqual(h.visits, []);
  }
});

test("POST recovery with local confirmation never restores the submission URL", async () => {
  const h = harness({ passkey: true });
  await h.redirect(ORIGIN + "/lms/submit", ORIGIN + "/login", "POST");
  await h.commit(ORIGIN + "/login");
  await h.approve();
  h.setCookie({ name: "SESSION", value: "fresh" });
  await h.commit(HOME);
  assert.deepEqual(h.visits, [MOBILE + "/mock-otkey/portal/home"]);
});
