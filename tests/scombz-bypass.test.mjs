import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const background = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const start = background.indexOf("// Optional browser-level redirect:");
const end = background.indexOf("function isTargetSender(", start);
assert.ok(start >= 0 && end > start);
const source = background.slice(start, end);
const origin = "https://scombz.shibaura-it.ac.jp";
const authPage = "chrome-extension://mock/auth-redirect.html";
const bridge = "https://mobile.scombz.shibaura-it.ac.jp/testkey/portal/home";

function harness({ connected = true, bypass = true, token = "testkey", logout = false } = {}) {
  const data = {
    scombzToken: connected ? "bearer" : "",
    settings: {
      scombzAutoLogin: true,
      scombzAvoidLoginPage: bypass
    }
  };
  const pending = new Map();
  const restore = new Map();
  const changes = [];
  let tabUrl = authPage;
  let rules = [];
  const ctx = vm.createContext({
    URL, Date, Set, Map,
    SCOMBZ_ORIGIN: origin,
    SCOMBZ_HOME: origin + "/portal/home",
    scombzPendingTabs: pending,
    scombzRestoreTabs: restore,
    scombzQueueRenewal: (id) => {
      if (pending.has(id)) return pending.get(id);
      const p = { started: false, resumeUrl: origin + "/lms/task",
        otkeyPromise: token ? Promise.resolve(token) : Promise.reject(new Error("API unavailable")) };
      pending.set(id, p);
      return p;
    },
    scombzRetryAllowed: () => true,
    scombzBridgeUrl: () => bridge,
    requireUnlocked: async () => ({ vault: {}, key: {}, data }),
    normalizeSettings: (value) => value,
    saveVaultData: async () => {},
    chrome: {
      runtime: { getURL: () => authPage },
      declarativeNetRequest: {
        getDynamicRules: async () => rules,
        updateDynamicRules: async ({ removeRuleIds, addRules }) => {
          changes.push({ removeRuleIds, addRules });
          rules = rules.filter(r => !removeRuleIds.includes(r.id)).concat(addRules);
        }
      },
      tabs: {
        get: async () => ({ id: 4, url: tabUrl }),
        update: async (_id, { url }) => { tabUrl = url; }
      },
      cookies: { get: async () => null }
    }
  });
  vm.runInContext(source, ctx);
  if (logout) vm.runInContext("scombzBypassCancelledTabs.add(4)", ctx);
  const run = (fn) => vm.runInContext(fn, ctx);
  return {
    data, pending, restore, changes, run,
    get rules() { return rules; },
    get tabUrl() { return tabUrl; }
  };
}

test("opt-in DNR intercept only matches ScombZ main-frame /login", async () => {
  const h = harness();
  await h.run("scombzSyncBypassRule()");
  assert.equal(h.rules.length, 1);
  const rule = h.rules[0];
  assert.equal(rule.action.redirect.extensionPath, "/auth-redirect.html");
  assert.deepEqual(Array.from(rule.condition.resourceTypes), ["main_frame"]);
  const filter = new RegExp(rule.condition.regexFilter);
  assert.ok(filter.test(origin + "/login"));
  assert.ok(filter.test(origin + "/portal/login?next=abc"));
  assert.equal(filter.test(origin + "/lms/login-help"), false);
  assert.equal(filter.test("https://example.com/login"), false);
  await h.run("scombzSyncBypassRule()");
  assert.equal(h.changes.length, 1, "same rule should not be installed twice");
});

test("no interception if API is disconnected or switch is off", async () => {
  for (const args of [{ connected: false }, { bypass: false }]) {
    const h = harness(args);
    await h.run("scombzSyncBypassRule()");
    assert.equal(h.rules.length, 0);
  }
});

test("intercepted login exchanges OTKEY and restores original deep link afterwards", async () => {
  const h = harness();
  await h.run("scombzSyncBypassRule()");
  assert.equal((await h.run('scombzRunBypass({url:"'+authPage+'",tab:{id:4}})')).ok, true);
  assert.equal(h.tabUrl, bridge);
  assert.equal(h.restore.get(4).url, origin + "/lms/task");
  assert.equal(h.pending.size, 0);
});

test("API failure disables interception and returns to university login", async () => {
  const h = harness({ token: "" });
  await h.run("scombzSyncBypassRule()");
  const result = await h.run('scombzRunBypass({url:"'+authPage+'",tab:{id:4}})');
  assert.equal(result.ok, false);
  assert.equal(h.tabUrl, origin + "/login");
  assert.equal(h.data.settings.scombzAvoidLoginPage, false);
  assert.equal(h.rules.length, 0);
});

test("explicit logout never silently logs back in", async () => {
  const h = harness({ logout: true });
  await h.run("scombzSyncBypassRule()");
  const result = await h.run('scombzRunBypass({url:"'+authPage+'",tab:{id:4}})');
  assert.equal(result.ok, false);
  assert.equal(h.tabUrl, origin + "/login");
  assert.equal(h.rules.length, 0);
});

test("rejects forged bypass requests from other extension pages", async () => {
  const h = harness();
  await assert.rejects(
    h.run('scombzRunBypass({url:"chrome-extension://mock/options.html",tab:{id:4}})'),
    /認証ページ以外/
  );
  assert.equal(h.tabUrl, authPage);
});

test("browser manifests ship web-accessible interceptor and fixed 0.7.0 version", async () => {
  const [manifestText, packageText, html, js] = await Promise.all([
    "../src/manifest.json", "../package.json",
    "../src/auth-redirect.html", "../src/auth-redirect.js"
  ].map(path => readFile(new URL(path, import.meta.url), "utf8")));
  const manifest = JSON.parse(manifestText);
  assert.equal(manifest.version, "0.7.0");
  assert.equal(JSON.parse(packageText).version, "0.7.0");
  assert.equal(manifest.name, "ScombZ Login Helper");
  assert.ok(manifest.permissions.includes("declarativeNetRequestWithHostAccess"));
  assert.ok(manifest.web_accessible_resources.some(resource =>
    resource.resources.includes("auth-redirect.html") &&
    resource.matches.includes(origin + "/*")
  ));
  assert.match(html, /auth-redirect\.js/);
  assert.match(html, /id="recoveryPanel"[^>]*hidden/);
  assert.doesNotMatch(html, /セッションを更新しています/);
  assert.match(js, /scombzBypassLogin/);
  assert.match(js, /setTimeout\(/);
});
