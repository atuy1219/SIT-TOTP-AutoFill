import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/scombz-auth.js", import.meta.url), "utf8");

function createContext(handler = async () => {
  throw new Error("Unexpected network call");
}) {
  const visits = [];
  const context = vm.createContext({
    URL,
    TextEncoder,
    AbortController,
    setTimeout,
    clearTimeout,
    fetch: handler,
    chrome: {
      tabs: {
        update: async (tabId, opts) => visits.push({ tabId, url: opts.url }),
        create: async (opts) => visits.push({ url: opts.url })
      }
    }
  });
  vm.runInContext(source, context);
  return {
    evaluate: (code) => vm.runInContext(code, context),
    visits
  };
}

function response(body, status = 200) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: () => null },
    text: async () => JSON.stringify(body)
  };
}

test("student ID supports normalized ADFS account format", () => {
  const ctx = createContext();
  assert.equal(ctx.evaluate('scombzStudentId("al25133@sic")'), "AL25133");
  assert.equal(ctx.evaluate('scombzStudentId("AL25133")'), "AL25133");
  assert.throws(() => ctx.evaluate('scombzStudentId("someone@outlook.com")'));
});

test("login sends the password only to the university mobile API", async () => {
  let sent = null;
  const ctx = createContext(async (url, options) => {
    sent = { url, options };
    return response({ status: "OK", token: "test-bearer" });
  });
  assert.equal(await ctx.evaluate('scombzApiLogin("al25133@sic", "test-password")'), "test-bearer");
  assert.equal(sent.url, "https://smob.sic.shibaura-it.ac.jp/smob/api/login");
  assert.equal(sent.options.method, "POST");
  assert.equal(sent.options.redirect, "manual");
  assert.equal(sent.options.credentials, "omit");
  assert.deepEqual(JSON.parse(sent.options.body), {
    user: "AL25133", pass: "test-password"
  });
});

test("open uses the OTKEY redirect in the browser, not cross-origin fetch", async () => {
  const calls = [];
  const ctx = createContext(async (url, options) => {
    calls.push({ url, options });
    return response({ status: "OK", otkey: "short-lived-key" });
  });
  await ctx.evaluate('scombzOpenWithToken("test-bearer", {tabId: 7})');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://smob.sic.shibaura-it.ac.jp/smob/api/otkey");
  assert.equal(calls[0].options.headers.Authorization, "Bearer test-bearer");
  assert.deepEqual(ctx.visits, [{
    tabId: 7,
    url: "https://mobile.scombz.shibaura-it.ac.jp/short-lived-key/portal/home"
  }]);
});

test("automatic renewal requires an existing ScombZ tab", async () => {
  const ctx = createContext();
  await assert.rejects(
    ctx.evaluate('scombzOpenWithToken("test-bearer")'),
    /認証先タブ/
  );
  assert.equal(ctx.visits.length, 0);
});

test("OTKEY bridge is always rooted at portal/home, not an arbitrary deep link", () => {
  const ctx = createContext();
  assert.equal(
    ctx.evaluate('scombzBridgeUrl("ticket")'),
    "https://mobile.scombz.shibaura-it.ac.jp/ticket/portal/home"
  );
  assert.equal(
    ctx.evaluate('scombzBridgeUrl("ticket", "https://evil.example/")'),
    "https://mobile.scombz.shibaura-it.ac.jp/ticket/portal/home"
  );
});

test("401 API response signals reconnect without exposing the token", async () => {
  const ctx = createContext(async () => response({ status: "NG" }, 401));
  await assert.rejects(ctx.evaluate('scombzGetOtkey("test-bearer")'), (err) => {
    assert.equal(err.authExpired, true);
    assert.doesNotMatch(err.message, /test-bearer/);
    return true;
  });
});
