import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// runtime.onMessage is an extension-internal channel. Options pages and
// popups may have different MessageSender metadata depending on the browser.
// In particular sender.id, sender.url and sender.tab are all optional.
// External pages/extensions would need onMessageExternal, not registered here.
const source = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const start = source.indexOf("let vaultOperationQueue = Promise.resolve();");
const end = source.indexOf("chrome.runtime.onMessage.addListener", start);
assert.ok(start >= 0 && end > start);
const handlerCode = source.slice(start, end);

function harness(data = {
  username: "al25133@sic",
  password: "stored-university-password",
  scombzToken: "",
  settings: { autoLogin: true, autoFill: true, scombzAutoLogin: false }
}) {
  const log = [];
  const ctx = vm.createContext({
    passkeyAuthorizeConnect: async () => {},
    hasRiskConsent: async () => true,
    requireUnlocked: async () => ({ vault: {}, key: {}, data }),
    normalizeUsername: (value) => String(value).trim(),
    normalizeSettings: (value) => ({ ...value }),
    scombzApiLogin: async (username, password) => {
      log.push({ action: "login", username, password });
      return "new-test-token";
    },
    saveVaultData: async (_data, _key, _vault) => {
      log.push({ action: "save", data: structuredClone(data) });
    },
    withActiveScombzToken: async (_vault, _key, _data, callback) => callback(data.scombzToken)
  });
  vm.runInContext(handlerCode, ctx);
  return {
    handle: (message, sender = {}) => vm.runInContext("handleMessage", ctx)(message, sender),
    data,
    log
  };
}

test("uses stored university/ScombZ password and permits extension tab sender", async () => {
  const h = harness();
  const response = await h.handle(
    { type: "scombzConnect", username: "al25133@sic" },
    { id: "extension-id", tab: { id: 4 }, url: "moz-extension://uuid/options.html" }
  );
  assert.equal(response.ok, true);
  assert.deepEqual(h.log[0], {
    action: "login", username: "al25133@sic", password: "stored-university-password"
  });
  assert.equal(h.data.scombzToken, "new-test-token");
  assert.equal(h.data.settings.scombzAutoLogin, true);
  assert.equal(h.data.password, "stored-university-password");
});

test("uses one-time typed university password without persisting it", async () => {
  const h = harness({
    username: "al25133@sic",
    password: "",
    scombzToken: "",
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  });
  const response = await h.handle({
    type: "scombzConnect",
    username: "al25133@sic",
    accountPassword: "temporary-university-password"
  }, {});
  assert.equal(response.ok, true);
  assert.equal(h.log[0].password, "temporary-university-password");
  assert.equal(h.data.password, "");
  const saved = h.log.find((entry) => entry.action === "save");
  assert.equal(saved.data.password, "");
  assert.equal(saved.data.scombzToken, "new-test-token");
});

test("API connection cannot replace the saved username with an unsaved account", async () => {
  const h = harness();
  await assert.rejects(h.handle({
    type: "scombzConnect", username: "ab12345@sic", accountPassword: "new-account-password"
  }, {}), /先に大学アカウントを保存/);
  assert.equal(h.log.length, 0, "neither login nor a vault write may happen");
  assert.equal(h.data.username, "al25133@sic");
  assert.equal(h.data.password, "stored-university-password");
});

test("popup and options actions are not rejected when sender metadata is absent", async () => {
  const h = harness();
  const connected = await h.handle({ type: "scombzConnect" }, {});
  assert.equal(connected.ok, true);
  await assert.rejects(
    h.handle({ type: "scombzOpen" }, {}),
    /不明な要求です。/
  );
  const disconnected = await h.handle({ type: "scombzDisconnect" }, {});
  assert.equal(disconnected.ok, true);
  assert.equal(h.data.scombzToken, "");
});

test("only internal onMessage is registered, never onMessageExternal", () => {
  assert.match(source, /chrome\.runtime\.onMessage\.addListener/);
  assert.doesNotMatch(source, /chrome\.runtime\.onMessageExternal\.addListener/);
});

test("extension permissions keep network observation read-only and private pages unexposed", async () => {
  const manifest = JSON.parse(await readFile(new URL("../src/manifest.json", import.meta.url), "utf8"));
  assert.ok(manifest.permissions.includes("webRequest"));
  assert.ok(!manifest.permissions.includes("webRequestBlocking"));
  assert.ok(manifest.host_permissions.includes("https://scombz.shibaura-it.ac.jp/*"));
  assert.equal(manifest.web_accessible_resources, undefined);
});
