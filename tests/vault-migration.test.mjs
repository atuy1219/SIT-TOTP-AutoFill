import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = (await readFile(new URL("../src/background.js", import.meta.url), "utf8"))
  .replace('importScripts("scombz-auth.js");', "");

function memoryStorage() {
  const values = {};
  return {
    values,
    get: async (key) => typeof key === "string" ? { [key]: values[key] } : { ...values },
    set: async (items) => Object.assign(values, items),
    remove: async (keys) => {
      for (const k of Array.isArray(keys) ? keys : [keys]) delete values[k];
    },
    setAccessLevel: async () => {}
  };
}

function harness() {
  const local = memoryStorage(), session = memoryStorage();
  const listener = { addListener: () => {} };
  const chrome = {
    storage: { local, session },
    runtime: { onInstalled: listener, onStartup: listener, onMessage: listener },
    webNavigation: { onBeforeNavigate: listener, onCommitted: listener, onCompleted: listener },
    webRequest: { onBeforeRedirect: listener, onCompleted: listener },
    tabs: { onRemoved: listener }
  };
  const ctx = vm.createContext({
    chrome,
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    URL,
    SCOMBZ_HOST: "scombz.shibaura-it.ac.jp",
    SCOMBZ_ORIGIN: "https://scombz.shibaura-it.ac.jp",
    Uint8Array,
    btoa,
    atob,
    setTimeout,
    clearTimeout,
    Map,
    scombzStudentId: (value) => String(value).split("@")[0].toUpperCase()
  });
  vm.runInContext(source, ctx);
  const call = vm.runInContext("handleMessage", ctx);
  return { ctx, chrome, local, session, call };
}

test("fresh vault is device encrypted and never requests master password", async () => {
  const h = harness();
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const init = await h.call({
    type: "initialize",
    username: "al25133",
    accountPassword: "university-password",
    secret: seed,
    settings: { autoLogin: true, autoFill: true, scombzAutoLogin: true }
  }, {});
  assert.equal(init.ok, true);
  assert.equal(init.unlockMode, "device");
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "device");
  assert.ok(h.local.values.sitAdfsDeviceKey);

  await h.session.remove("sitAdfsSessionKey");
  const status = await h.call({ type: "status" }, {});
  assert.equal(status.unlocked, true);

  const exported = await h.call({ type: "exportBackupData" }, {});
  assert.equal(exported.data.secret, seed);
  assert.equal(exported.data.username, "al25133@sic");
  assert.equal(exported.data.password, undefined);
  assert.equal(exported.data.scombzToken, undefined);
  assert.equal(JSON.stringify(exported).includes("university-password"), false);
});

test("password-protected legacy vault migrates once without losing TOTP seed", async () => {
  const h = harness();
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await vm.runInContext("deriveVaultKey", h.ctx)(
    "old-password", salt, true
  );
  const original = {
    secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    username: "al25133@sic",
    password: "old-university-password",
    scombzToken: "token",
    settings: { autoLogin: true, autoFill: true, scombzAutoLogin: true }
  };
  const vault = await vm.runInContext("encryptVault", h.ctx)(
    original, key, salt, "password"
  );
  await h.local.set({ sitAdfsEncryptedVault: vault });
  assert.equal((await h.call({ type: "status" }, {})).unlockMode, "legacy");

  const migrated = await h.call({
    type: "unlock", masterPassword: "old-password"
  }, {});
  assert.equal(migrated.migrated, true);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "device");

  await h.session.remove("sitAdfsSessionKey");
  assert.equal((await h.call({ type: "status" }, {})).unlocked, true);
  const exportData = (await h.call({ type: "exportBackupData" }, {})).data;
  assert.equal(exportData.secret, original.secret);
});

test("passwordless backup import preserves seed but excludes credentials", async () => {
  const h = harness();
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const result = await h.call({ type: "importBackupData", data: {
    secret: seed, username: "al25133@sic",
    password: "injected-password", scombzToken: "injected-token",
    settings: { autoLogin: true, autoFill: true, scombzAutoLogin: true }
  } }, {});
  assert.equal(result.ok, true);
  const exported = (await h.call({ type: "exportBackupData" }, {})).data;
  assert.equal(exported.secret, seed);
  assert.equal(exported.settings.autoLogin, false);
  assert.equal(exported.settings.scombzAutoLogin, false);
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, false);
  assert.equal((await h.call({ type: "getConfig" }, {})).scombzConnected, false);
});


test("university username and password are required even if legacy automation is off", async () => {
  const h = harness();
  const base = {
    type: "initialize",
    secret: "",
    settings: {
      autoLogin: false, autoFill: false,
      autoSelectProvider: false, scombzAutoLogin: false
    }
  };
  await assert.rejects(
    h.call({ ...base, username: "al25133", accountPassword: "" }, {}),
    /大学アカウントのパスワード/
  );
  await assert.rejects(
    h.call({ ...base, username: "", accountPassword: "university-password" }, {}),
    /大学ユーザー名/
  );
  assert.equal(h.local.values.sitAdfsEncryptedVault, undefined);
  const result = await h.call({
    ...base, username: "al25133", accountPassword: "university-password"
  }, {});
  assert.equal(result.ok, true);
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, true);
});

test("saved university password is reused without needing to type it again", async () => {
  const h = harness();
  await h.call({
    type: "initialize",
    username: "al25133",
    accountPassword: "original-university-password",
    secret: "",
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  const saved = await h.call({
    type: "saveConfig",
    username: "al25133",
    accountPassword: "",
    secret: "",
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  assert.equal(saved.ok, true);
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, true);
  // Older settings UIs must not be able to clear the now-mandatory password.
  await h.call({
    type: "saveConfig", username: "al25133", accountPassword: "",
    clearAccountPassword: true,
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  const data = await vm.runInContext("requireUnlocked", h.ctx)();
  assert.equal(data.data.password, "original-university-password");
});

test("imported passwordless backup can be recovered but requires credential setup before saving", async () => {
  const h = harness();
  await h.call({
    type: "importBackupData",
    data: {
      username: "al25133@sic", secret: "",
      settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
    }
  }, {});
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, false);
  await assert.rejects(
    h.call({
      type: "saveConfig", username: "al25133@sic",
      accountPassword: "",
      settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
    }, {}),
    /大学アカウントのパスワード/
  );
  const updated = await h.call({
    type: "saveConfig", username: "al25133@sic",
    accountPassword: "new-university-password",
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  assert.equal(updated.ok, true);
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, true);
});


test("checkbox autosave cannot persist pending password, student ID, or TOTP seed", async () => {
  const h = harness();
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  await h.call({
    type: "initialize", username: "al25133", accountPassword: "saved-account-password",
    secret: seed,
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  const result = await h.call({
    type: "saveSettings",
    // Unexpected credential properties must never be consumed by this case.
    username: "ab12345", accountPassword: "UNSAVED_PASSWORD",
    secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    settings: { autoLogin: true, autoFill: true, scombzAutoLogin: false }
  }, {});
  assert.equal(result.ok, true);
  const unlocked = await vm.runInContext("requireUnlocked", h.ctx)();
  assert.equal(unlocked.data.username, "al25133@sic");
  assert.equal(unlocked.data.password, "saved-account-password");
  assert.equal(unlocked.data.secret, seed);
  assert.equal(unlocked.data.settings.autoLogin, true);
  assert.equal(unlocked.data.settings.autoFill, true);
});

test("explicit account and seed saves update only their own fields", async () => {
  const h = harness();
  await h.call({
    type: "initialize", username: "al25133", accountPassword: "old-password",
    secret: "",
    settings: { autoLogin: false, autoFill: false, scombzAutoLogin: false }
  }, {});
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  await h.call({
    type: "saveSecret",
    secret: seed, username: "ab12345", accountPassword: "UNSAVED_PASSWORD",
    settings: { autoLogin: true, autoFill: true }
  }, {});
  let data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.secret, seed);
  assert.equal(data.password, "old-password");
  assert.equal(data.username, "al25133@sic");
  assert.equal(data.settings.autoFill, false);
  await h.call({
    type: "saveAccount",
    username: "al25133",
    accountPassword: "new-password",
    secret: "UNSAVED_SEED",
    settings: { autoLogin: true, autoFill: true }
  }, {});
  data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.password, "new-password");
  assert.equal(data.secret, seed);
  assert.equal(data.settings.autoFill, false);
  await assert.rejects(
    h.call({ type: "saveSecret", secret: "invalid" }, {}),
    /32文字のBase32/
  );
  data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.secret, seed);
});

test("enabling TOTP autofill without a saved seed rejects auto-save", async () => {
  const h = harness();
  await h.call({
    type: "initialize", username: "al25133", accountPassword: "saved-password",
    secret: "", settings: { autoFill: false, scombzAutoLogin: false }
  }, {});
  await assert.rejects(
    h.call({ type: "saveSettings", settings: {
      autoFill: true, scombzAutoLogin: false
    } }, {}),
    /TOTP自動入力を有効にするにはシードを保存/
  );
  const data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.settings.autoFill, false);
});

test("changing university username requires an explicit matching new password", async () => {
  const h = harness();
  await h.call({
    type: "initialize", username: "al25133", accountPassword: "old-password",
    secret: "", settings: { autoLogin: false, scombzAutoLogin: false }
  }, {});
  await assert.rejects(
    h.call({ type: "saveAccount", username: "ab12345", accountPassword: "" }, {}),
    /新しいパスワード/
  );
  const saved = await h.call({
    type: "saveAccount", username: "ab12345", accountPassword: "new-password"
  }, {});
  assert.equal(saved.ok, true);
  const data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.username, "ab12345@sic");
  assert.equal(data.password, "new-password");
});
