import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = (await readFile(new URL("../src/background.js", import.meta.url), "utf8"))
  .replace(/^importScripts\([^\n]+\);$/gm, "");

const passkeySource = await readFile(new URL("../src/passkey-auth.js", import.meta.url), "utf8");

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
  local.values.sitScombzRiskConsent = "accepted-v1";
  const listener = { addListener: () => {} };
  const chrome = {
    storage: { local, session },
    runtime: { onInstalled: listener, onStartup: listener, onMessage: listener,
      getURL: file => "chrome-extension://test-id/" + file },
    webNavigation: { onBeforeNavigate: listener, onCommitted: listener, onCompleted: listener },
    webRequest: { onBeforeRedirect: listener, onCompleted: listener },
    tabs: { onRemoved: listener },
    cookies: { onChanged: listener }
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
  vm.runInContext(passkeySource + "\n" + source, ctx);
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

test("password vault stays protected until passkey migration succeeds", async () => {
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

  const unlocked = await h.call({
    type: "unlock", masterPassword: "old-password"
  }, {});
  assert.equal(unlocked.migrationRequired, true);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "password");
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  const status = await h.call({ type: "status" }, {});
  assert.equal(status.unlocked, true);
  assert.equal(status.migrationRequired, true);
  assert.deepEqual(h.local.values.sitAdfsEncryptedVault, vault,
    "status must not silently replace password encryption with device encryption");

  await h.session.remove("sitAdfsSessionKey");
  assert.equal((await h.call({ type: "status" }, {})).unlocked, false);
  await assert.rejects(h.call({ type: "unlock", masterPassword: "wrong-password" }, {}), /マスターパスワード/);
  assert.deepEqual(h.local.values.sitAdfsEncryptedVault, vault);
  await h.call({ type: "unlock", masterPassword: "old-password" }, {});

  const prf = Buffer.alloc(32, 7).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 9).toString("base64url") };
  await vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "prf");
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  assert.equal((await h.call({ type: "status" }, {})).unlocked, true);
  assert.equal((await h.call({ type: "status" }, {})).migrationRequired, false);
  const data = (await vm.runInContext("requireUnlocked", h.ctx)()).data;
  assert.equal(data.secret, original.secret);
  assert.equal(data.password, original.password);
  assert.equal(data.username, original.username);
  assert.equal(data.scombzToken, original.scombzToken);
  assert.equal(data.settings.autoFill, true);

  await h.session.remove(["sitAdfsSessionKey", "sitAdfsPrfSessionExpiry"]);
  assert.equal((await h.call({ type: "status" }, {})).unlockMode, "prf");
  await assert.rejects(h.call({ type: "unlock", masterPassword: "old-password" }, {}), /パスキー/);
  await vm.runInContext("passkeyUnlockPrfVault", h.ctx)(prf, config);
  assert.equal((await h.call({ type: "exportBackupData" }, {})).data.secret, original.secret);
});

for (const compatiblePrefix of ["", "sit:"]) {
  test(`0.5.1 six-character master password remains readable (${compatiblePrefix || "native"})`, async () => {
    const h = harness();
    const salt = webcrypto.getRandomValues(new Uint8Array(16));
    const key = await vm.runInContext("deriveVaultKey", h.ctx)(compatiblePrefix + "123456", salt, true);
    const original = { username: "al25133@sic", password: "university-password",
      secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", settings: { autoFill: true } };
    const vault = await vm.runInContext("encryptVault", h.ctx)(original, key, salt, "password");
    await h.local.set({ sitAdfsEncryptedVault: vault });
    const unlocked = await h.call({ type: "unlock", masterPassword: "123456" }, {});
    assert.equal(unlocked.migrationRequired, true);
    assert.deepEqual(h.local.values.sitAdfsEncryptedVault, vault);
    assert.equal((await vm.runInContext("requireUnlocked", h.ctx)()).data.secret, original.secret);
    assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  });
}

test("0.5.1 cached session and backup import do not install a device key", async () => {
  const h = harness();
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await vm.runInContext("deriveVaultKey", h.ctx)("old-password", salt, true);
  const vault = await vm.runInContext("encryptVault", h.ctx)(
    { username: "al25133@sic", password: "university-password", secret: "", settings: {} }, key, salt, "password");
  await h.local.set({ sitAdfsEncryptedVault: vault });
  await h.session.set({ sitAdfsSessionKey: Buffer.from(await webcrypto.subtle.exportKey("raw", key)).toString("base64") });
  assert.equal((await h.call({ type: "status" }, {})).migrationRequired, true);
  assert.deepEqual(h.local.values.sitAdfsEncryptedVault, vault);
  await h.call({ type: "importBackupData", data: {
    username: "al25133@sic", secret: "", settings: { autoFill: false }
  } }, {});
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "password");
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  assert.equal((await h.call({ type: "status" }, {})).migrationRequired, true);
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

test("API connection keeps the account pair consistent and requires saving username changes", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "old-account-password",
    settings: { autoLogin: true, scombzAutoLogin: true } }, {});
  const logins = [];
  h.ctx.scombzApiLogin = async (username, password) => {
    logins.push({ username, password });
    return "new-api-token";
  };
  const previous = h.local.values.sitAdfsEncryptedVault;
  await assert.rejects(h.call({ type: "scombzConnect", username: "ab12345",
    accountPassword: "new-account-password" }, {}), /先に大学アカウントを保存/);
  assert.deepEqual(logins, []);
  assert.deepEqual(h.local.values.sitAdfsEncryptedVault, previous);
  const sender = { url: "https://adfs.sic.shibaura-it.ac.jp/adfs/ls/" };
  let credentials = await h.call({ type: "adfsCredentials" }, sender);
  assert.equal(credentials.username, "al25133@sic");
  assert.equal(credentials.password, "old-account-password");
  await h.call({ type: "saveAccount", username: "ab12345", accountPassword: "new-account-password" }, {});
  await h.call({ type: "scombzConnect", username: "AB12345" }, {});
  assert.deepEqual(logins, [{ username: "ab12345@sic", password: "new-account-password" }]);
  credentials = await h.call({ type: "adfsCredentials" }, sender);
  assert.equal(credentials.username, "ab12345@sic");
  assert.equal(credentials.password, "new-account-password");
  assert.equal((await h.call({ type: "getConfig" }, {})).scombzConnected, true);
});


test("PRF enrollment re-encrypts the entire vault and removes its persistent key", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "university-password",
    secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    settings: { scombzAutoLogin: false } }, {});
  const oldKey = h.local.values.sitAdfsDeviceKey;
  const prf = Buffer.alloc(32, 7).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 9).toString("base64url"), transports: ["hybrid"] };
  const enable = vm.runInContext("passkeyEnablePrfVault", h.ctx);
  await enable(prf, config);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "prf");
  assert.equal(h.local.values.sitAdfsEncryptedVault.kdf, "WEBAUTHN-PRF-HKDF-SHA256");
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  assert.ok(!JSON.stringify(h.local.values).includes(oldKey));
  assert.equal((await h.call({ type: "status" }, {})).unlockMode, "prf");

  // Deleting the passkey switch must not restore the device vault key.
  await h.session.remove(["sitAdfsSessionKey", "sitAdfsPrfSessionExpiry"]);
  await h.local.remove("sitScombzLocalPasskey");
  assert.equal((await h.call({ type: "status" }, {})).unlocked, false);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "prf");
  await assert.rejects(h.call({ type: "exportBackupData" }, {}), /PRF保管庫/);
  await h.local.set({ sitScombzLocalPasskey: config });

  const unlock = vm.runInContext("passkeyUnlockPrfVault", h.ctx);
  await assert.rejects(unlock(Buffer.alloc(32, 8).toString("base64url"), config), /PRF鍵/);
  await unlock(prf, config);
  const decoded = await vm.runInContext("requireUnlocked", h.ctx)();
  assert.equal(decoded.data.password, "university-password");
  assert.equal(decoded.data.secret, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");

  // Backup import must not silently reinstall an unprotected device vault.
  await h.call({ type: "importBackupData", data: { username: "al25133", secret: "",
    settings: { autoFill: false } } }, {});
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "prf");
  const disable = vm.runInContext("passkeyDisablePrfVault", h.ctx);
  await disable();
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "device");
  assert.ok(h.local.values.sitAdfsDeviceKey);
  assert.equal(h.local.values.sitScombzLocalPasskey, null);
});

test("PRF lock expires and cannot use a stale saved device key", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "university-password",
    settings: { autoFill: false } }, {});
  const prf = Buffer.alloc(32, 5).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 3).toString("base64url") };
  await vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config);
  await h.session.set({ sitAdfsPrfSessionExpiry: Date.now() - 1 });
  assert.equal((await h.call({ type: "status" }, {})).unlocked, false);
  await h.local.set({ sitAdfsDeviceKey: Buffer.alloc(32, 0).toString("base64") });
  assert.equal((await h.call({ type: "status" }, {})).unlocked, false);
});

for (const enabled of [false, true]) {
  for (const connected of [false, true]) {
    test(`locked PRF vault prompts only for enabled and connected API login (${enabled}, ${connected})`, async () => {
      const h = harness();
      await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
        settings: { autoFill: false, scombzAutoLogin: false } }, {});
      if (connected) {
        h.ctx.scombzApiLogin = async () => "saved-api-token";
        await h.call({ type: "scombzConnect" }, {});
      }
      await h.call({ type: "saveSettings", settings: { scombzAutoLogin: enabled } }, {});
      const prf = Buffer.alloc(32, 7).toString("base64url");
      const config = { credentialId: "AQID", publicKey: "AQID",
        prfSalt: Buffer.alloc(32, 9).toString("base64url") };
      await vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config);
      assert.equal(h.local.values.sitAdfsEncryptedVault.scombzAutoLoginReady, enabled && connected);
      await h.session.remove(["sitAdfsSessionKey", "sitAdfsPrfSessionExpiry"]);
      h.ctx.scombzGetOtkey = () => { throw new Error("API must not be called before passkey approval"); };
      const result = await vm.runInContext("scombzPrepareOtkey", h.ctx)();
      if (enabled && connected) assert.equal(result.passkeyRequired, true);
      else assert.equal(result, null);
    });
  }
}

test("older PRF vault gains readiness metadata after a successful unlock", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { scombzAutoLogin: false } }, {});
  h.ctx.scombzApiLogin = async () => "saved-api-token";
  await h.call({ type: "scombzConnect" }, {});
  const prf = Buffer.alloc(32, 7).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 9).toString("base64url") };
  await vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config);
  delete h.local.values.sitAdfsEncryptedVault.scombzAutoLoginReady;
  await h.session.remove(["sitAdfsSessionKey", "sitAdfsPrfSessionExpiry"]);
  // Unknown locked settings must not trigger an unwanted passkey prompt.
  assert.equal(await vm.runInContext("scombzPrepareOtkey", h.ctx)(), null);
  await vm.runInContext("passkeyUnlockPrfVault", h.ctx)(prf, config);
  assert.equal(h.local.values.sitAdfsEncryptedVault.scombzAutoLoginReady, true);
  await h.call({ type: "scombzDisconnect" }, {});
  assert.equal(h.local.values.sitAdfsEncryptedVault.scombzAutoLoginReady, false);
});

test("locked password vault can be reset and restored from a separate backup", async () => {
  const h = harness();
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const key = await vm.runInContext("deriveVaultKey", h.ctx)("forgotten-master-password", salt, true);
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const original = { username: "al25133@sic", password: "saved-password", secret: seed, settings: {} };
  const vault = await vm.runInContext("encryptVault", h.ctx)(original, key, salt, "password");
  await h.local.set({ sitAdfsEncryptedVault: vault });
  assert.equal((await h.call({ type: "status" }, {})).unlocked, false);
  await h.call({ type: "reset" }, {});
  assert.equal(h.local.values.sitAdfsEncryptedVault, undefined);
  await h.call({ type: "importBackupData", data: {
    username: original.username, secret: seed, settings: { autoFill: true }
  } }, {});
  const exported = (await h.call({ type: "exportBackupData" }, {})).data;
  assert.equal(exported.secret, seed);
  assert.equal((await h.call({ type: "getConfig" }, {})).passwordConfigured, false);
});

function pauseApiLogin(h, { reject = false } = {}) {
  let release, notifyStarted;
  const started = new Promise(resolve => { notifyStarted = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  h.ctx.scombzApiLogin = async () => {
    notifyStarted();
    await gate;
    if (reject) throw new Error("API unavailable");
    return "new-api-token";
  };
  return { started, release };
}

test("pending API connection serializes settings, seed saves, and passkey enrollment", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { autoFill: false, scombzAutoLogin: true } }, {});
  const api = pauseApiLogin(h);
  const connect = h.call({ type: "scombzConnect" }, {});
  await api.started;
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const saveSeed = h.call({ type: "saveSecret", secret: seed }, {});
  const saveSettings = h.call({ type: "saveSettings", settings: {
    autoFill: true, autoSubmit: true, scombzAutoLogin: false
  } }, {});
  const prf = Buffer.alloc(32, 7).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 9).toString("base64url") };
  let enrolled = false;
  const enrollment = vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config)
    .then(() => { enrolled = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(enrolled, false, "enrollment must wait until API connection commits");
  api.release();
  await Promise.all([connect, saveSeed, saveSettings, enrollment]);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "prf");
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  await h.session.remove(["sitAdfsSessionKey", "sitAdfsPrfSessionExpiry"]);
  await vm.runInContext("passkeyUnlockPrfVault", h.ctx)(prf, config);
  const { data } = await vm.runInContext("requireUnlocked", h.ctx)();
  assert.equal(data.secret, seed);
  assert.equal(data.password, "saved-password");
  assert.equal(data.scombzToken, "new-api-token");
  assert.equal(data.settings.scombzAutoLogin, false);
  assert.equal(data.settings.autoSubmit, true);
});

test("reset during pending API connection cannot resurrect deleted credentials", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { autoFill: false, scombzAutoLogin: true } }, {});
  const api = pauseApiLogin(h);
  const connect = h.call({ type: "scombzConnect" }, {});
  await api.started;
  const reset = h.call({ type: "reset" }, {});
  api.release();
  await Promise.all([connect, reset]);
  assert.equal(h.local.values.sitAdfsEncryptedVault, undefined);
  assert.equal(h.local.values.sitAdfsDeviceKey, undefined);
  assert.equal((await h.call({ type: "status" }, {})).initialized, false);
});

test("passkey disable waits for a pending authorized API connection", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { autoFill: false, scombzAutoLogin: true } }, {});
  const prf = Buffer.alloc(32, 7).toString("base64url");
  const config = { credentialId: "AQID", publicKey: "AQID",
    prfSalt: Buffer.alloc(32, 9).toString("base64url") };
  await vm.runInContext("passkeyEnablePrfVault", h.ctx)(prf, config);
  await h.session.set({ "sitPasskeyConnect:42": {
    credentialId: config.credentialId, expiresAt: Date.now() + 10000
  } });
  const api = pauseApiLogin(h);
  const connect = h.call({ type: "scombzConnect" }, {
    url: "chrome-extension://test-id/options.html", tab: { id: 42 }
  });
  await api.started;
  const disable = vm.runInContext("passkeyDisablePrfVault", h.ctx)();
  api.release();
  await Promise.all([connect, disable]);
  assert.equal(h.local.values.sitAdfsEncryptedVault.unlockMode, "device");
  await h.session.remove("sitAdfsSessionKey");
  assert.equal((await h.call({ type: "status" }, {})).unlocked, true);
  assert.equal((await vm.runInContext("requireUnlocked", h.ctx)()).data.scombzToken, "new-api-token");
});

test("background token expiration cannot overwrite a later seed save", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { autoFill: false, scombzAutoLogin: true } }, {});
  h.ctx.scombzApiLogin = async () => "old-api-token";
  await h.call({ type: "scombzConnect" }, {});
  let release, notifyStarted;
  const started = new Promise(resolve => { notifyStarted = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  h.ctx.scombzGetOtkey = async () => {
    notifyStarted();
    await gate;
    throw Object.assign(new Error("Token expired"), { authExpired: true });
  };
  const renewal = vm.runInContext("scombzPrepareOtkey", h.ctx)();
  await started;
  const seed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const save = h.call({ type: "saveSecret", secret: seed }, {});
  release();
  await Promise.all([renewal, save]);
  const { data } = await vm.runInContext("requireUnlocked", h.ctx)();
  assert.equal(data.secret, seed);
  assert.equal(data.scombzToken, "");
});

test("failed API connection does not prevent later vault writes", async () => {
  const h = harness();
  await h.call({ type: "initialize", username: "al25133", accountPassword: "saved-password",
    settings: { autoFill: false, scombzAutoLogin: true } }, {});
  const api = pauseApiLogin(h, { reject: true });
  const connect = assert.rejects(h.call({ type: "scombzConnect" }, {}), /API unavailable/);
  await api.started;
  const save = h.call({ type: "saveAccount", username: "al25133", accountPassword: "new-password" }, {});
  api.release();
  await Promise.all([connect, save]);
  assert.equal((await vm.runInContext("requireUnlocked", h.ctx)()).data.password, "new-password");
});


test("consent is required before using or unlocking saved credentials", async () => {
  const h = harness();
  await h.local.remove("sitScombzRiskConsent");
  assert.equal((await h.call({ type: "status" }, {})).consentRequired, true);
  await assert.rejects(h.call({ type: "initialize", username: "al25133",
    accountPassword: "secret", settings: {} }, {}), /同意/);
  await assert.rejects(h.call({ type: "acceptRiskConsent", accepted: true },
    { url: "https://evil.example/" }), /設定画面/);
  await assert.rejects(h.call({ type: "acceptRiskConsent", accepted: false },
    { url: "chrome-extension://test-id/options.html" }), /設定画面/);
  const result = await h.call({ type: "acceptRiskConsent", accepted: true },
    { url: "chrome-extension://test-id/options.html" });
  assert.equal(result.ok, true);
  assert.equal((await h.call({ type: "status" }, {})).consentRequired, undefined);
});
