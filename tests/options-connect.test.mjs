import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/options.js", import.meta.url), "utf8");

function harness({ api = true, passkey = false, registerError = false,
  connectError = false, saveError = false, migration = false,
  migrationUnlocked = false, confirmReset = true, resetError = false } = {}) {
  const elements = new Map();
  const calls = [];
  const events = [];
  const confirmations = [];
  let migrated = false;
  let reset = false;
  let locked = false;
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value: "", checked: false, disabled: false, handlers: {},
      classList: { toggle() {}, remove() {} }, focus() {},
      addEventListener(event, handler) { this.handlers[event] = handler; }
    });
    return elements.get(id);
  };
  const ctx = vm.createContext({
    crypto: webcrypto, Uint8Array, TextEncoder, TextDecoder, btoa, atob,
    Event: class { constructor(type) { this.type = type; } },
    confirm: text => { confirmations.push(text); return confirmReset; },
    document: { getElementById: element, dispatchEvent(event) { events.push(event.type); } },
    setTimeout: () => 1, clearTimeout() {}, clearInterval() {},
    chrome: {
      tabs: { getCurrent: async () => ({ id: 42 }) },
      runtime: { getManifest: () => ({ version: "test" }),
        sendMessage: async message => {
          calls.push(message);
          if (locked && ["getConfig", "exportBackupData", "importBackupData", "saveSecret", "scombzDisconnect"].includes(message.type)) {
            return { ok: false, error: "PRF保管庫はロックされています。パスキーで解除してください。" };
          }
          if (message.type === "reset") {
            if (resetError) return { ok: false, error: "reset failed" };
            reset = true;
            return { ok: true };
          }
          if (message.type === "importBackupData") return { ok: true };
          if (message.type === "status") return reset ? { initialized: false } : {
            initialized: true, unlocked: !locked && (migrated || migrationUnlocked || !migration),
            unlockMode: migrated ? "prf" : !migration ? "device" : migrationUnlocked ? "password" : "legacy",
            migrationRequired: !migrated && migrationUnlocked
          };
          if (message.type === "getConfig") return {
            ok: true, username: "al00000@sic", settings: {}, passkeyEnabled: true, passkeyProtected: true
          };
          if (message.type === "unlock") {
            migrationUnlocked = true;
            return { ok: true, migrationRequired: true };
          }
          if (message.type === "initialize" || message.type === "saveAccount") {
            if (locked) return { ok: false, error: "PRF保管庫はロックされています。パスキーで解除してください。" };
            return { ok: !saveError, error: saveError ? "save failed" : undefined };
          }
          if (message.type === "scombzConnect") {
            return { ok: !connectError, error: connectError ? "connection failed" : undefined };
          }
          throw new Error("Unexpected message: " + message.type);
        }
      }
    },
    PasskeyClient: {
      unlock: async () => { calls.push({ type: "unlockPasskey" }); locked = false; },
      register: async () => {
        calls.push({ type: "register" });
        if (registerError) throw new Error("registration cancelled");
        migrated = true;
      },
      confirmConnect: async () => calls.push({ type: "confirmConnect" })
    }
  });
  vm.runInContext(source.slice(0, source.lastIndexOf("refresh().catch(")), ctx);
  if (!migration) vm.runInContext("refresh = async () => {};", ctx);
  element("initialUsername").value = "al00000";
  element("initialAccountPassword").value = "university-password";
  element("initialScombzAutoLogin").checked = api;
  element("initialScombzPasskey").checked = passkey;
  element("username").value = "al00000";
  element("replacementAccountPassword").value = "new-university-password";
  element("scombzAutoLogin").checked = api;
  return { element, calls, events, confirmations, click: id => element(id).handlers.click(),
    expire: () => { locked = true; },
    encryptBackup: (data, password) => vm.runInContext("encryptBackupData", ctx)(data, password),
    refresh: () => vm.runInContext("refresh()", ctx) };
}

test("initial save registers the selected passkey before authorizing API connection", async () => {
  const h = harness({ passkey: true });
  await h.click("initializeButton");
  assert.deepEqual(h.calls.map(call => call.type),
    ["initialize", "register", "confirmConnect", "scombzConnect"]);
  assert.equal(h.calls[0].settings.scombzAutoLogin, true);
  assert.equal(h.calls.at(-1).pageTabId, 42);
  assert.equal(h.calls.at(-1).accountPassword, undefined, "connect uses saved credentials");
  assert.equal(h.element("initialAccountPassword").value, "");
  assert.equal(h.element("initializeButton").disabled, false);
});

test("initial save connects without registering a passkey when it is unselected", async () => {
  const h = harness();
  await h.click("initializeButton");
  assert.deepEqual(h.calls.map(call => call.type),
    ["initialize", "confirmConnect", "scombzConnect"]);
});

for (const failure of [{}, { connectError: true }, { passkey: true, registerError: true }]) {
  test(`saved TOTP seed is confirmed once regardless of subsequent setup result: ${JSON.stringify(failure)}`, async () => {
    const h = harness(failure);
    h.element("initialSecret").value = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    await h.click("initializeButton");
    assert.deepEqual(h.events, ["sit:initialized-with-seed"]);
    assert.equal(h.element("initialSecret").value, "");
  });
}

test("TOTP confirmation is skipped when initialization fails or no seed was saved", async () => {
  const failed = harness({ saveError: true });
  failed.element("initialSecret").value = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  await failed.click("initializeButton");
  assert.deepEqual(failed.events, []);
  const seedless = harness();
  await seedless.click("initializeButton");
  assert.deepEqual(seedless.events, []);
});

test("API disabled skips connection for both initial and subsequent account saves", async () => {
  const h = harness({ api: false, passkey: true });
  await h.click("initializeButton");
  await h.click("saveAccountButton");
  assert.deepEqual(h.calls.map(call => call.type), ["initialize", "register", "saveAccount"]);
});

test("cancelled initial passkey registration stops API connection and reports saved credentials", async () => {
  const h = harness({ passkey: true, registerError: true });
  await h.click("initializeButton");
  assert.deepEqual(h.calls.map(call => call.type), ["initialize", "register"]);
  assert.match(h.element("message").textContent, /初期設定は保存済み/);
  assert.equal(h.element("initializeButton").disabled, false);
});

test("failed credential saves do not register passkeys or connect to the API", async () => {
  const h = harness({ passkey: true, saveError: true });
  await h.click("initializeButton");
  await h.click("saveAccountButton");
  assert.deepEqual(h.calls.filter(call => call.type !== "status").map(call => call.type), ["initialize", "saveAccount"]);
  assert.equal(h.element("initializeButton").disabled, false);
  assert.equal(h.element("saveAccountButton").disabled, false);
});

for (const button of ["initializeButton", "saveAccountButton"]) {
  test(`${button} reports connection failure while keeping the account saved`, async () => {
    const h = harness({ connectError: true });
    await h.click(button);
    assert.deepEqual(h.calls.map(call => call.type),
      [button === "initializeButton" ? "initialize" : "saveAccount", "confirmConnect", "scombzConnect"]);
    assert.match(h.element("message").textContent, /保存済み/);
    assert.match(h.element("message").textContent, /connection failed/);
    assert.equal(h.element(button).disabled, false);
  });
}

for (const migrationUnlocked of [false, true]) {
  test(`migration registers a passkey with an ${migrationUnlocked ? "unlocked" : "locked"} vault`, async () => {
    const h = harness({ migration: true, migrationUnlocked });
    await h.refresh();
    assert.equal(h.element("unlockPanel").hidden, false);
    assert.equal(h.element("unlockMasterPasswordLabel").hidden, migrationUnlocked);
    assert.match(h.element("unlockDescription").textContent, /マスターパスワードによる保護は廃止/);
    h.element("unlockMasterPassword").value = "old-password";
    await h.click("unlockButton");
    assert.deepEqual(h.calls.filter(call => ["unlock", "register"].includes(call.type))
      .map(call => call.type), migrationUnlocked ? ["register"] : ["unlock", "register"]);
    assert.equal(h.element("settingsArea").hidden, false);
    assert.equal(h.element("unlockButton").disabled, false);
  });
}

test("cancelled migration stays on the migration screen and can retry registration", async () => {
  const h = harness({ migration: true, registerError: true });
  await h.refresh();
  h.element("unlockMasterPassword").value = "old-password";
  await h.click("unlockButton");
  assert.equal(h.element("unlockPanel").hidden, false);
  assert.equal(h.element("settingsArea").hidden, true);
  assert.equal(h.element("unlockMasterPassword").value, "");
  assert.equal(h.element("unlockMasterPasswordLabel").hidden, true);
  assert.match(h.element("unlockButton").textContent, /パスキーを登録して移行/);
  assert.match(h.element("message").textContent, /移行は完了していません/);
  await h.click("unlockButton");
  assert.equal(h.calls.filter(call => call.type === "unlock").length, 1);
  assert.equal(h.calls.filter(call => call.type === "register").length, 2);
});

test("both current and 0.5.1 imports ask for the backup password", async () => {
  const h = harness();
  for (const version of [1, 3]) {
    h.element("importFile").files = [{ text: async () => JSON.stringify({
      format: "sit-totp-autofill-backup", version
    }) }];
    await h.element("importFile").handlers.change();
    assert.equal(h.element("legacyImportPasswordLabel").hidden, false);
    assert.equal(h.element("importPasswordLabelText").textContent, "バックアップパスワード");
  }
});

test("0.5.1 backup decrypts with its separate backup password", async () => {
  const h = harness();
  const data = { username: "al25133@sic", password: "saved-university-password",
    secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", settings: { autoFill: true } };
  const envelope = await h.encryptBackup(data, "separate-backup-password");
  // 0.5.1 used the same PBKDF2/AES-GCM payload with a version-1 envelope.
  envelope.version = 1;
  envelope.vault.unlockMode = "password";
  h.element("importFile").files = [{ text: async () => JSON.stringify(envelope) }];
  h.element("importPassword").value = "vault-master-password";
  await h.click("importButton");
  assert.match(h.element("message").textContent, /バックアップパスワードが違う/);
  assert.equal(h.calls.some(call => call.type === "importBackupData"), false);
  h.element("importPassword").value = "separate-backup-password";
  await h.click("importButton");
  const imported = h.calls.find(call => call.type === "importBackupData");
  assert.equal(imported.data.secret, data.secret);
  assert.equal(h.element("importPassword").value, "");
});

test("locked 0.5.1 migration can reset without the master password after confirmation", async () => {
  const h = harness({ migration: true });
  await h.refresh();
  assert.equal(h.element("resetLockedButton").hidden, false);
  await h.click("resetLockedButton");
  assert.equal(h.confirmations.length, 1);
  assert.equal(h.calls.filter(call => call.type === "reset").length, 1);
  assert.equal(h.calls.some(call => call.type === "unlock"), false);
  assert.equal(h.element("initializePanel").hidden, false);
});

test("cancelled migration reset preserves the vault", async () => {
  const h = harness({ migration: true, confirmReset: false });
  await h.refresh();
  await h.click("resetLockedButton");
  assert.equal(h.calls.some(call => call.type === "reset"), false);
  assert.equal(h.element("unlockPanel").hidden, false);
});

test("failed migration reset is not reported as successful", async () => {
  const h = harness({ migration: true, resetError: true });
  await h.refresh();
  await h.click("resetLockedButton");
  assert.match(h.element("message").textContent, /reset failed/);
  assert.equal(h.element("unlockPanel").hidden, false);
});

test("manual API connection requires saving a changed username and keeps pending credentials", async () => {
  const h = harness();
  h.element("username").value = "ab12345";
  h.element("replacementAccountPassword").value = "new-account-password";
  await h.click("scombzConnectButton");
  assert.match(h.element("message").textContent, /先に大学アカウントを保存/);
  assert.equal(h.calls.some(call => ["confirmConnect", "scombzConnect"].includes(call.type)), false);
  assert.equal(h.element("username").value, "ab12345");
  assert.equal(h.element("replacementAccountPassword").value, "new-account-password");
  assert.equal(h.element("scombzConnectButton").disabled, false);
});

test("manual API connection accepts the saved student ID without its suffix", async () => {
  const h = harness();
  await h.click("scombzConnectButton");
  assert.equal(h.calls.filter(call => call.type === "scombzConnect").length, 1);
  assert.equal(h.element("replacementAccountPassword").value, "");
});

for (const action of ["scombzConnectButton", "saveAccountButton", "saveSeedButton",
  "scombzDisconnectButton", "exportButton", "importButton"]) {
  test(`${action} switches to passkey unlock after expiry and recovers without reloading`, async () => {
    const h = harness({ migration: true });
    await h.refresh();
    h.element("unlockMasterPassword").value = "old-password";
    await h.click("unlockButton");
    assert.equal(h.element("settingsArea").hidden, false);
    h.expire();
    if (action === "saveSeedButton") {
      h.element("replacementSecret").value = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    }
    if (action === "importButton") {
      h.element("importFile").files = [{ text: async () => JSON.stringify({
        format: "sit-totp-autofill-backup", version: 2,
        data: { username: "al00000@sic", secret: "", settings: {} }
      }) }];
    }
    await h.click(action);
    assert.equal(h.element("settingsArea").hidden, true);
    assert.equal(h.element("unlockPanel").hidden, false);
    assert.equal(h.element("unlockPasskeyButton").hidden, false);
    await h.click("unlockPasskeyButton");
    assert.equal(h.element("settingsArea").hidden, false);
    assert.equal(h.element("unlockPanel").hidden, true);
  });
}

for (const action of ["scombzConnectButton", "saveAccountButton"]) {
  test(`${action} preserves pending account inputs across passkey reauthentication`, async () => {
    const h = harness({ migration: true });
    await h.refresh();
    h.element("unlockMasterPassword").value = "old-password";
    await h.click("unlockButton");
    h.element("username").value = "ab12345";
    h.element("replacementAccountPassword").value = "new-account-password";
    h.expire();
    await h.click(action);
    assert.equal(h.element("unlockPanel").hidden, false);
    await h.click("unlockPasskeyButton");
    assert.equal(h.element("username").value, "ab12345");
    assert.equal(h.element("replacementAccountPassword").value, "new-account-password");
    assert.equal(h.calls.some(call => call.type === "scombzConnect"), false);
  });
}
