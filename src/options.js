"use strict";

const byId = (id) => document.getElementById(id);
const LOCAL_VAULT_KEY = "sitAdfsEncryptedVault";
const LOCAL_DEVICE_KEY = "sitAdfsDeviceKey";
const SESSION_KEY = "sitAdfsSessionKey";
const BACKUP_FORMAT = "sit-totp-autofill-backup";
const BACKUP_VERSION = 2;
const ITERATIONS = 310000;
let initialPreviewTimer = null;
let notificationTimer = null;
// Serialize writes from the options page: rapid checkbox changes and explicit
// credential/seed saves must not overwrite one another with stale vault data.
let settingsWriteQueue = Promise.resolve();

function queueSettingsWrite(operation) {
  const task = settingsWriteQueue.then(operation, operation);
  settingsWriteQueue = task.catch(() => {});
  return task;
}

async function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra });
}

function message(text, error = false) {
  const element = byId("message");
  clearTimeout(notificationTimer);
  element.textContent = text;
  element.classList.toggle("error", error);
  if (!text) return;
  // Important errors stay longer, but neither success nor error permanently
  // covers the top of the screen.
  notificationTimer = setTimeout(() => {
    element.textContent = "";
    element.classList.remove("error");
  }, error ? 10000 : 5500);
}

function showState(state) {
  byId("initializePanel").hidden = state !== "initialize";
  byId("unlockPanel").hidden = state !== "unlock";
  byId("settingsArea").hidden = state !== "settings";
}

function normalizeBase32(value) {
  return String(value || "").toUpperCase().replace(/[\s=-]/g, "");
}

function validateSecret(secret) {
  const normalized = normalizeBase32(secret);
  if (normalized.length !== 32) {
    throw new Error("シードは32文字のBase32で入力してください。");
  }
  if (!/^[A-Z2-7]{32}$/.test(normalized)) {
    throw new Error("シードにBase32以外の文字が含まれています。");
  }
  decodeBase32(normalized);
  return normalized;
}

function decodeBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = normalizeBase32(value);
  let bits = 0;
  let buffer = 0;
  const output = [];

  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Base32シードが不正です。");
    buffer = (buffer << 5) | index;
    bits += 5;

    while (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(output);
}

function counterToBytes(counter) {
  let value = BigInt(counter);
  const bytes = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

async function generateTotp(secret, now = Date.now()) {
  const period = 30;
  const counter = Math.floor(now / 1000 / period);
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterToBytes(counter))
  );
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return {
    code: String(binary % 1_000_000).padStart(6, "0"),
    remaining: period - (Math.floor(now / 1000) % period)
  };
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function deriveBackupKey(password, salt, extractable = true) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: ITERATIONS
    },
    material,
    { name: "AES-GCM", length: 256 },
    extractable,
    ["encrypt", "decrypt"]
  );
}

async function decryptVaultPayload(vault, key) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(vault.iv) },
    key,
    base64ToBytes(vault.ciphertext)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function validateBackupEnvelope(value) {
  if (!value || value.format !== BACKUP_FORMAT || value.version !== 1) {
    throw new Error("この拡張機能のバックアップファイルではありません。");
  }
  const vault = value.vault;
  if (
    !vault ||
    vault.unlockMode !== "password" ||
    vault.kdf !== "PBKDF2-SHA256" ||
    vault.iterations !== ITERATIONS ||
    typeof vault.salt !== "string" ||
    typeof vault.iv !== "string" ||
    typeof vault.ciphertext !== "string"
  ) {
    throw new Error("バックアップファイルの暗号化形式が不正です。");
  }
  return vault;
}

function validateBackupData(data) {
  if (!data || typeof data !== "object") {
    throw new Error("バックアップ内の設定データが不正です。");
  }
  if (data.secret) validateSecret(data.secret);
  else if (data.settings?.autoFill !== false) {
    throw new Error("バックアップ内のTOTP設定が不正です。");
  }
  if (data.scombzToken != null && typeof data.scombzToken !== "string") {
    throw new Error("バックアップ内のScombZ接続情報が不正です。");
  }
  if (typeof data.username !== "string" || typeof data.password !== "string") {
    throw new Error("バックアップ内のアカウント情報が不正です。");
  }
  if (!data.settings || typeof data.settings !== "object") {
    throw new Error("バックアップ内の自動化設定が不正です。");
  }
}

function downloadJson(value, filename) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function updateInitialAutoLoginMode() {
  // University credentials are mandatory even when legacy ADFS automation
  // is disabled. Only ADFS-specific dependent options should be disabled.
  const autoLogin = byId("initialAutoLogin").checked;
  byId("initialKeepSignedIn").disabled = !autoLogin;
  if (!autoLogin) byId("initialKeepSignedIn").checked = false;
}

function readInitialSettings() {
  return {
    autoLogin: byId("initialAutoLogin").checked,
    keepSignedIn: byId("initialKeepSignedIn").checked,
    autoSelectProvider: byId("initialAutoSelectProvider").checked,
    autoFill: byId("initialAutoFill").checked,
    autoSubmit: byId("initialAutoSubmit").checked,
    scombzAutoLogin: byId("initialScombzAutoLogin").checked,
    scombzAvoidLoginPage: byId("initialScombzAvoidLoginPage").checked
  };
}

function readSettings() {
  return {
    autoLogin: byId("autoLogin").checked,
    keepSignedIn: byId("keepSignedIn").checked,
    autoSelectProvider: byId("autoSelectProvider").checked,
    autoFill: byId("autoFill").checked,
    autoSubmit: byId("autoSubmit").checked,
    scombzAutoLogin: byId("scombzAutoLogin").checked,
    scombzAvoidLoginPage: byId("scombzAvoidLoginPage").checked
  };
}

function stopInitialPreview() {
  clearInterval(initialPreviewTimer);
  initialPreviewTimer = null;
  byId("initialPreview").hidden = true;
}

async function refreshInitialPreview() {
  const secret = validateSecret(byId("initialSecret").value);
  const result = await generateTotp(secret);
  byId("initialPreviewCode").textContent = result.code;
  byId("initialPreviewRemaining").textContent = `残り${result.remaining}秒`;
  byId("initialPreview").hidden = false;
}

async function startInitialPreview() {
  stopInitialPreview();
  await refreshInitialPreview();
  initialPreviewTimer = setInterval(() => {
    refreshInitialPreview().catch(() => stopInitialPreview());
  }, 1000);
}

async function refresh() {
  const status = await send("status");

  if (!status.initialized) {
    showState("initialize");
    updateInitialAutoLoginMode();
    return;
  }

  stopInitialPreview();

  if (!status.unlocked) {
    const legacyMode = status.unlockMode === "legacy";
    showState("unlock");
    byId("unlockDescription").textContent = legacyMode
      ? "旧保管庫をパスワード不要の方式へ移行します。旧パスワードはこの一度だけ必要です。"
      : "端末の暗号化キーを読み込めません。バックアップから復元するか、再設定してください。";
    byId("unlockMasterPasswordLabel").hidden = !legacyMode;
    byId("unlockButton").hidden = !legacyMode;
    byId("resetLockedButton").hidden = legacyMode;
    if (legacyMode) byId("unlockMasterPassword").focus();
    return;
  }

  const config = await send("getConfig");
  if (!config?.ok) {
    message(config?.error || "設定を読み込めません。", true);
    return;
  }

  showState("settings");
  byId("username").value = config.username || "";
  byId("passwordStatus").textContent = config.passwordConfigured
    ? "大学パスワードは暗号化して保存されています。"
    : "大学パスワードが未設定です。入力して保存してください。";
  byId("passwordStatus").classList.toggle("warning", !config.passwordConfigured);
  byId("seedStatus").textContent = config.secretConfigured
    ? "TOTPシードは保存されています。"
    : "TOTPシードは未設定です。";
  byId("autoLogin").checked = config.settings.autoLogin === true;
  byId("keepSignedIn").checked = config.settings.keepSignedIn === true;
  byId("autoSelectProvider").checked =
    config.settings.autoSelectProvider === true;
  byId("autoFill").checked = config.settings.autoFill === true;
  byId("autoSubmit").checked = config.settings.autoSubmit === true;
  byId("scombzAutoLogin").checked = config.settings.scombzAutoLogin === true;
  byId("scombzAvoidLoginPage").checked =
    config.settings.scombzAvoidLoginPage === true;
  byId("scombzDisconnectButton").disabled = !config.scombzConnected;


}

byId("initialAutoLogin").addEventListener("change", updateInitialAutoLoginMode);
byId("initialScombzAutoLogin").addEventListener("change", updateInitialAutoLoginMode);
byId("initialSecret").addEventListener("input", stopInitialPreview);
byId("initialPreviewButton").addEventListener("click", () => {
  startInitialPreview().catch((error) => message(error.message, true));
});

byId("initializeButton").addEventListener("click", async () => {
  const username = byId("initialUsername").value.trim();
  const password = byId("initialAccountPassword").value;
  if (!username) {
    byId("initialUsername").focus();
    message("大学ユーザー名を入力してください。", true);
    return;
  }
  if (!password) {
    byId("initialAccountPassword").focus();
    message("大学アカウントのパスワードを入力してください。", true);
    return;
  }
  const hadTotpSeed = Boolean(byId("initialSecret").value.trim());
  const result = await send("initialize", {
    username,
    accountPassword: password,
    secret: byId("initialSecret").value,
    settings: readInitialSettings()
  });

  if (!result?.ok) {
    message(result?.error || "保存できませんでした。", true);
    return;
  }

  stopInitialPreview();
  for (const id of [
    "initialAccountPassword",
    "initialSecret"
  ]) {
    byId(id).value = "";
  }

  message("初期設定を保存しました。");
  await refresh();
  if (hadTotpSeed) {
    document.dispatchEvent(new Event("sit:initialized-with-seed"));
  }
});

byId("unlockButton").addEventListener("click", async () => {
  const result = await send("unlock", {
    masterPassword: byId("unlockMasterPassword").value
  });

  if (!result?.ok) {
    message(result?.error || "解除できませんでした。", true);
    return;
  }

  byId("unlockMasterPassword").value = "";
  message("旧保管庫をパスワード不要の暗号化方式へ移行しました。");
  await refresh();
});

byId("unlockMasterPassword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") byId("unlockButton").click();
});

async function saveAutomationSettings() {
  // Capture only checkboxes. Do not include any unsaved account/seed inputs.
  const settings = readSettings();
  try {
    const result = await queueSettingsWrite(() =>
      send("saveSettings", { settings }));
    if (!result?.ok) {
      message(result?.error || "自動保存できませんでした。", true);
      await refresh();
    }
  } catch (error) {
    message(error.message || "自動保存できませんでした。", true);
    await refresh();
  }
}

for (const id of [
  "scombzAutoLogin", "scombzAvoidLoginPage",
  "autoLogin", "keepSignedIn", "autoSelectProvider",
  "autoFill", "autoSubmit"
]) {
  byId(id).addEventListener("change", saveAutomationSettings);
}

byId("saveAccountButton").addEventListener("click", async () => {
  const username = byId("username").value.trim();
  const password = byId("replacementAccountPassword").value;
  try {
    const result = await queueSettingsWrite(() =>
      send("saveAccount", { username, accountPassword: password }));
    if (!result?.ok) throw new Error(result?.error || "大学アカウントを保存できませんでした。");
    if (byId("replacementAccountPassword").value === password) {
      byId("replacementAccountPassword").value = "";
    }
    message(result.scombzDisconnected
      ? "大学アカウントを保存しました。APIへ再接続してください。"
      : "大学アカウントを保存しました。");
    await refresh();
  } catch (error) {
    message(error.message || "大学アカウントを保存できませんでした。", true);
  }
});

byId("saveSeedButton").addEventListener("click", async () => {
  const secret = byId("replacementSecret").value;
  if (!secret.trim()) {
    message("保存するTOTPシードを入力してください。", true);
    return;
  }
  try {
    const result = await queueSettingsWrite(() =>
      send("saveSecret", { secret }));
    if (!result?.ok) throw new Error(result?.error || "TOTPシードを保存できませんでした。");
    if (byId("replacementSecret").value === secret) {
      byId("replacementSecret").value = "";
    }
    message("TOTPシードを保存しました。");
    await refresh();
  } catch (error) {
    message(error.message || "TOTPシードを保存できませんでした。", true);
  }
});

byId("scombzConnectButton").addEventListener("click", async () => {
  // ScombZ and ADFS share the same university password. Use the saved
  // password when available, or the account field as a temporary credential.
  // Do not save a temporary password merely because API connect was clicked.
  const result = await send("scombzConnect", {
    username: byId("username").value,
    accountPassword: byId("replacementAccountPassword").value
  });
  byId("replacementAccountPassword").value = "";
  if (!result?.ok) {
    message(result?.error || "ScombApp APIへ接続できませんでした。", true);
    return;
  }
  message("ScombApp APIへ接続しました。ScombZへの自動ログインを有効にしました。");
  await refresh();
});

byId("scombzDisconnectButton").addEventListener("click", async () => {
  if (!confirm("端末に保存されたScombApp APIトークンを削除しますか？")) return;
  const result = await send("scombzDisconnect");
  if (!result?.ok) message(result?.error || "接続を削除できませんでした。", true);
  else {
    message("ScombApp APIの接続情報を削除しました。");
    await refresh();
  }
});

byId("exportButton").addEventListener("click", async () => {
  try {
    const result = await send("exportBackupData");
    if (!result?.ok) throw new Error(result?.error || "バックアップを取得できません。");
    const data = result.data;
    if (data?.secret && !confirm(
      "バックアップにはTOTPシードが暗号化されずに含まれます。大学パスワードとAPIトークンは含まれません。安全に保管しますか？"
    )) return;
    const backup = {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      exportedAt: new Date().toISOString(),
      data
    };
    const date = new Date().toISOString().slice(0, 10);
    downloadJson(backup, "scombz-login-helper-backup-" + date + ".json");
    message("バックアップを書き出しました。");
  } catch (error) {
    message(error.message || String(error), true);
  }
});

byId("importFile").addEventListener("change", async () => {
  byId("legacyImportPasswordLabel").hidden = true;
  const file = byId("importFile").files?.[0];
  if (!file) return;
  try {
    const envelope = JSON.parse(await file.text());
    byId("legacyImportPasswordLabel").hidden =
      envelope?.format !== BACKUP_FORMAT || envelope?.version !== 1;
  } catch {
    // Import handler presents validation errors.
  }
});

byId("importButton").addEventListener("click", async () => {
  try {
    const file = byId("importFile").files?.[0];
    if (!file) throw new Error("バックアップファイルを選択してください。");
    const envelope = JSON.parse(await file.text());
    if (envelope?.format !== BACKUP_FORMAT) {
      throw new Error("この拡張機能のバックアップではありません。");
    }
    let data;
    if (envelope.version === BACKUP_VERSION) {
      data = envelope.data;
    } else if (envelope.version === 1) {
      const vault = validateBackupEnvelope(envelope);
      const password = byId("importPassword").value;
      if (!password) throw new Error("旧バックアップの復号パスワードを入力してください。");
      const key = await deriveBackupKey(password, base64ToBytes(vault.salt), false);
      try {
        data = await decryptVaultPayload(vault, key);
      } catch {
        throw new Error("旧バックアップのパスワードが違うか、ファイルが破損しています。");
      }
      validateBackupData(data);
    } else {
      throw new Error("対応していないバックアップ形式です。");
    }
    const status = await send("status");
    if (status.initialized &&
        !confirm("既存設定をバックアップのシードと設定で上書きしますか？")) return;
    const result = await send("importBackupData", { data });
    if (!result?.ok) throw new Error(result?.error || "インポートに失敗しました。");
    byId("importFile").value = "";
    byId("importPassword").value = "";
    byId("legacyImportPasswordLabel").hidden = true;
    message("シードと設定を復元しました。大学パスワード・ScombZ API接続は再設定してください。");
    await refresh();
  } catch (error) {
    message(error.message || String(error), true);
  }
});

byId("resetLockedButton").addEventListener("click", async () => {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  await send("reset");
  message("すべて削除しました。");
  await refresh();
});

byId("resetButton").addEventListener("click", async () => {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  await send("reset");
  message("すべて削除しました。");
  await refresh();
});

updateInitialAutoLoginMode();
byId("extensionVersion").textContent = `v${chrome.runtime.getManifest().version}`;
refresh().catch((error) => message(error.message, true));
