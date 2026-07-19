"use strict";

const byId = (id) => document.getElementById(id);
const LOCAL_VAULT_KEY = "sitAdfsEncryptedVault";
const LOCAL_DEVICE_KEY = "sitAdfsDeviceKey";
const SESSION_KEY = "sitAdfsSessionKey";
const BACKUP_FORMAT = "sit-totp-autofill-backup";
const BACKUP_VERSION = 1;
const ITERATIONS = 310000;
let initialPreviewTimer = null;

async function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra });
}

function message(text, error = false) {
  const element = byId("message");
  element.textContent = text;
  element.classList.toggle("error", error);
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

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
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

async function importVaultKey(encoded, extractable = false) {
  return crypto.subtle.importKey(
    "raw",
    base64ToBytes(encoded),
    { name: "AES-GCM" },
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

async function encryptBackupVault(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(password, salt, false);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return {
    version: 2,
    unlockMode: "password",
    kdf: "PBKDF2-SHA256",
    iterations: ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

function validateBackupEnvelope(value) {
  if (!value || value.format !== BACKUP_FORMAT || value.version !== BACKUP_VERSION) {
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
  validateSecret(data.secret);
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

function updateInitialMasterPasswordMode() {
  const useMasterPassword = byId("initialUseMasterPassword").checked;
  byId("initialMasterPasswordFields").hidden = !useMasterPassword;
  byId("deviceUnlockWarning").hidden = useMasterPassword;
  byId("initialMasterPassword").disabled = !useMasterPassword;
  byId("initialMasterPasswordConfirm").disabled = !useMasterPassword;

  if (!useMasterPassword) {
    byId("initialMasterPassword").value = "";
    byId("initialMasterPasswordConfirm").value = "";
  }
}

function updateInitialAutoLoginMode() {
  const autoLogin = byId("initialAutoLogin").checked;
  byId("initialUsername").disabled = !autoLogin;
  byId("initialAccountPassword").disabled = !autoLogin;
  byId("initialKeepSignedIn").disabled = !autoLogin;

  if (!autoLogin) {
    byId("initialUsername").value = "";
    byId("initialAccountPassword").value = "";
    byId("initialKeepSignedIn").checked = false;
  }
}

function readInitialSettings() {
  return {
    autoLogin: byId("initialAutoLogin").checked,
    keepSignedIn: byId("initialKeepSignedIn").checked,
    autoSelectProvider: byId("initialAutoSelectProvider").checked,
    autoFill: byId("initialAutoFill").checked,
    autoSubmit: byId("initialAutoSubmit").checked
  };
}

function readSettings() {
  return {
    autoLogin: byId("autoLogin").checked,
    keepSignedIn: byId("keepSignedIn").checked,
    autoSelectProvider: byId("autoSelectProvider").checked,
    autoFill: byId("autoFill").checked,
    autoSubmit: byId("autoSubmit").checked
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
    updateInitialMasterPasswordMode();
    updateInitialAutoLoginMode();
    return;
  }

  stopInitialPreview();

  if (!status.unlocked) {
    const deviceMode = status.unlockMode === "device";
    showState("unlock");
    byId("unlockDescription").textContent = deviceMode
      ? "端末内の自動解除キーを読み込めません。バックアップをインポートするか、データを削除して再設定してください。"
      : "マスターパスワードを入力してください。";
    byId("unlockMasterPasswordLabel").hidden = deviceMode;
    byId("unlockButton").hidden = deviceMode;
    byId("resetLockedButton").hidden = !deviceMode;
    if (!deviceMode) byId("unlockMasterPassword").focus();
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
    : "大学パスワードは保存されていません。";
  byId("autoLogin").checked = config.settings.autoLogin !== false;
  byId("keepSignedIn").checked = config.settings.keepSignedIn !== false;
  byId("autoSelectProvider").checked =
    config.settings.autoSelectProvider !== false;
  byId("autoFill").checked = config.settings.autoFill !== false;
  byId("autoSubmit").checked = config.settings.autoSubmit !== false;

  const deviceMode = config.unlockMode === "device";
  byId("unlockModeStatus").textContent = deviceMode
    ? "マスターパスワードなし：端末内の自動解除キーを使用します。"
    : "マスターパスワードで暗号化されています。";
  byId("unlockModeStatus").classList.toggle("warning", deviceMode);
  byId("lockButton").hidden = deviceMode;
}

byId("initialUseMasterPassword").addEventListener(
  "change",
  updateInitialMasterPasswordMode
);
byId("initialAutoLogin").addEventListener("change", updateInitialAutoLoginMode);
byId("initialSecret").addEventListener("input", stopInitialPreview);
byId("initialPreviewButton").addEventListener("click", () => {
  startInitialPreview().catch((error) => message(error.message, true));
});

byId("initializeButton").addEventListener("click", async () => {
  const useMasterPassword = byId("initialUseMasterPassword").checked;
  const masterPassword = byId("initialMasterPassword").value;

  if (
    useMasterPassword &&
    masterPassword !== byId("initialMasterPasswordConfirm").value
  ) {
    message("マスターパスワードの確認が一致しません。", true);
    return;
  }

  const autoLogin = byId("initialAutoLogin").checked;
  const result = await send("initialize", {
    useMasterPassword,
    masterPassword,
    username: autoLogin ? byId("initialUsername").value : "",
    accountPassword: autoLogin ? byId("initialAccountPassword").value : "",
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
    "initialSecret",
    "initialMasterPassword",
    "initialMasterPasswordConfirm"
  ]) {
    byId(id).value = "";
  }

  message("初期設定を保存しました。");
  await refresh();
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
  message("解除しました。");
  await refresh();
});

byId("unlockMasterPassword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") byId("unlockButton").click();
});

byId("saveButton").addEventListener("click", async () => {
  const result = await send("saveConfig", {
    username: byId("username").value,
    accountPassword: byId("replacementAccountPassword").value,
    clearAccountPassword: byId("clearAccountPassword").checked,
    secret: byId("replacementSecret").value,
    settings: readSettings()
  });

  if (!result?.ok) {
    message(result?.error || "保存できませんでした。", true);
    return;
  }

  byId("replacementAccountPassword").value = "";
  byId("replacementSecret").value = "";
  byId("clearAccountPassword").checked = false;
  message("設定を保存しました。");
  await refresh();
});

byId("exportButton").addEventListener("click", async () => {
  try {
    const password = byId("exportPassword").value;
    if (password.length < 8) {
      throw new Error("バックアップ用パスワードは8文字以上にしてください。");
    }
    if (password !== byId("exportPasswordConfirm").value) {
      throw new Error("バックアップ用パスワードの確認が一致しません。");
    }

    const local = await chrome.storage.local.get(LOCAL_VAULT_KEY);
    const session = await chrome.storage.session.get(SESSION_KEY);
    const vault = local[LOCAL_VAULT_KEY];
    const encodedKey = session[SESSION_KEY];
    if (!vault || !encodedKey) {
      throw new Error("保管庫を解除してからバックアップしてください。");
    }

    const data = await decryptVaultPayload(vault, await importVaultKey(encodedKey));
    validateBackupData(data);
    const backup = {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      exportedAt: new Date().toISOString(),
      vault: await encryptBackupVault(data, password)
    };
    const date = new Date().toISOString().slice(0, 10);
    downloadJson(backup, `sit-totp-autofill-backup-${date}.json`);
    byId("exportPassword").value = "";
    byId("exportPasswordConfirm").value = "";
    message("暗号化バックアップを書き出しました。");
  } catch (error) {
    message(error.message || String(error), true);
  }
});

byId("importButton").addEventListener("click", async () => {
  try {
    const file = byId("importFile").files?.[0];
    const password = byId("importPassword").value;
    if (!file) throw new Error("バックアップファイルを選択してください。");
    if (!password) throw new Error("バックアップ用パスワードを入力してください。");

    const envelope = JSON.parse(await file.text());
    const vault = validateBackupEnvelope(envelope);
    const key = await deriveBackupKey(password, base64ToBytes(vault.salt), true);
    let data;
    try {
      data = await decryptVaultPayload(vault, key);
    } catch {
      throw new Error("バックアップ用パスワードが違うか、ファイルが破損しています。");
    }
    validateBackupData(data);

    const status = await send("status");
    if (
      status.initialized &&
      !confirm("現在の設定をバックアップ内の設定で上書きしますか？")
    ) {
      return;
    }

    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
    await chrome.storage.local.set({ [LOCAL_VAULT_KEY]: vault });
    await chrome.storage.local.remove(LOCAL_DEVICE_KEY);
    await chrome.storage.session.set({ [SESSION_KEY]: bytesToBase64(rawKey) });

    byId("importFile").value = "";
    byId("importPassword").value = "";
    message("バックアップをインポートしました。バックアップ用パスワードが新しいマスターパスワードになります。");
    await refresh();
  } catch (error) {
    message(error.message || String(error), true);
  }
});

byId("lockButton").addEventListener("click", async () => {
  await send("lock");
  message("ロックしました。");
  await refresh();
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

updateInitialMasterPasswordMode();
updateInitialAutoLoginMode();
refresh().catch((error) => message(error.message, true));
