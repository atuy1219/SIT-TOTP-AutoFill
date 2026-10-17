"use strict";

const byId = (id) => document.getElementById(id);
const BACKUP_FORMAT = "sit-totp-autofill-backup";
const BACKUP_VERSION = 2;
const ENCRYPTED_BACKUP_VERSION = 3;
const ITERATIONS = 310000;
let notificationTimer = null;
let pendingAccountUsername = null;
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

async function refreshIfLocked() {
  try {
    const status = await send("status");
    if (status?.initialized && !status.unlocked) {
      if (!byId("settingsArea").hidden) pendingAccountUsername = byId("username").value;
      await refresh();
    }
  } catch {
    // Preserve the original action error if the background is unavailable.
  }
}

function normalizeUsername(value) {
  const username = String(value || "").trim();
  return /^[A-Za-z]{2}\d{5}$/.test(username) ? `${username.toLowerCase()}@sic` : username;
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
  byId("consentPanel").hidden = state !== "consent";
  byId("importPanel").hidden = state === "consent";
  byId("initializePanel").hidden = state !== "initialize";
  byId("unlockPanel").hidden = state !== "unlock";
  byId("settingsArea").hidden = state !== "settings";
  byId("deleteDataPanel").hidden = state !== "settings";
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

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

async function encryptBackupData(data, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(password, salt, false);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key,
    new TextEncoder().encode(JSON.stringify(data)));
  return {
    format: BACKUP_FORMAT, version: ENCRYPTED_BACKUP_VERSION,
    exportedAt: new Date().toISOString(),
    vault: { kdf: "PBKDF2-SHA256", iterations: ITERATIONS,
      salt: bytesToBase64(salt), iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)) }
  };
}

async function decryptEncryptedBackup(envelope, password) {
  const vault = envelope?.vault;
  if (envelope?.version !== ENCRYPTED_BACKUP_VERSION || !vault ||
      vault.kdf !== "PBKDF2-SHA256" || vault.iterations !== ITERATIONS ||
      typeof vault.salt !== "string" || typeof vault.iv !== "string" ||
      typeof vault.ciphertext !== "string") {
    throw new Error("暗号化バックアップの形式が不正です。");
  }
  if (!password) throw new Error("バックアップパスワードを入力してください。");
  try {
    const salt = base64ToBytes(vault.salt);
    const iv = base64ToBytes(vault.iv);
    if (salt.length !== 16 || iv.length !== 12) throw new Error("Invalid parameters");
    const key = await deriveBackupKey(password, salt, false);
    const decrypted = await decryptVaultPayload(vault, key);
    if (!decrypted || typeof decrypted.username !== "string" ||
        typeof decrypted.settings !== "object" ||
        (decrypted.secret && typeof decrypted.secret !== "string")) throw new Error("Invalid payload");
    return decrypted;
  } catch {
    throw new Error("バックアップパスワードが違うか、ファイルが破損しています。");
  }
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
    scombzAutoLogin: byId("initialScombzAutoLogin").checked
  };
}

function readSettings() {
  return {
    autoLogin: byId("autoLogin").checked,
    keepSignedIn: byId("keepSignedIn").checked,
    autoSelectProvider: byId("autoSelectProvider").checked,
    autoFill: byId("autoFill").checked,
    autoSubmit: byId("autoSubmit").checked,
    scombzAutoLogin: byId("scombzAutoLogin").checked
  };
}

async function refresh() {
  const status = await send("status");
  if (status.consentRequired) {
    showState("consent");
    return;
  }

  if (!status.initialized) {
    showState("initialize");
    updateInitialAutoLoginMode();
    return;
  }

  if (!status.unlocked || status.migrationRequired) {
    const legacyMode = status.unlockMode === "legacy" || status.migrationRequired;
    const prfMode = status.unlockMode === "prf";
    byId("unlockHeading").textContent = prfMode ? "パスキー保管庫の解除"
      : legacyMode ? "マスターパスワードからパスキーへ移行" : "保管庫を読み込めません";
    showState("unlock");
    byId("unlockDescription").textContent = legacyMode
      ? "マスターパスワードによる保護は廃止しました。データを解除してパスキーを登録します。移行が完了するまで元のデータと保護方式を保持します。"
      : prfMode ? "暗号化保管庫を使うにはパスキーで本人確認してください。紛失した場合は復号できません。"
      : "端末の暗号化キーを読み込めません。バックアップから復元するか、再設定してください。";
    byId("unlockMasterPasswordLabel").hidden = !legacyMode || status.unlocked;
    byId("unlockButton").hidden = !legacyMode;
    byId("unlockButton").textContent = status.unlocked
      ? "パスキーを登録して移行" : "解除してパスキーを登録";
    byId("unlockPasskeyButton").hidden = !prfMode;
    byId("resetLockedButton").hidden = false;
    if (legacyMode && !status.unlocked) byId("unlockMasterPassword").focus();
    return;
  }

  const config = await send("getConfig");
  if (!config?.ok) {
    message(config?.error || "設定を読み込めません。", true);
    return;
  }

  showState("settings");
  byId("username").value = pendingAccountUsername ?? config.username ?? "";
  pendingAccountUsername = null;
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
  const apiConnected = config.scombzConnected === true;
  byId("apiConnectionStatus").textContent = apiConnected
    ? "APIトークン保存済み"
    : "API未接続";
  byId("scombzConnectButton").hidden = apiConnected;
  byId("scombzDisconnectButton").hidden = !apiConnected;
  byId("scombzDisconnectButton").disabled = !apiConnected;
  byId("scombzPasskey").checked = config.passkeyEnabled === true;
  byId("credentialProtectionStatus").textContent = config.passkeyProtected
    ? "パスキーで保護されています。"
    : config.passkeyEnabled
      ? "パスキー確認のみ有効です。認証情報もパスキーで保護するには、下の移行ボタンを押してください。"
      : "端末の自動解除キーで保護されています。パスキーを有効にすると、解除に本人確認が必要になります。";
  byId("migratePasskeyButton").hidden = !config.passkeyEnabled || config.passkeyProtected;


}

byId("riskConsentCheckbox").addEventListener("change", () => {
  byId("riskConsentButton").disabled = !byId("riskConsentCheckbox").checked;
});
byId("riskConsentButton").addEventListener("click", async () => {
  if (!byId("riskConsentCheckbox").checked) return;
  const button = byId("riskConsentButton");
  button.disabled = true;
  try {
    const result = await send("acceptRiskConsent", { accepted: true });
    if (!result?.ok) throw new Error(result?.error || "同意を保存できませんでした。");
    await refresh();
  } catch (error) {
    message(error.message || "同意を保存できませんでした。", true);
    button.disabled = false;
  }
});

byId("initialAutoLogin").addEventListener("change", updateInitialAutoLoginMode);
byId("initialScombzAutoLogin").addEventListener("change", updateInitialAutoLoginMode);

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
  const settings = readInitialSettings();
  const usePasskey = byId("initialScombzPasskey").checked;
  const button = byId("initializeButton");
  button.disabled = true;
  let saved = false;
  try {
    const result = await send("initialize", {
      username,
      accountPassword: password,
      secret: byId("initialSecret").value,
      settings
    });

    if (!result?.ok) {
      message(result?.error || "保存できませんでした。", true);
      return;
    }
    saved = true;

    for (const id of [
      "initialAccountPassword",
      "initialSecret"
    ]) {
      byId(id).value = "";
    }

    if (usePasskey) await PasskeyClient.register();
    if (settings.scombzAutoLogin) {
      await connectScombzApi();
    }
    message(settings.scombzAutoLogin
      ? "初期設定を保存し、ScombApp APIへ接続しました。"
      : "初期設定を保存しました。");
    await refresh();
  } catch (error) {
    message((saved ? "初期設定は保存済みです。パスキー登録またはAPI接続を完了できませんでした。" : "保存できませんでした。") +
      (error.message || String(error)), true);
    await refresh();
  } finally {
    button.disabled = false;
    if (saved && hadTotpSeed) {
      document.dispatchEvent(new Event("sit:initialized-with-seed"));
    }
  }
});

byId("unlockButton").addEventListener("click", async () => {
  const button = byId("unlockButton");
  button.disabled = true;
  try {
    if (!byId("unlockMasterPasswordLabel").hidden) {
      const result = await send("unlock", {
        masterPassword: byId("unlockMasterPassword").value
      });
      if (!result?.ok) throw new Error(result?.error || "解除できませんでした。");
      byId("unlockMasterPassword").value = "";
    }
    await PasskeyClient.register();
    message("データをパスキー保護へ移行しました。マスターパスワードは今後使用しません。");
  } catch (error) {
    message("パスキーへの移行は完了していません。" + (error.message || String(error)), true);
  } finally {
    button.disabled = false;
    await refresh();
  }
});

byId("unlockPasskeyButton").addEventListener("click", async () => {
  const button = byId("unlockPasskeyButton");
  button.disabled = true;
  try {
    await PasskeyClient.unlock();
    await refresh();
  } catch (error) {
    message(error.message || "パスキーで保管庫を解除できませんでした。", true);
  } finally {
    button.disabled = false;
  }
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
  "scombzAutoLogin",
  "autoLogin", "keepSignedIn", "autoSelectProvider",
  "autoFill", "autoSubmit"
]) {
  byId(id).addEventListener("change", saveAutomationSettings);
}

byId("saveAccountButton").addEventListener("click", async () => {
  const button = byId("saveAccountButton");
  button.disabled = true;
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
    if (byId("scombzAutoLogin").checked) {
      try {
        await connectScombzApi();
        message("大学アカウントを保存し、ScombApp APIへ接続しました。");
      } catch (error) {
        message("大学アカウントは保存済みですが、API接続に失敗しました。" +
          (error.message || String(error)), true);
      }
      await refresh();
    }
  } catch (error) {
    message(error.message || "大学アカウントを保存できませんでした。", true);
    await refreshIfLocked();
  } finally {
    button.disabled = false;
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
    await refreshIfLocked();
  }
});

byId("scombzPasskey").addEventListener("change", async () => {
  const checkbox = byId("scombzPasskey");
  checkbox.disabled = true;
  try {
    if (checkbox.checked) await PasskeyClient.register();
    else await PasskeyClient.disable();
    message(checkbox.checked ? "パスキーによる認証情報の保護を有効にしました。" : "パスキー保護を無効にし、端末の自動解除キーによる保護に切り替えました。");
  } catch (error) {
    message(error.name === "NotAllowedError" ? "パスキー設定の変更をキャンセルしました。" : error.message, true);
  } finally {
    checkbox.disabled = false;
    await refresh();
  }
});

byId("migratePasskeyButton").addEventListener("click", async () => {
  const button = byId("migratePasskeyButton");
  button.disabled = true;
  try {
    await PasskeyClient.register();
    message("保管庫をPRF鍵で暗号化しました。");
    await refresh();
  } catch (error) {
    message(error.message || "PRF保護への移行に失敗しました。", true);
  } finally {
    button.disabled = false;
  }
});

async function connectScombzApi(credentials = {}) {
  await PasskeyClient.confirmConnect();
  const result = await send("scombzConnect", {
    ...credentials,
    pageTabId: (await chrome.tabs.getCurrent())?.id
  });
  if (!result?.ok) throw new Error(result?.error || "ScombApp APIへ接続できませんでした。");
}

byId("scombzConnectButton").addEventListener("click", async () => {
  const button = byId("scombzConnectButton");
  button.disabled = true;
  const username = byId("username").value;
  const password = byId("replacementAccountPassword").value;
  let connectionAttempted = false;
  try {
    const config = await send("getConfig");
    if (!config?.ok) throw new Error(config?.error || "設定を読み込めません。");
    if (normalizeUsername(username) !== normalizeUsername(config.username)) {
      message("大学ユーザー名を変更する場合は、先に大学アカウントを保存してください。", true);
      return;
    }
    connectionAttempted = true;
    // A temporary university password is used only for this API connection.
    await connectScombzApi({
      username,
      accountPassword: password
    });
    message("ScombApp APIへ接続しました。ScombZへの自動ログインを有効にしました。");
    await refresh();
  } catch (error) {
    message(error.message || "ScombApp APIへ接続できませんでした。", true);
    await refreshIfLocked();
  } finally {
    if (connectionAttempted && byId("replacementAccountPassword").value === password) {
      byId("replacementAccountPassword").value = "";
    }
    button.disabled = false;
  }
});

byId("scombzDisconnectButton").addEventListener("click", async () => {
  if (!confirm("端末に保存されたScombApp APIトークンを削除しますか？")) return;
  try {
    const result = await send("scombzDisconnect");
    if (!result?.ok) throw new Error(result?.error || "接続を削除できませんでした。");
    message("ScombApp APIの接続情報を削除しました。");
    await refresh();
  } catch (error) {
    message(error.message || "接続を削除できませんでした。", true);
    await refreshIfLocked();
  }
});


byId("encryptBackupCheckbox").addEventListener("change", () => {
  const checked = byId("encryptBackupCheckbox").checked;
  byId("backupPasswordFields").hidden = !checked;
  if (!checked) {
    byId("backupPassword").value = "";
    byId("backupPasswordConfirm").value = "";
  }
});

byId("exportButton").addEventListener("click", async () => {
  try {
    const result = await send("exportBackupData");
    if (!result?.ok) throw new Error(result?.error || "バックアップを取得できません。");
    const data = result.data;
    const encrypted = byId("encryptBackupCheckbox").checked;
    let backup;
    if (encrypted) {
      const password = byId("backupPassword").value;
      if (password.length < 8) throw new Error("バックアップパスワードを8文字以上で入力してください。");
      if (password !== byId("backupPasswordConfirm").value) {
        throw new Error("確認用バックアップパスワードが一致しません。");
      }
      backup = await encryptBackupData(data, password);
    } else {
      if (data?.secret && !confirm(
        "バックアップにはTOTPシードが暗号化されずに含まれます。安全に保管しますか？"
      )) return;
      backup = { format: BACKUP_FORMAT, version: BACKUP_VERSION,
        exportedAt: new Date().toISOString(), data };
    }
    const date = new Date().toISOString().slice(0, 10);
    downloadJson(backup, "scombz-login-helper-backup-" + date +
      (encrypted ? "-encrypted" : "") + ".json");
    byId("backupPassword").value = "";
    byId("backupPasswordConfirm").value = "";
    message(encrypted ? "暗号化バックアップを書き出しました。" : "バックアップを書き出しました。");
  } catch (error) {
    message(error.message || String(error), true);
    await refreshIfLocked();
  }
});

byId("importFile").addEventListener("change", async () => {
  byId("legacyImportPasswordLabel").hidden = true;
  const file = byId("importFile").files?.[0];
  if (!file) return;
  try {
    const envelope = JSON.parse(await file.text());
    byId("importPasswordLabelText").textContent = "バックアップパスワード";
    byId("legacyImportPasswordLabel").hidden =
      envelope?.format !== BACKUP_FORMAT || ![1, ENCRYPTED_BACKUP_VERSION].includes(envelope?.version);
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
    } else if (envelope.version === ENCRYPTED_BACKUP_VERSION) {
      data = await decryptEncryptedBackup(envelope, byId("importPassword").value);
    } else if (envelope.version === 1) {
      const vault = validateBackupEnvelope(envelope);
      const password = byId("importPassword").value;
      if (!password) throw new Error("バックアップパスワードを入力してください。");
      const key = await deriveBackupKey(password, base64ToBytes(vault.salt), false);
      try {
        data = await decryptVaultPayload(vault, key);
      } catch {
        throw new Error("バックアップパスワードが違うか、ファイルが破損しています。");
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
    await refreshIfLocked();
  }
});

async function resetVault() {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  try {
    const result = await send("reset");
    if (!result?.ok) throw new Error(result?.error || "データを削除できませんでした。");
    pendingAccountUsername = null;
    byId("unlockMasterPassword").value = "";
    message("すべて削除しました。");
    await refresh();
  } catch (error) {
    message(error.message || "データを削除できませんでした。", true);
  }
}

byId("resetLockedButton").addEventListener("click", resetVault);
byId("resetButton").addEventListener("click", resetVault);

updateInitialAutoLoginMode();
byId("extensionVersion").textContent = `v${chrome.runtime.getManifest().version}`;
refresh().catch((error) => message(error.message, true));
