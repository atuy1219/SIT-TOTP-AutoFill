"use strict";

importScripts("scombz-auth.js");

const LOCAL_VAULT_KEY = "sitAdfsEncryptedVault";
const LOCAL_DEVICE_KEY = "sitAdfsDeviceKey";
const SESSION_KEY = "sitAdfsSessionKey";
const ITERATIONS = 310000;
const TARGET_HOST = "adfs.sic.shibaura-it.ac.jp";
const TARGET_PATH_PREFIX = "/adfs/ls";

const DEFAULT_SETTINGS = Object.freeze({
  autoLogin: false,
  keepSignedIn: false,
  autoSelectProvider: false,
  autoFill: false,
  autoSubmit: false,
  scombzAutoLogin: false,
  scombzAvoidLoginPage: false
});

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

function normalizeUsername(value) {
  const normalized = String(value || "").trim();
  if (/^[A-Za-z]{2}\d{5}$/.test(normalized)) {
    return `${normalized.toLowerCase()}@sic`;
  }
  return normalized;
}

function validateCredentials(username, password, required = false) {
  const normalizedUsername = normalizeUsername(username);
  const normalizedPassword = String(password || "");

  if (!required && !normalizedUsername && !normalizedPassword) {
    return { username: "", password: "" };
  }

  if (!normalizedUsername || !/[@\\]/.test(normalizedUsername)) {
    throw new Error("大学ユーザー名は「英字2文字+数字5桁」または「ユーザー名@sic」で入力してください。");
  }
  if (required && !normalizedPassword) {
    throw new Error("大学アカウントのパスワードを入力してください。");
  }

  return {
    username: normalizedUsername,
    password: normalizedPassword
  };
}

function normalizeSettings(value = {}) {
  return {
    autoLogin: value.autoLogin === true,
    keepSignedIn: value.keepSignedIn === true,
    autoSelectProvider: value.autoSelectProvider === true,
    autoFill: value.autoFill === true,
    autoSubmit: value.autoSubmit === true,
    scombzAutoLogin: value.scombzAutoLogin === true,
    scombzAvoidLoginPage: value.scombzAvoidLoginPage === true
  };
}

function getUnlockMode(vault) {
  return vault?.unlockMode === "device" ? "device" : "password";
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
    remaining: period - (Math.floor(now / 1000) % period),
    step: counter,
    period
  };
}

async function deriveVaultKey(password, salt, extractable = true) {
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

async function importVaultKey(rawKey, extractable = false) {
  return crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    extractable,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(data, key, salt, unlockMode = "password") {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return {
    version: 2,
    unlockMode,
    kdf: unlockMode === "device" ? "DEVICE-KEY" : "PBKDF2-SHA256",
    iterations: unlockMode === "device" ? 0 : ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
}

async function decryptVault(vault, key) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(vault.iv) },
    key,
    base64ToBytes(vault.ciphertext)
  );
  const data = JSON.parse(new TextDecoder().decode(plaintext));

  // v0.1/v0.2 vault migration
  return {
    version: 1,
    secret: String(data.secret || ""),
    username: String(data.username || ""),
    password: String(data.password || ""),
    scombzToken: String(data.scombzToken || ""),
    settings: normalizeSettings(data.settings || {}),
    createdAt: Number(data.createdAt || Date.now()),
    updatedAt: Number(data.updatedAt || Date.now())
  };
}

async function configureStorageAccess() {
  try {
    await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  } catch {}
  try {
    await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  } catch {}
}

configureStorageAccess();
chrome.runtime.onInstalled.addListener(configureStorageAccess);
chrome.runtime.onStartup.addListener(configureStorageAccess);

async function getEncryptedVault() {
  const stored = await chrome.storage.local.get(LOCAL_VAULT_KEY);
  return stored[LOCAL_VAULT_KEY] || null;
}

async function getSessionKey() {
  const stored = await chrome.storage.session.get(SESSION_KEY);
  const encoded = stored[SESSION_KEY];
  return encoded ? importVaultKey(base64ToBytes(encoded)) : null;
}

async function getDeviceKey() {
  const stored = await chrome.storage.local.get(LOCAL_DEVICE_KEY);
  const encoded = stored[LOCAL_DEVICE_KEY];
  return encoded
    ? { encoded, key: await importVaultKey(base64ToBytes(encoded)) }
    : null;
}

async function storeSessionKey(encoded) {
  await chrome.storage.session.set({ [SESSION_KEY]: encoded });
}

async function saveDeviceVault(data) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await importVaultKey(rawKey);
  const vault = await encryptVault(data, key, salt, "device");
  const encodedKey = bytesToBase64(rawKey);
  await chrome.storage.local.set({
    [LOCAL_VAULT_KEY]: vault,
    [LOCAL_DEVICE_KEY]: encodedKey
  });
  await storeSessionKey(encodedKey);
  return { vault, key, data };
}

async function requireUnlocked() {
  const vault = await getEncryptedVault();
  if (!vault) throw new Error("初期設定が完了していません。");

  let key = await getSessionKey();
  if (!key && getUnlockMode(vault) === "device") {
    const deviceKey = await getDeviceKey();
    if (deviceKey) {
      key = deviceKey.key;
      await storeSessionKey(deviceKey.encoded);
    }
  }
  if (!key) throw new Error("保管庫がロックされています。");

  try {
    const data = await decryptVault(vault, key);
    if (getUnlockMode(vault) === "password") {
      return saveDeviceVault(data);
    }
    return { vault, key, data };
  } catch {
    await chrome.storage.session.remove(SESSION_KEY);
    throw new Error(
      getUnlockMode(vault) === "device"
        ? "端末内の自動解除キーを使用できません。設定をリセットしてください。"
        : "保管庫を再度解除してください。"
    );
  }
}

async function saveVaultData(data, key, existingVault) {
  data.updatedAt = Date.now();
  const encrypted = await encryptVault(
    data,
    key,
    base64ToBytes(existingVault.salt),
    getUnlockMode(existingVault)
  );
  await chrome.storage.local.set({ [LOCAL_VAULT_KEY]: encrypted });
}

// All messages handled by runtime.onMessage are internal to this extension.
// External extensions and websites would require onMessageExternal, which is
// intentionally not registered. A sender.url/id check for the popup/options
// blocked legitimate messages on some browsers (sender fields are optional).
// The only installed content script is the isolated ADFS UI helper.

async function withActiveScombzToken(vault, key, data, action) {
  if (!data.scombzToken) throw new Error("ScombApp APIへ接続してください。");
  try {
    return await action(data.scombzToken);
  } catch (error) {
    if (error?.authExpired) {
      data.scombzToken = "";
      await saveVaultData(data, key, vault);
    }
    throw error;
  }
}

// Optional browser-level redirect: prevent the ScombZ /login document
// from loading and use an extension-owned authentication bridge instead.
// This is opt-in because it changes navigation and may need site-specific
// adjustments. The existing, tested login-page recovery remains the default.
const SCOMBZ_BYPASS_RULE_ID = 7302;
const scombzBypassCancelledTabs = new Set();
const SCOMBZ_RECOVERY_DOCUMENT = "auth-redirect.html";

function scombzBypassRule() {
  return {
    id: SCOMBZ_BYPASS_RULE_ID,
    priority: 100,
    action: {
      type: "redirect",
      redirect: { extensionPath: "/" + SCOMBZ_RECOVERY_DOCUMENT }
    },
    condition: {
      regexFilter: "^https://scombz\\.shibaura-it\\.ac\\.jp/(?:portal/)?login/?(?:[?#].*)?$",
      resourceTypes: ["main_frame"]
    }
  };
}

async function scombzSyncBypassRule(enabledOverride) {
  if (!chrome.declarativeNetRequest?.updateDynamicRules) return;
  let enabled = enabledOverride;
  if (typeof enabled !== "boolean") {
    try {
      const { data } = await requireUnlocked();
      const settings = normalizeSettings(data.settings);
      enabled = Boolean(data.scombzToken &&
        settings.scombzAutoLogin && settings.scombzAvoidLoginPage);
    } catch {
      enabled = false;
    }
  }
  const installed = (await chrome.declarativeNetRequest.getDynamicRules())
    .some((rule) => rule.id === SCOMBZ_BYPASS_RULE_ID);
  if (installed === enabled) return;
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [SCOMBZ_BYPASS_RULE_ID],
    addRules: enabled ? [scombzBypassRule()] : []
  });
}

function scombzIsBypassDocument(sender) {
  const expected = chrome.runtime.getURL(SCOMBZ_RECOVERY_DOCUMENT);
  return Number.isInteger(sender?.tab?.id) && sender.tab.id >= 0 &&
    sender.url === expected;
}

async function scombzAllowNormalLogin(tabId) {
  scombzBypassCancelledTabs.add(tabId);
  scombzPendingTabs.delete(tabId);
  // Explicit fallback needs to persist, or reloading /login could send the
  // user back into the extension recovery page indefinitely.
  try {
    const { vault, key, data } = await requireUnlocked();
    data.settings = normalizeSettings({ ...data.settings,
      scombzAvoidLoginPage: false });
    await saveVaultData(data, key, vault);
  } catch {}
  await scombzSyncBypassRule(false);
  const tab = await chrome.tabs.get(tabId);
  if (tab?.url === chrome.runtime.getURL(SCOMBZ_RECOVERY_DOCUMENT)) {
    await chrome.tabs.update(tabId, { url: SCOMBZ_ORIGIN + "/login" });
  }
}

async function scombzRunBypass(sender) {
  if (!scombzIsBypassDocument(sender)) {
    throw new Error("認証ページ以外からは実行できません。");
  }
  const tabId = sender.tab.id;
  if (scombzBypassCancelledTabs.has(tabId)) {
    await scombzAllowNormalLogin(tabId);
    return { ok: false, reason: "logout" };
  }
  const pending = scombzPendingTabs.get(tabId) || scombzQueueRenewal(tabId);
  if (!pending || pending.started) return { ok: false, reason: "limited" };
  pending.started = true;
  try {
    const otkey = await pending.otkeyPromise;
    if (!otkey) throw new Error("OTKEYを取得できません。");
    const tab = await chrome.tabs.get(tabId);
    if (tab?.url !== chrome.runtime.getURL(SCOMBZ_RECOVERY_DOCUMENT) ||
        scombzBypassCancelledTabs.has(tabId)) {
      return { ok: false, reason: "navigated" };
    }
    if (!scombzRetryAllowed(tabId)) {
      throw new Error("認証の再試行回数を超えました。");
    }
    const cookie = await chrome.cookies.get({
      url: SCOMBZ_ORIGIN + "/", name: "SESSION"
    });
    if (cookie) {
      await chrome.cookies.remove({
        url: SCOMBZ_ORIGIN + "/", name: "SESSION",
        ...(cookie.storeId ? { storeId: cookie.storeId } : {})
      });
    }
    if (pending.resumeUrl && pending.resumeUrl !== SCOMBZ_HOME) {
      scombzRestoreTabs.set(tabId, {
        url: pending.resumeUrl, createdAt: Date.now()
      });
    }
    await chrome.tabs.update(tabId, { url: scombzBridgeUrl(otkey) });
    return { ok: true };
  } catch {
    await scombzAllowNormalLogin(tabId);
    return { ok: false, reason: "fallback" };
  } finally {
    if (scombzPendingTabs.get(tabId) === pending) {
      scombzPendingTabs.delete(tabId);
    }
  }
}

function isTargetSender(sender) {
  const candidate = sender?.url || sender?.tab?.url || "";
  try {
    const url = new URL(candidate);
    return (
      url.protocol === "https:" &&
      url.hostname === TARGET_HOST &&
      url.pathname.startsWith(TARGET_PATH_PREFIX)
    );
  } catch {
    return false;
  }
}

async function handleMessage(message, sender) {
  switch (message?.type) {
    case "scombzBypassLogin":
      return scombzRunBypass(sender);

    case "scombzBypassFallback": {
      if (!scombzIsBypassDocument(sender)) {
        throw new Error("認証ページ以外からは実行できません。");
      }
      await scombzAllowNormalLogin(sender.tab.id);
      return { ok: true };
    }

    case "status": {
      const vault = await getEncryptedVault();
      if (!vault) return { ok: true, initialized: false, unlocked: false, unlockMode: null };
      try {
        await requireUnlocked();
        return { ok: true, initialized: true, unlocked: true, unlockMode: "device" };
      } catch {
        return {
          ok: true,
          initialized: true,
          unlocked: false,
          unlockMode: getUnlockMode(vault) === "password" ? "legacy" : "device"
        };
      }
    }

    case "initialize": {
      if (await getEncryptedVault()) {
        throw new Error("保管庫は既に作成されています。");
      }

      const settings = normalizeSettings(message.settings);
      const credentials = validateCredentials(
        message.username,
        message.accountPassword,
        true
      );
      const secret = String(message.secret || "").trim()
        ? validateSecret(message.secret) : "";
      if (!secret && settings.autoFill) {
        throw new Error("ADFSのTOTP自動入力にはシードが必要です。");
      }
      if (settings.scombzAutoLogin) scombzStudentId(credentials.username);

      const now = Date.now();
      const data = {
        version: 1,
        secret,
        username: credentials.username,
        password: credentials.password,
        scombzToken: "",
        settings,
        createdAt: now,
        updatedAt: now
      };

      await saveDeviceVault(data);
      await scombzSyncBypassRule(false);
      return { ok: true, unlockMode: "device" };
    }

    case "unlock": {
      const vault = await getEncryptedVault();
      if (!vault) throw new Error("保管庫がありません。");
      if (getUnlockMode(vault) === "device") {
        await requireUnlocked();
        return { ok: true, unlockMode: "device" };
      }
      // Only existing password-protected vaults require a one-time migration.
      const password = String(message.masterPassword || "");
      if (password.length < 6) throw new Error("旧マスターパスワードを入力してください。");
      let data;
      try {
        const key = await deriveVaultKey(password, base64ToBytes(vault.salt), true);
        data = await decryptVault(vault, key);
      } catch {
        if (password.length >= 8) throw new Error("旧マスターパスワードが違います。");
        try {
          const key = await deriveVaultKey(
            "sit:" + password, base64ToBytes(vault.salt), true);
          data = await decryptVault(vault, key);
        } catch {
          throw new Error("旧マスターパスワードが違います。");
        }
      }
      await saveDeviceVault(data);
      return { ok: true, unlockMode: "device", migrated: true };
    }

    case "exportBackupData": {
      const { data } = await requireUnlocked();
      return {
        ok: true,
        data: {
          username: data.username,
          secret: data.secret,
          settings: normalizeSettings(data.settings)
        }
      };
    }

    case "importBackupData": {
      const value = message?.data;
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("バックアップが不正です。");
      }
      const settings = normalizeSettings(value.settings);
      const secret = String(value.secret || "") ? validateSecret(value.secret) : "";
      if (!secret && settings.autoFill) {
        throw new Error("このバックアップにはTOTPシードが必要です。");
      }
      const username = normalizeUsername(value.username);
      settings.autoLogin = false;
      settings.scombzAutoLogin = false;
      const now = Date.now();
      await saveDeviceVault({
        version: 1, secret, username, password: "", scombzToken: "",
        settings, createdAt: now, updatedAt: now
      });
      await scombzSyncBypassRule(false);
      return { ok: true };
    }

    case "getConfig": {
      const { vault, data } = await requireUnlocked();
      return {
        ok: true,
        unlockMode: getUnlockMode(vault),
        username: data.username,
        passwordConfigured: Boolean(data.password),
        scombzConnected: Boolean(data.scombzToken),
        settings: normalizeSettings(data.settings),
        secretConfigured: Boolean(data.secret),
        secretLength: data.secret.length,
        algorithm: "SHA-256",
        digits: 6,
        period: 30
      };
    }

    // Each settings section has a distinct write contract. Automatic
    // checkbox saves must never read or persist unsaved password/seed inputs.
    case "saveSettings": {
      const { vault, key, data } = await requireUnlocked();
      const settings = normalizeSettings(message.settings);
      validateCredentials(data.username, data.password, true);
      if (settings.scombzAutoLogin) scombzStudentId(data.username);
      if (settings.autoFill && !data.secret) {
        throw new Error("TOTP自動入力を有効にするにはシードを保存してください。");
      }
      data.settings = settings;
      await saveVaultData(data, key, vault);
      await scombzSyncBypassRule(Boolean(data.scombzToken &&
        settings.scombzAutoLogin && settings.scombzAvoidLoginPage));
      return { ok: true };
    }

    case "saveAccount": {
      const { vault, key, data } = await requireUnlocked();
      const username = normalizeUsername(message.username);
      const replacementPassword = String(message.accountPassword || "");
      if (username !== data.username && !replacementPassword) {
        throw new Error("大学ユーザー名を変更する場合は新しいパスワードも入力してください。");
      }
      const password = replacementPassword || data.password;
      validateCredentials(username, password, true);
      const credentialsChanged = username !== data.username ||
        (replacementPassword && replacementPassword !== data.password);
      data.username = username;
      data.password = password;
      if (credentialsChanged) data.scombzToken = "";
      if (normalizeSettings(data.settings).scombzAutoLogin) {
        scombzStudentId(data.username);
      }
      await saveVaultData(data, key, vault);
      if (credentialsChanged) await scombzSyncBypassRule(false);
      return { ok: true, scombzDisconnected: Boolean(credentialsChanged) };
    }

    case "saveSecret": {
      const { vault, key, data } = await requireUnlocked();
      const secret = validateSecret(message.secret);
      data.secret = secret;
      await saveVaultData(data, key, vault);
      return { ok: true };
    }

    case "saveConfig": {
      const { vault, key, data } = await requireUnlocked();
      const settings = normalizeSettings(message.settings);
      const replacementSecret = String(message.secret || "").trim();
      const replacementPassword = String(message.accountPassword || "");
      const username = normalizeUsername(
        String(message.username ?? data.username)
      );

      data.secret = replacementSecret
        ? validateSecret(replacementSecret)
        : data.secret;
      data.username = username;
      if (replacementPassword) {
        data.password = replacementPassword;
      }
      // A password is required for saved university credentials even if
      // the legacy ADFS automation feature is disabled.
      validateCredentials(data.username, data.password, true);
      if (settings.scombzAutoLogin) scombzStudentId(data.username);
      if (!data.secret && settings.autoFill) {
        throw new Error("ADFSのTOTP自動入力にはシードが必要です。");
      }
      data.settings = settings;
      await saveVaultData(data, key, vault);
      await scombzSyncBypassRule(Boolean(data.scombzToken &&
        settings.scombzAutoLogin && settings.scombzAvoidLoginPage));
      return { ok: true };
    }

    case "currentCode": {
      const { data } = await requireUnlocked();
      if (!data.secret) return { ok: false, reason: "not-configured" };
      const result = await generateTotp(data.secret);
      return {
        ok: true,
        ...result,
        settings: normalizeSettings(data.settings)
      };
    }

    case "scombzConnect": {
      const { vault, key, data } = await requireUnlocked();
      const username = normalizeUsername(message.username ?? data.username);
      const password = typeof message.accountPassword === "string" && message.accountPassword
        ? message.accountPassword : data.password;
      const token = await scombzApiLogin(username, password);
      // Mobile API uses the *same* university/ScombZ account. A temporary
      // password entered for API connection is not saved to the vault.
      data.username = username;
      data.scombzToken = token;
      data.settings = normalizeSettings({ ...data.settings, scombzAutoLogin: true });
      await saveVaultData(data, key, vault);
      await scombzSyncBypassRule(data.settings.scombzAvoidLoginPage);
      return { ok: true };
    }

    case "scombzDisconnect": {
      const { vault, key, data } = await requireUnlocked();
      data.scombzToken = "";
      await saveVaultData(data, key, vault);
      await scombzSyncBypassRule(false);
      return { ok: true };
    }

    case "adfsSettings": {
      if (!isTargetSender(sender)) {
        throw new Error("許可されていないページからの要求です。");
      }

      const { data } = await requireUnlocked();
      return {
        ok: true,
        settings: normalizeSettings(data.settings)
      };
    }

    case "adfsCredentials": {
      if (!isTargetSender(sender)) {
        throw new Error("許可されていないページからの要求です。");
      }

      const { data } = await requireUnlocked();
      const settings = normalizeSettings(data.settings);
      if (!settings.autoLogin) {
        return { ok: false, reason: "disabled" };
      }
      if (!data.username || !data.password) {
        return { ok: false, reason: "missing" };
      }

      return {
        ok: true,
        username: data.username,
        password: data.password,
        keepSignedIn: settings.keepSignedIn
      };
    }

    case "adfsCode": {
      if (!isTargetSender(sender)) {
        throw new Error("許可されていないページからの要求です。");
      }

      const { data } = await requireUnlocked();
      const settings = normalizeSettings(data.settings);
      if (!settings.autoFill) {
        return { ok: false, reason: "disabled" };
      }

      const result = await generateTotp(data.secret);
      return {
        ok: true,
        ...result,
        autoSubmit: settings.autoSubmit
      };
    }

    case "reset": {
      await chrome.storage.local.remove([LOCAL_VAULT_KEY, LOCAL_DEVICE_KEY]);
      await chrome.storage.session.remove(SESSION_KEY);
      await scombzSyncBypassRule(false);
      return { ok: true };
    }

    default:
      throw new Error("不明な要求です。");
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) =>
      sendResponse({
        ok: false,
        error: error?.message || String(error)
      })
    );
  return true;
});

// Start gathering OTKEY when ScombZ explicitly rejects an existing session,
// but let the browser finish its redirect to /login BEFORE changing the tab.
// Updating a tab during a nonblocking webRequest redirect races with the
// browser and can send the user to an invalid destination.
const scombzPendingTabs = new Map();
const scombzRestoreTabs = new Map();
const scombzAttempts = new Map();
const SCOMBZ_RETRY_WINDOW_MS = 60000;
const SCOMBZ_MAX_RETRIES = 2;
const SCOMBZ_DUPLICATE_GUARD_MS = 2500;
const SCOMBZ_PENDING_TTL_MS = 30000;
const SCOMBZ_HOME = SCOMBZ_ORIGIN + "/portal/home";

function scombzIsLoginPage(path) {
  return /^\/(?:login|portal\/login)\/?$/.test(path);
}

function scombzIsLogoutPage(path) {
  return /(?:^|\/)(?:logout|signout)(?:\/|$)/i.test(path);
}

function scombzSafeReturnUrl(url) {
  try {
    const target = new URL(url);
    return target.origin === SCOMBZ_ORIGIN &&
      !scombzIsLoginPage(target.pathname) &&
      !scombzIsLogoutPage(target.pathname) &&
      !target.username && !target.password
      ? target.href : null;
  } catch {
    return null;
  }
}

async function scombzPrepareOtkey() {
  try {
    const { vault, key, data } = await requireUnlocked();
    if (!normalizeSettings(data.settings).scombzAutoLogin || !data.scombzToken) {
      return null;
    }
    return await withActiveScombzToken(vault, key, data,
      (token) => scombzGetOtkey(token));
  } catch {
    // Keep the university's normal login available on temporary API errors.
    return null;
  }
}

function scombzRetryAvailable(tabId) {
  const now = Date.now();
  const attempt = scombzAttempts.get(tabId);
  if (attempt && now - attempt.lastAttemptAt < SCOMBZ_DUPLICATE_GUARD_MS) {
    return false;
  }
  if (attempt && now - attempt.since < SCOMBZ_RETRY_WINDOW_MS &&
      attempt.count >= SCOMBZ_MAX_RETRIES) return false;
  return true;
}

function scombzQueueRenewal(tabId, resumeUrl = null) {
  const now = Date.now();
  const previous = scombzPendingTabs.get(tabId);
  if (previous && now - previous.createdAt < SCOMBZ_PENDING_TTL_MS) {
    return previous;
  }
  // A late /login onCompleted event can arrive after tabs.update has already
  // started the bridge. Ignore it before issuing a second OTKEY request.
  if (!scombzRetryAvailable(tabId)) return null;
  const pending = {
    createdAt: now,
    resumeUrl: scombzSafeReturnUrl(resumeUrl),
    started: false,
    // Prefetch only. Never change the tab from onBeforeRedirect, where a
    // normal 302 can still be in flight and overwrite tabs.update.
    otkeyPromise: scombzPrepareOtkey()
  };
  scombzPendingTabs.set(tabId, pending);
  return pending;
}

function scombzRetryAllowed(tabId) {
  const now = Date.now();
  const attempt = scombzAttempts.get(tabId);
  if (attempt && now - attempt.lastAttemptAt < SCOMBZ_DUPLICATE_GUARD_MS) {
    return false;
  }
  if (attempt && now - attempt.since < SCOMBZ_RETRY_WINDOW_MS &&
      attempt.count >= SCOMBZ_MAX_RETRIES) return false;
  const sameWindow = attempt && now - attempt.since < SCOMBZ_RETRY_WINDOW_MS;
  scombzAttempts.set(tabId, {
    since: sameWindow ? attempt.since : now,
    count: sameWindow ? attempt.count + 1 : 1,
    lastAttemptAt: now
  });
  return true;
}

function scombzMatchesCurrentTab(tab, target, failed401) {
  if (!tab || typeof tab.url !== "string") return false;
  let current;
  try { current = new URL(tab.url); } catch { return false; }
  return current.origin === SCOMBZ_ORIGIN &&
    !scombzIsLogoutPage(current.pathname) &&
    (failed401
      ? current.href === target.href
      : scombzIsLoginPage(current.pathname));
}

async function scombzRenewAfterNavigation({ tabId, frameId, url }, failed401 = false) {
  if (frameId !== 0 || !Number.isInteger(tabId) || tabId < 0 ||
      scombzBypassCancelledTabs.has(tabId)) return;
  let target;
  try { target = new URL(url); } catch { return; }
  if (target.origin !== SCOMBZ_ORIGIN || scombzIsLogoutPage(target.pathname)) return;
  if (!failed401 && !scombzIsLoginPage(target.pathname)) return;

  const pending = scombzPendingTabs.get(tabId) ||
    scombzQueueRenewal(tabId);
  if (!pending || pending.started) return;

  // onCommitted may fire while tabs.get still reports the previous URL.
  // Leave the queued OTKEY request intact and retry on DOM completion,
  // WITHOUT consuming the rate limit or marking the attempt as started.
  let tab;
  try { tab = await chrome.tabs.get(tabId); } catch { return; }
  if (!scombzMatchesCurrentTab(tab, target, failed401)) return;
  pending.started = true;

  try {
    const otkey = await pending.otkeyPromise;
    if (!otkey) return;
    // A second check is essential while awaiting the Mobile API, since
    // the user could have navigated to an unrelated page or site.
    tab = await chrome.tabs.get(tabId);
    if (!scombzMatchesCurrentTab(tab, target, failed401)) return;

    // Count an attempt only once we're genuinely about to exchange OTKEY
    // in an active login tab, never for stale tab.url or API failures.
    if (!scombzRetryAllowed(tabId)) return;
    const cookie = await chrome.cookies.get({
      url: SCOMBZ_ORIGIN + "/", name: "SESSION"
    });
    if (cookie) {
      await chrome.cookies.remove({
        url: SCOMBZ_ORIGIN + "/", name: "SESSION",
        ...(cookie.storeId ? { storeId: cookie.storeId } : {})
      });
    }
    // Use the known-good bridge endpoint only. The old code appended
    // arbitrary /lms/... and query paths to /<OTKEY>, which could break
    // the university's login routing.
    const resumeUrl = pending.resumeUrl;
    if (resumeUrl && resumeUrl !== SCOMBZ_HOME) {
      scombzRestoreTabs.set(tabId, { url: resumeUrl, createdAt: Date.now() });
    } else {
      scombzRestoreTabs.delete(tabId);
    }
    await chrome.tabs.update(tabId, { url: scombzBridgeUrl(otkey) });
  } catch {
    scombzRestoreTabs.delete(tabId);
  } finally {
    if (scombzPendingTabs.get(tabId) === pending) {
      scombzPendingTabs.delete(tabId);
    }
  }
}

async function scombzRestoreAfterAuthentication(tabId) {
  const resume = scombzRestoreTabs.get(tabId);
  if (!resume) return;
  if (Date.now() - resume.createdAt > SCOMBZ_PENDING_TTL_MS) {
    scombzRestoreTabs.delete(tabId);
    return;
  }
  try {
    // Restore a GET destination only after the Web SESSION actually exists.
    const cookie = await chrome.cookies.get({
      url: SCOMBZ_ORIGIN + "/", name: "SESSION"
    });
    if (!cookie) return;
    const tab = await chrome.tabs.get(tabId);
    if (!tab || typeof tab.url !== "string") return;
    const target = new URL(tab.url);
    if (target.origin !== SCOMBZ_ORIGIN ||
        target.pathname !== "/portal/home") return;
    // Both onCommitted and onCompleted may run during portal navigation.
    // Restore only once even if the two async callbacks overlap.
    if (scombzRestoreTabs.get(tabId) !== resume) return;
    scombzRestoreTabs.delete(tabId);
    scombzAttempts.delete(tabId);
    await chrome.tabs.update(tabId, { url: resume.url });
  } catch {
    // Keep the authenticated portal page if destination restore fails.
    scombzRestoreTabs.delete(tabId);
  }
}

// Observe the redirect and prepare OTKEY immediately, but do NOT navigate
// until /login commits; otherwise the server's own redirect may win the race.
chrome.webRequest.onBeforeRedirect.addListener((details) => {
  if (details.type !== "main_frame" || details.tabId < 0) return;
  try {
    const source = new URL(details.url);
    const redirect = new URL(details.redirectUrl);
    if (source.origin !== SCOMBZ_ORIGIN ||
        redirect.origin !== SCOMBZ_ORIGIN ||
        !scombzIsLoginPage(redirect.pathname)) return;
    if (scombzIsLogoutPage(source.pathname)) {
      scombzBypassCancelledTabs.add(details.tabId);
      return;
    }
    scombzQueueRenewal(details.tabId,
      details.method === "GET" ? source.href : null);
  } catch {}
}, { urls: [SCOMBZ_ORIGIN + "/*"], types: ["main_frame"] });

// 401 without a redirect is a separate confirmed authentication failure.
// Handle it when the response completes rather than during response headers.
chrome.webRequest.onCompleted.addListener((details) => {
  if (details.type !== "main_frame" || details.tabId < 0 ||
      details.statusCode !== 401) return;
  try {
    const target = new URL(details.url);
    if (target.origin !== SCOMBZ_ORIGIN ||
        scombzIsLogoutPage(target.pathname)) return;
    const pending = scombzQueueRenewal(details.tabId,
      details.method === "GET" ? target.href : null);
    if (pending) void scombzRenewAfterNavigation({
      tabId: details.tabId, frameId: 0, url: target.href
    }, true);
  } catch {}
}, { urls: [SCOMBZ_ORIGIN + "/*"], types: ["main_frame"] });

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  let target;
  try { target = new URL(details.url); } catch { return; }
  if (target.origin !== SCOMBZ_ORIGIN) return;
  if (scombzIsLoginPage(target.pathname)) {
    void scombzRenewAfterNavigation(details);
  } else if (target.pathname === "/portal/home") {
    void scombzRestoreAfterAuthentication(details.tabId);
    // Even without a saved deep link, reaching the home page with a SESSION
    // proves that the current tab's last renewal succeeded.
    void chrome.cookies.get({
      url: SCOMBZ_ORIGIN + "/", name: "SESSION"
    }).then((cookie) => {
      if (cookie && !scombzRestoreTabs.has(details.tabId)) {
        scombzAttempts.delete(details.tabId);
      }
    }).catch(() => {});
  }
}, { url: [{ hostEquals: SCOMBZ_HOST, schemes: ["https"] }] });

// A direct /login reload is a fresh navigation. By onCompleted, tabs.get
// normally reflects the committed login URL even on browsers where the
// preceding onCommitted notification still reported the old tab URL.
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0 || details.tabId < 0) return;
  try {
    const target = new URL(details.url);
    if (target.origin !== SCOMBZ_ORIGIN) return;
    if (scombzIsLoginPage(target.pathname)) {
      void scombzRenewAfterNavigation(details);
    } else if (target.pathname === "/portal/home") {
      // A home commit can also report the previous mobile bridge tab URL.
      // Retry deep-link restoration once Chrome/Firefox finishes loading.
      void scombzRestoreAfterAuthentication(details.tabId);
    }
  } catch {}
}, { url: [{ hostEquals: SCOMBZ_HOST, schemes: ["https"] }] });

// Dynamic browser rules persist across service-worker sleeps and browser
// sessions; reconcile them when the extension is installed or starts.
chrome.runtime.onInstalled.addListener(() => {
  void scombzSyncBypassRule().catch(() => {});
});
chrome.runtime.onStartup.addListener(() => {
  void scombzSyncBypassRule().catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scombzPendingTabs.delete(tabId);
  scombzRestoreTabs.delete(tabId);
  scombzAttempts.delete(tabId);
  scombzBypassCancelledTabs.delete(tabId);
});
