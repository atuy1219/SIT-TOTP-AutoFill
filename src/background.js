"use strict";

const LOCAL_VAULT_KEY = "sitAdfsEncryptedVault";
const LOCAL_DEVICE_KEY = "sitAdfsDeviceKey";
const SESSION_KEY = "sitAdfsSessionKey";
const ITERATIONS = 310000;
const TARGET_HOST = "adfs.sic.shibaura-it.ac.jp";
const TARGET_PATH_PREFIX = "/adfs/ls";

const DEFAULT_SETTINGS = Object.freeze({
  autoLogin: true,
  keepSignedIn: true,
  autoSelectProvider: true,
  autoFill: true,
  autoSubmit: true,
  minRemainingSeconds: 5
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
  if (!normalizedPassword) {
    throw new Error("大学アカウントのパスワードを入力してください。");
  }

  return {
    username: normalizedUsername,
    password: normalizedPassword
  };
}

function normalizeSettings(value = {}) {
  const threshold = Number(value.minRemainingSeconds);
  return {
    autoLogin: value.autoLogin !== false,
    keepSignedIn: value.keepSignedIn !== false,
    autoSelectProvider: value.autoSelectProvider !== false,
    autoFill: value.autoFill !== false,
    autoSubmit: value.autoSubmit !== false,
    minRemainingSeconds:
      Number.isInteger(threshold) && threshold >= 0 && threshold <= 15
        ? threshold
        : DEFAULT_SETTINGS.minRemainingSeconds
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
    case "status": {
      const vault = await getEncryptedVault();
      const initialized = Boolean(vault);
      const unlockMode = initialized ? getUnlockMode(vault) : null;
      let unlocked = initialized && Boolean(await getSessionKey());

      if (initialized && !unlocked && unlockMode === "device") {
        try {
          await requireUnlocked();
          unlocked = true;
        } catch {}
      }

      return { ok: true, initialized, unlocked, unlockMode };
    }

    case "initialize": {
      if (await getEncryptedVault()) {
        throw new Error("保管庫は既に作成されています。");
      }

      const useMasterPassword = message.useMasterPassword !== false;
      const unlockMode = useMasterPassword ? "password" : "device";
      const masterPassword = String(message.masterPassword || "");
      if (useMasterPassword && masterPassword.length < 8) {
        throw new Error("マスターパスワードは8文字以上にしてください。");
      }

      const settings = normalizeSettings(message.settings);
      const credentials = validateCredentials(
        message.username,
        message.accountPassword,
        settings.autoLogin
      );
      const secret = validateSecret(message.secret);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      let key;
      let rawKey;

      if (useMasterPassword) {
        key = await deriveVaultKey(masterPassword, salt, true);
        rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      } else {
        rawKey = crypto.getRandomValues(new Uint8Array(32));
        key = await importVaultKey(rawKey);
      }

      const now = Date.now();
      const data = {
        version: 1,
        secret,
        username: credentials.username,
        password: credentials.password,
        settings,
        createdAt: now,
        updatedAt: now
      };

      const encrypted = await encryptVault(data, key, salt, unlockMode);
      const encodedKey = bytesToBase64(rawKey);

      await chrome.storage.local.set({ [LOCAL_VAULT_KEY]: encrypted });
      if (unlockMode === "device") {
        await chrome.storage.local.set({ [LOCAL_DEVICE_KEY]: encodedKey });
      } else {
        await chrome.storage.local.remove(LOCAL_DEVICE_KEY);
      }
      await storeSessionKey(encodedKey);

      return { ok: true, unlockMode };
    }

    case "unlock": {
      const vault = await getEncryptedVault();
      if (!vault) throw new Error("保管庫がありません。");

      if (getUnlockMode(vault) === "device") {
        await requireUnlocked();
        return { ok: true, unlockMode: "device" };
      }

      const masterPassword = String(message.masterPassword || "");
      const key = await deriveVaultKey(
        masterPassword,
        base64ToBytes(vault.salt),
        true
      );

      try {
        await decryptVault(vault, key);
      } catch {
        throw new Error("マスターパスワードが違います。");
      }

      const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      await storeSessionKey(bytesToBase64(rawKey));
      return { ok: true, unlockMode: "password" };
    }

    case "lock":
      await chrome.storage.session.remove(SESSION_KEY);
      return { ok: true };

    case "getConfig": {
      const { vault, data } = await requireUnlocked();
      return {
        ok: true,
        unlockMode: getUnlockMode(vault),
        username: data.username,
        passwordConfigured: Boolean(data.password),
        settings: normalizeSettings(data.settings),
        secretConfigured: Boolean(data.secret),
        secretLength: data.secret.length,
        algorithm: "SHA-256",
        digits: 6,
        period: 30
      };
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
      if (message.clearAccountPassword === true) {
        data.password = "";
      }

      validateCredentials(data.username, data.password, settings.autoLogin);
      data.settings = settings;
      await saveVaultData(data, key, vault);
      return { ok: true };
    }

    case "currentCode": {
      const { data } = await requireUnlocked();
      const result = await generateTotp(data.secret);
      return {
        ok: true,
        ...result,
        settings: normalizeSettings(data.settings)
      };
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
      if (result.remaining <= settings.minRemainingSeconds) {
        return {
          ok: false,
          reason: "wait",
          waitMs: (result.remaining + 1) * 1000
        };
      }

      return {
        ok: true,
        ...result,
        autoSubmit: settings.autoSubmit
      };
    }

    case "reset": {
      await chrome.storage.local.remove([LOCAL_VAULT_KEY, LOCAL_DEVICE_KEY]);
      await chrome.storage.session.remove(SESSION_KEY);
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
