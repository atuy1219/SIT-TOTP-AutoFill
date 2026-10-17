"use strict";

// WebAuthn defaults to the extension itself as the relying party. No server,
// domain override or network request is used for registration or verification.
const PASSKEY_CONFIG_KEY = "sitScombzLocalPasskey";
const PASSKEY_REQUEST_PREFIX = "sitPasskeyRequest:";
const PASSKEY_TAB_PREFIX = "sitPasskeyTab:";
const PASSKEY_TTL = 120000;
const passkeyBusy = new Set();
const passkeyOpening = new Set();

function passkeyEncode(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function passkeyDecode(value) {
  if (typeof value !== "string" || value.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("パスキーの応答が不正です。");
  }
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

async function passkeyConfig() {
  return (await chrome.storage.local.get(PASSKEY_CONFIG_KEY))[PASSKEY_CONFIG_KEY] || null;
}

function passkeyIsOptions(sender) {
  return sender?.url === chrome.runtime.getURL("options.html");
}

async function passkeyOrigin() {
  const base = chrome.runtime.getURL("");
  if (base.startsWith("chrome-extension://")) return base.replace(/\/$/, "");
  if (!base.startsWith("moz-extension://")) throw new Error("未対応の拡張機能オリジンです。");
  // Firefox's WebAuthn origin is a deterministic hash of the extension ID.
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(chrome.runtime.id)));
  return "moz-extension://" + Array.from(hash, byte =>
    String.fromCharCode(97 + (byte >> 4), 97 + (byte & 15))).join("");
}

async function passkeyNewRequest(kind, extra = {}) {
  const id = passkeyEncode(crypto.getRandomValues(new Uint8Array(24)));
  const request = { kind, ...extra, challenge: passkeyEncode(
    crypto.getRandomValues(new Uint8Array(32))), createdAt: Date.now() };
  await chrome.storage.session.set({ [PASSKEY_REQUEST_PREFIX + id]: request });
  return { id, request };
}

async function passkeySender(sender, pageTabId) {
  if (sender?.tab?.id !== undefined || !Number.isInteger(pageTabId)) return sender;
  const tab = await chrome.tabs.get(pageTabId);
  if (tab?.url !== sender?.url) throw new Error("操作元のタブを確認できません。");
  return { ...sender, tab };
}

async function passkeyReadRequest(id, sender) {
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]{32}$/.test(id)) throw new Error("確認が見つかりません。");
  const request = (await chrome.storage.session.get(PASSKEY_REQUEST_PREFIX + id))[PASSKEY_REQUEST_PREFIX + id];
  if (!request || Date.now() - request.createdAt > PASSKEY_TTL) throw new Error("確認の有効期限が切れました。");
  if (request.kind === "login") {
    if (sender?.url !== chrome.runtime.getURL("passkey-confirm.html") + "?id=" + id ||
        !Number.isInteger(sender?.tab?.id) ||
        (request.promptTabId !== undefined && sender.tab.id !== request.promptTabId)) {
      throw new Error("パスキー確認画面から操作してください。");
    }
    // The new page can load before tabs.create resolves in the background.
    if (request.promptTabId === undefined) {
      request.promptTabId = sender.tab.id;
      await chrome.storage.session.set({ [PASSKEY_REQUEST_PREFIX + id]: request });
    }
  } else if (!passkeyIsOptions(sender) || sender?.tab?.id !== request.optionsTabId) {
    throw new Error("設定画面から操作してください。");
  }
  return request;
}

async function passkeyDeleteRequest(id, request) {
  await chrome.storage.session.remove(PASSKEY_REQUEST_PREFIX + id);
  if (request.kind === "login") {
    const key = PASSKEY_TAB_PREFIX + request.tabId;
    if ((await chrome.storage.session.get(key))[key] === id) await chrome.storage.session.remove(key);
  }
}

async function passkeyValidateData(request, response, type) {
  const clientBytes = passkeyDecode(response.clientDataJSON);
  const client = JSON.parse(new TextDecoder().decode(clientBytes));
  const origin = await passkeyOrigin();
  if (client.type !== type || client.challenge !== request.challenge ||
      client.origin !== origin || client.crossOrigin === true) {
    throw new Error("パスキーの確認内容が一致しません。");
  }
  const authenticator = passkeyDecode(response.authenticatorData);
  // Chromium hashes the full serialized extension origin, not just its hostname.
  const rpIds = new Set([origin.startsWith("chrome-extension://") ? origin : new URL(origin).hostname]);
  // Firefox's page UUID and stable WebAuthn origin differ across installations.
  if (origin.startsWith("moz-extension://")) {
    rpIds.add(new URL(chrome.runtime.getURL("")).hostname);
  }
  const rpHashes = await Promise.all([...rpIds].map(async id => new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(id))
  )));
  if (authenticator.length < 37 ||
      !rpHashes.some(hash => hash.every((byte, i) => authenticator[i] === byte)) ||
      (authenticator[32] & 5) !== 5) throw new Error("パスキーによる本人確認が必要です。");
  return { clientBytes, authenticator };
}

// WebAuthn ES256 signatures use DER; WebCrypto expects r || s.
function passkeyRawSignature(encoded) {
  const der = passkeyDecode(encoded);
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("署名が不正です。");
  let offset = 2;
  const raw = new Uint8Array(64);
  for (let index = 0; index < 2; index++) {
    if (der[offset++] !== 2) throw new Error("署名が不正です。");
    const length = der[offset++];
    let part = der.slice(offset, offset + length);
    if (!length || part.length !== length || part[0] & 0x80) throw new Error("署名が不正です。");
    offset += length;
    if (part[0] === 0 && part.length > 1) part = part.slice(1);
    if (part.length > 32) throw new Error("署名が不正です。");
    raw.set(part, index * 32 + 32 - part.length);
  }
  if (offset !== der.length) throw new Error("署名が不正です。");
  return raw;
}

function passkeyAlgorithm(algorithm) {
  if (algorithm === -7) return { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  if (algorithm === -257) return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  throw new Error("このパスキーには対応していません。");
}

async function passkeyVerifyAssertion(request, response, config) {
  if (!config || response.credentialId !== config.credentialId) throw new Error("登録されたパスキーを使用してください。");
  const { clientBytes, authenticator } = await passkeyValidateData(request, response, "webauthn.get");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientBytes));
  const signed = new Uint8Array(authenticator.length + hash.length);
  signed.set(authenticator); signed.set(hash, authenticator.length);
  // Credentials saved before algorithm negotiation were always ES256.
  const algorithm = config.algorithm ?? -7;
  const parameters = passkeyAlgorithm(algorithm);
  const publicKey = await crypto.subtle.importKey("spki", passkeyDecode(config.publicKey),
    parameters, false, ["verify"]);
  const signature = algorithm === -7 ? passkeyRawSignature(response.signature) : passkeyDecode(response.signature);
  if (!await crypto.subtle.verify(parameters, publicKey, signature, signed)) throw new Error("パスキーの署名を確認できません。");
}

async function passkeyRequestLogin(tabId, resumeUrl, failed401, targetUrl) {
  if (passkeyOpening.has(tabId)) return;
  passkeyOpening.add(tabId);
  try {
    const index = PASSKEY_TAB_PREFIX + tabId;
    const previous = (await chrome.storage.session.get(index))[index];
    if (previous) {
      const old = (await chrome.storage.session.get(PASSKEY_REQUEST_PREFIX + previous))[PASSKEY_REQUEST_PREFIX + previous];
      if (old && Date.now() - old.createdAt <= PASSKEY_TTL) {
        try { await chrome.tabs.get(old.promptTabId); return; } catch {}
      }
      await chrome.storage.session.remove([index, PASSKEY_REQUEST_PREFIX + previous]);
    }
    const config = await passkeyConfig();
    if (!config) return;
    const { id, request } = await passkeyNewRequest("login", {
      tabId, resumeUrl, failed401, targetUrl, credentialId: config.credentialId,
      prfSalt: config.prfSalt, transports: config.transports
    });
    await chrome.storage.session.set({ [index]: id });
    try {
      const tab = await chrome.tabs.create({ url: chrome.runtime.getURL("passkey-confirm.html") + "?id=" + id });
      request.promptTabId = tab.id;
      await chrome.storage.session.set({ [PASSKEY_REQUEST_PREFIX + id]: request });
    } catch (error) {
      await passkeyDeleteRequest(id, request);
      throw error;
    }
  } finally { passkeyOpening.delete(tabId); }
}

async function passkeyHandleMessage(message, sender) {
  sender = await passkeySender(sender, message.pageTabId);
  if (["passkeyBeginRegistration", "passkeyBeginDisable", "passkeyBeginConnect",
       "passkeyBeginUnlock"].includes(message.type)) {
    if (!passkeyIsOptions(sender)) throw new Error("設定画面から操作してください。");
    const config = await passkeyConfig();
    const registration = message.type === "passkeyBeginRegistration";
    if (registration && config?.prfSalt) throw new Error("PRF保護は既に有効です。");
    if (!registration && !config) throw new Error("パスキー確認は無効です。");
    if (message.type === "passkeyBeginUnlock" && !config?.prfSalt) {
      throw new Error("PRF暗号化された保管庫ではありません。");
    }
    const data = registration ? (await requireUnlocked()).data : null;
    const kind = registration ? "register" : message.type === "passkeyBeginConnect"
      ? "connect" : message.type === "passkeyBeginUnlock" ? "unlock" : "disable";
    const { id, request } = await passkeyNewRequest(kind, {
      optionsTabId: sender?.tab?.id, credentialId: config?.credentialId,
      transports: config?.transports,
      prfSalt: registration ? passkeyEncode(crypto.getRandomValues(new Uint8Array(32))) : config?.prfSalt,
      ...(registration ? { prfChallenge: passkeyEncode(crypto.getRandomValues(new Uint8Array(32))) } : {})
    });
    return { ok: true, id, challenge: request.challenge, prfChallenge: request.prfChallenge,
      prfSalt: request.prfSalt, transports: request.transports,
      credentialId: config?.credentialId, userId: passkeyEncode(crypto.getRandomValues(new Uint8Array(32))),
      username: data?.username || "ScombZ" };
  }
  const request = await passkeyReadRequest(message.id, sender);
  if (message.type === "passkeyGetRequest") {
    if (request.kind !== "login") throw new Error("確認内容が不正です。");
    return { ok: true, id: message.id,
      challenge: request.challenge, credentialId: request.credentialId,
      prfSalt: request.prfSalt, transports: request.transports };
  }
  if (message.type === "passkeyCancel") {
    await passkeyDeleteRequest(message.id, request);
    return { ok: true };
  }
  if (message.type !== "passkeyFinish") throw new Error("不明なパスキー操作です。");
  if (passkeyBusy.has(message.id)) throw new Error("確認を処理しています。");
  passkeyBusy.add(message.id);
  const changesConfig = request.kind === "register" || request.kind === "disable";
  if (changesConfig && passkeyBusy.has("configuration")) {
    passkeyBusy.delete(message.id);
    throw new Error("パスキー設定を変更しています。");
  }
  if (changesConfig) passkeyBusy.add("configuration");
  try {
    await passkeyDeleteRequest(message.id, request);
    if (request.kind === "register") {
      if ((await passkeyConfig())?.prfSalt) throw new Error("PRF保護は既に有効です。");
      await requireUnlocked();
      await passkeyValidateData(request, message.response, "webauthn.create");
      passkeyDecode(message.response.credentialId);
      const algorithm = message.response.algorithm;
      passkeyAlgorithm(algorithm);
      await passkeyVerifyAssertion({ challenge: request.prfChallenge }, message.response.proof, {
        credentialId: message.response.credentialId, publicKey: message.response.publicKey, algorithm
      });
      const transports = Array.isArray(message.response.transports)
        ? message.response.transports.filter(value =>
          ["internal", "usb", "nfc", "ble", "hybrid"].includes(value)) : [];
      await passkeyEnablePrfVault(message.response.prfOutput, {
        credentialId: message.response.credentialId, publicKey: message.response.publicKey, algorithm,
        prfSalt: request.prfSalt, transports
      });
    } else {
      const config = await passkeyConfig();
      if (config?.credentialId !== request.credentialId) throw new Error("パスキー設定が変更されました。");
      await passkeyVerifyAssertion(request, message.response, config);
      if (config.prfSalt) await passkeyUnlockPrfVault(message.response.prfOutput, config);
      if (request.kind === "disable") {
        if (config.prfSalt) await passkeyDisablePrfVault();
        else await chrome.storage.local.remove(PASSKEY_CONFIG_KEY);
      } else if (request.kind === "connect") {
        await chrome.storage.session.set({ ["sitPasskeyConnect:" + request.optionsTabId]: {
          credentialId: config.credentialId, expiresAt: Date.now() + 10000
        } });
      } else if (request.kind === "login") await passkeyResumeLogin(request);
    }
    return { ok: true };
  } finally {
    passkeyBusy.delete(message.id);
    if (changesConfig) passkeyBusy.delete("configuration");
  }
}

async function passkeyAuthorizeConnect(sender, pageTabId) {
  sender = await passkeySender(sender, pageTabId);
  const lock = "connect:" + sender?.tab?.id;
  if (passkeyBusy.has(lock)) throw new Error("API接続を処理しています。");
  passkeyBusy.add(lock);
  try {
    const config = await passkeyConfig();
    if (!config) return;
    if (!passkeyIsOptions(sender)) throw new Error("設定画面から操作してください。");
    const key = "sitPasskeyConnect:" + sender?.tab?.id;
    const grant = (await chrome.storage.session.get(key))[key];
    await chrome.storage.session.remove(key);
    if (!grant || grant.expiresAt < Date.now() || grant.credentialId !== config.credentialId) {
      throw new Error("API接続前にパスキーで確認してください。");
    }
  } finally { passkeyBusy.delete(lock); }
}

async function passkeyTabRemoved(tabId) {
  const stored = await chrome.storage.session.get(null);
  for (const [key, request] of Object.entries(stored)) {
    if (key.startsWith(PASSKEY_REQUEST_PREFIX) && request?.kind === "login" &&
        (request.tabId === tabId || request.promptTabId === tabId)) {
      await passkeyDeleteRequest(key.slice(PASSKEY_REQUEST_PREFIX.length), request);
    }
  }
  await chrome.storage.session.remove("sitPasskeyConnect:" + tabId);
}

async function passkeyClearRequests() {
  const stored = await chrome.storage.session.get(null);
  const keys = Object.keys(stored).filter(key => key.startsWith(PASSKEY_REQUEST_PREFIX) ||
    key.startsWith(PASSKEY_TAB_PREFIX) || key.startsWith("sitPasskeyConnect:"));
  if (keys.length) await chrome.storage.session.remove(keys);
}

async function passkeyCancelTarget(tabId) {
  const key = PASSKEY_TAB_PREFIX + tabId;
  const id = (await chrome.storage.session.get(key))[key];
  if (!id) return;
  const request = (await chrome.storage.session.get(PASSKEY_REQUEST_PREFIX + id))[PASSKEY_REQUEST_PREFIX + id];
  if (request) await passkeyDeleteRequest(id, request);
  else await chrome.storage.session.remove(key);
}
