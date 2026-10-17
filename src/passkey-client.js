"use strict";

const PasskeyClient = (() => {
  const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const decode = text => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  async function send(type, extra = {}) {
    const tab = await chrome.tabs.getCurrent();
    const result = await chrome.runtime.sendMessage({ type, ...extra, pageTabId: tab?.id });
    if (!result?.ok) throw new Error(result?.error || "パスキーを確認できません。");
    return result;
  }
  function supported() {
    if (!globalThis.PublicKeyCredential || !navigator.credentials) {
      throw new Error("この環境はパスキーに対応していません。");
    }
  }
  function assertionResponse(credential) {
    return { credentialId: encode(credential.rawId),
      clientDataJSON: encode(credential.response.clientDataJSON),
      authenticatorData: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature) };
  }
  function prfOutput(credential, required) {
    if (!required) return undefined;
    const output = credential.getClientExtensionResults?.().prf?.results?.first;
    if (!(output instanceof ArrayBuffer) && !ArrayBuffer.isView(output)) {
      throw new Error("このブラウザまたは認証器はWebAuthn PRFに対応していません。");
    }
    if (output.byteLength !== 32) throw new Error("PRFの出力が不正です。");
    return encode(output);
  }
  async function authenticate(options) {
    supported();
    const publicKey = {
      challenge: decode(options.challenge),
      // Leave transports unspecified so synced credentials can work on other devices.
      allowCredentials: [{ type: "public-key", id: decode(options.credentialId) }],
      userVerification: "required", timeout: 60000
    };
    if (options.prfSalt) publicKey.extensions = { prf: { eval: { first: decode(options.prfSalt) } } };
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) throw new Error("パスキー確認がキャンセルされました。");
    return send("passkeyFinish", { id: options.id, response: {
      ...assertionResponse(credential), prfOutput: prfOutput(credential, Boolean(options.prfSalt))
    } });
  }
  async function register() {
    supported();
    const options = await send("passkeyBeginRegistration");
    try {
      const credential = await navigator.credentials.create({ publicKey: {
        rp: { name: "ScombZ Login Helper（PRF暗号化）" },
        user: { id: decode(options.userId), name: options.username, displayName: options.username },
        challenge: decode(options.challenge), pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        extensions: { prf: { eval: { first: decode(options.prfSalt) } } },
        attestation: "none", timeout: 60000
      } });
      if (!credential?.response?.getPublicKey || !credential.response.getAuthenticatorData) {
        throw new Error("この環境ではパスキーによる認証情報の保護を有効にできません。");
      }
      const authenticator = new Uint8Array(credential.response.getAuthenticatorData());
       const publicKey = credential.response.getPublicKey();
      if (!publicKey) throw new Error("パスキーの公開鍵を取得できません。");
      // A fresh assertion proves that this credential supplies the required PRF output.
      const proof = await navigator.credentials.get({ publicKey: {
        challenge: decode(options.prfChallenge),
        allowCredentials: [{ type: "public-key", id: new Uint8Array(credential.rawId) }],
        userVerification: "required", timeout: 60000,
        extensions: { prf: { eval: { first: decode(options.prfSalt) } } }
      } });
      if (!proof) throw new Error("PRF確認がキャンセルされました。");
      return await send("passkeyFinish", { id: options.id, response: {
        credentialId: encode(credential.rawId), publicKey: encode(publicKey),
        algorithm: credential.response.getPublicKeyAlgorithm(),
        clientDataJSON: encode(credential.response.clientDataJSON),
        authenticatorData: encode(authenticator),
        transports: credential.response.getTransports?.() || [],
        proof: assertionResponse(proof), prfOutput: prfOutput(proof, true)
      } });
    } catch (error) {
      await send("passkeyCancel", { id: options.id }).catch(() => {});
      throw error;
    }
  }
  async function disable() {
    const options = await send("passkeyBeginDisable");
    try { return await authenticate(options); }
    catch (error) {
      await send("passkeyCancel", { id: options.id }).catch(() => {});
      throw error;
    }
  }
  async function unlock() {
    const options = await send("passkeyBeginUnlock");
    try { return await authenticate(options); }
    catch (error) {
      await send("passkeyCancel", { id: options.id }).catch(() => {});
      throw error;
    }
  }
  async function confirmConnect() {
    const config = await send("getConfig");
    if (!config.passkeyEnabled) return;
    const options = await send("passkeyBeginConnect");
    try { return await authenticate(options); }
    catch (error) {
      await send("passkeyCancel", { id: options.id }).catch(() => {});
      throw error;
    }
  }
  return { register, disable, unlock, authenticate, confirmConnect, send };
})();
