import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/passkey-client.js", import.meta.url), "utf8");
function harness({ cancel = false, enabled = false, synced = false, supported = true, prfSupported = true } = {}) {
  const messages = [], requested = [];
  const options = { ok: true, id: "request", challenge: "AQID",
    userId: "BAUG", username: "test", credentialId: "BwgJ",
    prfChallenge: "AQID", prfSalt: Buffer.from(new Uint8Array(32).fill(1)).toString("base64url") };
  const auth = new Uint8Array(37); auth[32] = synced ? 13 : 5;
  const credential = {
    rawId: new Uint8Array([7, 8, 9]),
    response: {
      getPublicKey: () => new Uint8Array([10]), getPublicKeyAlgorithm: () => -7,
      getAuthenticatorData: () => auth, getTransports: () => ["internal", "hybrid"],
      clientDataJSON: new Uint8Array([12]), authenticatorData: auth, signature: new Uint8Array([14])
    },
    getClientExtensionResults: () => prfSupported ? { prf: { results: {
      first: new Uint8Array(32).fill(9).buffer
    } } } : {} 
  };
  async function request(options) {
    requested.push(options);
    if (cancel) throw new Error("cancelled");
    return credential;
  }
  const denyNetwork = () => { throw new Error("Network access is forbidden"); };
  const ctx = vm.createContext({
    Uint8Array, ArrayBuffer, btoa, atob, PublicKeyCredential: supported ? class {} : undefined,
    fetch: denyNetwork, XMLHttpRequest: denyNetwork, WebSocket: denyNetwork,
    navigator: { credentials: { create: request, get: request } },
    chrome: {
      tabs: { getCurrent: async () => ({ id: 2 }), create: denyNetwork, update: denyNetwork },
      permissions: {
        request: () => { throw new Error("No extra permission should be requested"); },
        contains: () => { throw new Error("No host permission should be checked"); }
      },
      runtime: { sendMessage: async message => {
        messages.push(message);
        return message.type === "getConfig" ? { ok: true, passkeyEnabled: enabled } : options;
      } }
    }
  });
  vm.runInContext(source, ctx);
  return { messages, requested,
    run: method => vm.runInContext("PasskeyClient." + method, ctx)() };
}

test("registration omits rp.id without network access or extra permissions", async () => {
  const h = harness();
  await h.run("register");
  assert.equal(Object.hasOwn(h.requested[0].publicKey.rp, "id"), false);
  assert.deepEqual(Array.from(h.requested[0].publicKey.pubKeyCredParams, entry => entry.alg), [-7, -257]);
  assert.equal(h.requested[0].publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(h.requested[0].publicKey.attestation, "none");
  assert.deepEqual(Array.from(h.requested[0].publicKey.challenge), [1, 2, 3]);
  assert.equal(h.messages.at(-1).response.publicKey, "Cg");
  assert.equal(h.requested.length, 2, "PRF output must be requested using a fresh assertion");
  assert.equal(h.messages.at(-1).response.proof.credentialId, "BwgJ");
  assert.equal(h.messages.at(-1).response.transports.includes("hybrid"), true);
  assert.equal(h.messages.at(-1).response.prfOutput, Buffer.from(new Uint8Array(32).fill(9)).toString("base64url"));
});

test("unavailable WebAuthn never starts registration", async () => {
  const h = harness({ supported: false });
  await assert.rejects(h.run("register"));
  assert.equal(h.messages.length, 0);
  assert.equal(h.requested.length, 0);
});

test("syncable Google Password Manager style credentials are permitted", async () => {
  const h = harness({ synced: true });
  await h.run("register");
  assert.equal(h.messages.at(-1).type, "passkeyFinish");
});

test("PRF is required and registration failure never enables the vault", async () => {
  for (const options of [{ cancel: true }, { prfSupported: false }]) {
    const h = harness(options);
    await assert.rejects(h.run("register"));
    assert.deepEqual(h.messages.map(m => m.type), ["passkeyBeginRegistration", "passkeyCancel"]);
  }
});

test("API connection asks for local verification only when the setting is enabled", async () => {
  const disabled = harness();
  await disabled.run("confirmConnect");
  assert.equal(disabled.requested.length, 0);
  {
    const enabled = harness({ enabled: true });
    await enabled.run("confirmConnect");
    assert.equal(enabled.requested[0].publicKey.userVerification, "required");
    assert.equal(Object.hasOwn(enabled.requested[0].publicKey, "rpId"), false);
    assert.equal(enabled.requested[0].publicKey.allowCredentials[0].transports, undefined);
    assert.ok(enabled.requested[0].publicKey.extensions?.prf);
    assert.equal(enabled.messages.at(-1).type, "passkeyFinish");
  }
});
