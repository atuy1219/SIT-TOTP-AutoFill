import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/passkey-auth.js", import.meta.url), "utf8");
const base = "chrome-extension://test-extension/";
const rpId = base.slice(0, -1);
const optionsSender = { url: base + "options.html", tab: { id: 2 } };
const encode = value => Buffer.from(value).toString("base64url");
const hash = value => webcrypto.subtle.digest("SHA-256", value);

function storage() {
  const values = {};
  return { values,
    get: async key => key === null ? { ...values } : ({ [key]: values[key] }),
    set: async object => { Object.assign(values, structuredClone(object)); },
    remove: async keys => { for (const key of [].concat(keys)) delete values[key]; }
  };
}

function harness(shared) {
  const local = shared?.local || storage(), session = shared?.session || storage();
  const prompts = [], resumed = [];
  let now = 1000000;
  const chrome = {
    runtime: { id: "test-extension", getURL: file => base + file },
    storage: { local, session },
    tabs: {
      create: async options => {
        assert.ok(options.url.startsWith(base), "only an extension-owned confirmation tab may open");
        const tab = { id: 10 + prompts.length, ...options }; prompts.push(tab); return tab;
      },
      get: async id => ({ id, url: id === 2 ? optionsSender.url : prompts.find(tab => tab.id === id)?.url })
    }
  };
  class FakeDate extends Date { static now() { return now; } }
  const denyNetwork = () => { throw new Error("Network access is forbidden during passkey authentication"); };
  const context = vm.createContext({
    crypto: webcrypto, Uint8Array, TextEncoder, TextDecoder, btoa, atob, URL,
    Date: FakeDate, chrome, fetch: denyNetwork, XMLHttpRequest: denyNetwork, WebSocket: denyNetwork,
    requireUnlocked: async () => ({ data: { username: "test-user" } }),
    passkeyEnablePrfVault: async (output, config) => {
      assert.equal(Buffer.from(output, "base64url").length, 32);
      assert.equal(Buffer.from(config.prfSalt, "base64url").length, 32);
      await local.set({ sitScombzLocalPasskey: config });
    },
    passkeyUnlockPrfVault: async (output) => {
      assert.equal(Buffer.from(output, "base64url").length, 32);
    },
    passkeyDisablePrfVault: async () => {
      await local.remove("sitScombzLocalPasskey");
    },
    passkeyResumeLogin: async request => { resumed.push(request); }
  });
  vm.runInContext(source, context);
  const invoke = (name, ...args) => vm.runInContext(name, context)(...args);
  return { local, session, chrome, prompts, resumed, invoke,
    advance: ms => { now += ms; },
    call: (message, sender = optionsSender) => invoke("passkeyHandleMessage", message, sender) };
}

async function authenticator(flags = 5, domain = rpId) {
  const bytes = new Uint8Array(37);
  bytes.set(new Uint8Array(await hash(new TextEncoder().encode(domain))));
  bytes[32] = flags;
  return bytes;
}

function clientData(options, type = "webauthn.get", overrides = {}) {
  return new TextEncoder().encode(JSON.stringify({
    type, challenge: options.challenge, origin: base.slice(0, -1), crossOrigin: false, ...overrides
  }));
}

async function enroll(h) {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = encode(await webcrypto.subtle.exportKey("spki", keys.publicKey));
  const options = await h.call({ type: "passkeyBeginRegistration" });
  assert.equal(Object.hasOwn(options, "rpId"), false);
  const credentialId = encode(new Uint8Array([1, 2, 3]));
  const registration = { keys, publicKey, credentialId };
  const proof = await assertion({ challenge: options.prfChallenge }, registration);
  const response = { credentialId, publicKey, algorithm: -7,
    clientDataJSON: encode(clientData(options, "webauthn.create")),
    authenticatorData: encode(await authenticator()), transports: ["internal", "hybrid"],
    prfOutput: encode(new Uint8Array(32).fill(7)), proof };
  await h.call({ type: "passkeyFinish", id: options.id, response });
  return { keys, publicKey, credentialId: response.credentialId };
}

function derSignature(raw) {
  const parts = [raw.slice(0, 32), raw.slice(32)].map(bytes => {
    let part = Array.from(bytes);
    while (part.length > 1 && !part[0]) part.shift();
    if (part[0] & 128) part.unshift(0);
    return [2, part.length, ...part];
  });
  return Uint8Array.from([0x30, parts[0].length + parts[1].length, ...parts[0], ...parts[1]]);
}

async function assertion(options, registration, { flags = 5, domain = rpId, client = {}, credentialId = registration.credentialId } = {}) {
  const data = clientData(options, "webauthn.get", client);
  const auth = await authenticator(flags, domain);
  const digest = new Uint8Array(await hash(data));
  const signed = new Uint8Array(auth.length + digest.length);
  signed.set(auth); signed.set(digest, auth.length);
  const raw = new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, registration.keys.privateKey, signed));
  return { credentialId, clientDataJSON: encode(data), authenticatorData: encode(auth),
    signature: encode(derSignature(raw)), prfOutput: encode(new Uint8Array(32).fill(7)) };
}

async function loginRequest(h, tabId = 4) {
  await h.invoke("passkeyRequestLogin", tabId, "https://scombz.shibaura-it.ac.jp/lms/course", false,
    "https://scombz.shibaura-it.ac.jp/login");
  const prompt = h.prompts.at(-1);
  const id = new URL(prompt.url).searchParams.get("id");
  const sender = { url: prompt.url, tab: { id: prompt.id } };
  const options = await h.call({ type: "passkeyGetRequest", id }, sender);
  return { id, sender, options };
}

test("registration and verification work without any network API or external tab", async () => {
  const h = harness();
  assert.equal(await h.invoke("passkeyConfig"), null);
  await h.invoke("passkeyAuthorizeConnect", optionsSender);
  const registration = await enroll(h), first = await loginRequest(h);
  const response = await assertion(first.options, registration);
  await h.call({ type: "passkeyFinish", id: first.id, response }, first.sender);
  assert.equal(h.resumed.length, 1);
  await assert.rejects(h.call({ type: "passkeyFinish", id: first.id, response }, first.sender));
  const second = await loginRequest(h);
  assert.notEqual(first.options.challenge, second.options.challenge);
  assert.equal(h.resumed.length, 1, "the next login remains locked");
});

test("request survives service-worker restart without granting access", async () => {
  const h = harness(), registration = await enroll(h), request = await loginRequest(h);
  const restarted = harness(h);
  await restarted.call({ type: "passkeyFinish", id: request.id,
    response: await assertion(request.options, registration) }, request.sender);
  assert.equal(restarted.resumed.length, 1);
});

for (const [name, overrides] of [
  ["wrong challenge", { client: { challenge: "wrong" } }],
  ["wrong origin", { client: { origin: "https://example.com" } }],
  ["cross-origin request", { client: { crossOrigin: true } }],
  ["wrong response type", { client: { type: "webauthn.create" } }],
  ["missing user verification", { flags: 1 }],
  ["missing user presence", { flags: 4 }],
  ["wrong relying party", { domain: "example.com" }],
  ["wrong credential", { credentialId: "different" }]
]) test(`rejects ${name} without resuming login`, async () => {
  const h = harness(), registration = await enroll(h), request = await loginRequest(h);
  await assert.rejects(h.call({ type: "passkeyFinish", id: request.id,
    response: await assertion(request.options, registration, overrides) }, request.sender));
  assert.equal(h.resumed.length, 0);
});

test("synced credentials with BE/BS flags are allowed when their signatures and PRF verify", async () => {
  for (const flags of [13, 29]) {
    const h = harness(), registration = await enroll(h), request = await loginRequest(h);
    const response = await assertion(request.options, registration, { flags });
    response.prfOutput = encode(new Uint8Array(32).fill(7));
    await h.call({ type: "passkeyFinish", id: request.id, response }, request.sender);
    assert.equal(h.resumed.length, 1);
  }
});

test("registration rejects invalid proof of the newly created passkey", async () => {
  const h = harness();
  const options = await h.call({ type: "passkeyBeginRegistration" });
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = encode(await webcrypto.subtle.exportKey("spki", keys.publicKey));
  const response = { credentialId: "AQID", publicKey, algorithm: -7,
    clientDataJSON: encode(clientData(options, "webauthn.create")),
    authenticatorData: encode(await authenticator()), prfOutput: encode(new Uint8Array(32)),
    proof: { credentialId: "AQID", clientDataJSON: "", authenticatorData: "", signature: "" } };
  await assert.rejects(h.call({ type: "passkeyFinish", id: options.id, response }));
  assert.equal(await h.invoke("passkeyConfig"), null);
});

test("invalid signature is rejected and its challenge is consumed", async () => {
  const h = harness(), registration = await enroll(h), request = await loginRequest(h);
  const response = await assertion(request.options, registration);
  const bytes = Buffer.from(response.signature, "base64url");
  bytes[bytes.length - 1] ^= 1;
  response.signature = encode(bytes);
  await assert.rejects(h.call({ type: "passkeyFinish", id: request.id, response }, request.sender));
  await assert.rejects(h.call({ type: "passkeyGetRequest", id: request.id }, request.sender));
  assert.equal(h.resumed.length, 0);
});

test("cancel and expiry do not authorize a login", async () => {
  const h = harness(), registration = await enroll(h), request = await loginRequest(h);
  await h.call({ type: "passkeyCancel", id: request.id }, request.sender);
  await assert.rejects(h.call({ type: "passkeyFinish", id: request.id,
    response: await assertion(request.options, registration) }, request.sender));
  const expired = await loginRequest(h);
  h.advance(120001);
  await assert.rejects(h.call({ type: "passkeyFinish", id: expired.id,
    response: await assertion(expired.options, registration) }, expired.sender));
  assert.equal(h.resumed.length, 0);
});

test("only the issuing extension page can submit a response", async () => {
  const h = harness();
  await assert.rejects(h.call({ type: "passkeyBeginRegistration" }, { url: "https://example.com" }));
  const registration = await enroll(h), request = await loginRequest(h);
  const response = await assertion(request.options, registration);
  await assert.rejects(h.call({ type: "passkeyFinish", id: request.id, response }, optionsSender));
  await assert.rejects(h.call({ type: "passkeyFinish", id: request.id, response }, {
    url: request.sender.url, tab: { id: 999 }
  }));
  assert.equal(h.resumed.length, 0);
});

test("duplicate requests share a confirmation tab while other tabs remain independent", async () => {
  const h = harness();
  await enroll(h);
  await Promise.all([h.invoke("passkeyRequestLogin", 4), h.invoke("passkeyRequestLogin", 4)]);
  await h.invoke("passkeyRequestLogin", 4);
  await h.invoke("passkeyRequestLogin", 5);
  assert.equal(h.prompts.length, 2);
});

test("disabling confirmation also requires the registered local credential", async () => {
  const h = harness(), registration = await enroll(h);
  await assert.rejects(h.call({ type: "passkeyBeginRegistration" }));
  const options = await h.call({ type: "passkeyBeginDisable" });
  await h.call({ type: "passkeyFinish", id: options.id, response: await assertion(options, registration) });
  assert.equal(await h.invoke("passkeyConfig"), null);
});

test("API approval is one-use, tab-bound and expires", async () => {
  const h = harness(), registration = await enroll(h);
  await assert.rejects(h.invoke("passkeyAuthorizeConnect", optionsSender));
  const options = await h.call({ type: "passkeyBeginConnect" });
  await h.call({ type: "passkeyFinish", id: options.id, response: await assertion(options, registration) });
  await assert.rejects(h.invoke("passkeyAuthorizeConnect", { ...optionsSender, tab: { id: 3 } }));
  await h.invoke("passkeyAuthorizeConnect", optionsSender);
  await assert.rejects(h.invoke("passkeyAuthorizeConnect", optionsSender));
  const next = await h.call({ type: "passkeyBeginConnect" });
  await h.call({ type: "passkeyFinish", id: next.id, response: await assertion(next, registration) });
  h.advance(10001);
  await assert.rejects(h.invoke("passkeyAuthorizeConnect", optionsSender));
});

test("Firefox origin derives from the fixed extension ID", async () => {
  const h = harness();
  h.chrome.runtime.getURL = file => "moz-extension://random-install-id/" + file;
  const expected = "moz-extension://" + Buffer.from(await hash(new TextEncoder().encode("test-extension")))
    .toString("hex").replace(/[0-9a-f]/g, digit => String.fromCharCode(97 + parseInt(digit, 16)));
  assert.equal(await h.invoke("passkeyOrigin"), expected);
});

test("closing a target or confirmation tab clears only its request", async () => {
  const h = harness();
  await enroll(h);
  const first = await loginRequest(h, 4), second = await loginRequest(h, 5);
  await h.invoke("passkeyTabRemoved", first.sender.tab.id);
  await assert.rejects(h.call({ type: "passkeyGetRequest", id: first.id }, first.sender));
  assert.equal((await h.call({ type: "passkeyGetRequest", id: second.id }, second.sender)).ok, true);
  await h.invoke("passkeyTabRemoved", 5);
  await assert.rejects(h.call({ type: "passkeyGetRequest", id: second.id }, second.sender));
  await h.invoke("passkeyClearRequests");
  assert.equal(Object.keys(h.session.values).length, 0);
});

test("extension pages without sender.tab use a browser-checked tab hint", async () => {
  const h = harness();
  const options = await h.call({ type: "passkeyBeginRegistration", pageTabId: 2 }, { url: optionsSender.url });
  assert.equal(options.ok, true);
  await assert.rejects(h.call({ type: "passkeyBeginRegistration", pageTabId: 999 }, { url: optionsSender.url }));
});

test("logout cancels a stored approval even across service-worker restarts", async () => {
  const h = harness(), registration = await enroll(h), request = await loginRequest(h);
  await h.invoke("passkeyCancelTarget", 4);
  const restarted = harness(h);
  await assert.rejects(restarted.call({ type: "passkeyFinish", id: request.id,
    response: await assertion(request.options, registration) }, request.sender));
  assert.equal(restarted.resumed.length, 0);
});

test("confirmation and settings pages block connection APIs using CSP", async () => {
  for (const file of ["options.html", "passkey-confirm.html"]) {
    const html = await readFile(new URL("../src/" + file, import.meta.url), "utf8");
    assert.match(html, /http-equiv="Content-Security-Policy"[^>]*connect-src 'none'/);
  }
  const manifest = JSON.parse(await readFile(new URL("../src/manifest.json", import.meta.url), "utf8"));
  assert.equal(manifest.optional_host_permissions, undefined);
});

test("Chrome RP ID hash uses the full extension origin, not the bare extension ID", async () => {
  const h = harness();
  const request = { challenge: "chrome-extension-rp-challenge" };
  const client = encode(clientData(request, "webauthn.create"));
  await h.invoke("passkeyValidateData", request, {
    clientDataJSON: client, authenticatorData: encode(await authenticator(5, rpId))
  }, "webauthn.create");
  await assert.rejects(h.invoke("passkeyValidateData", request, {
    clientDataJSON: client, authenticatorData: encode(await authenticator(5, "test-extension"))
  }, "webauthn.create"));
});

test("default RP hashes are constrained to the extension's own identities", async () => {
  const h = harness();
  h.chrome.runtime.getURL = file => "moz-extension://random-install-id/" + file;
  const origin = await h.invoke("passkeyOrigin");
  const request = { challenge: "own-extension-challenge" };
  const client = encode(clientData(request, "webauthn.create", { origin }));
  for (const domain of ["random-install-id", new URL(origin).hostname]) {
    await h.invoke("passkeyValidateData", request, {
      clientDataJSON: client, authenticatorData: encode(await authenticator(5, domain))
    }, "webauthn.create");
  }
  for (const domain of ["localhost", "other-extension", "example.com"]) {
    await assert.rejects(h.invoke("passkeyValidateData", request, {
      clientDataJSON: client, authenticatorData: encode(await authenticator(5, domain))
    }, "webauthn.create"));
  }
});
