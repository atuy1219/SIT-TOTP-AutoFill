import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/options.js", import.meta.url), "utf8");
const start = source.indexOf("const BACKUP_FORMAT =");
const end = source.indexOf("function updateInitialAutoLoginMode()", start);
assert.ok(start >= 0 && end > start);
const ctx = vm.createContext({
  crypto: webcrypto, Uint8Array, TextEncoder, TextDecoder, btoa, atob, Date,
  URL, Blob, setTimeout, clearTimeout
});
vm.runInContext(source.slice(start, end), ctx);
const encrypt = vm.runInContext("encryptBackupData", ctx);
const decrypt = vm.runInContext("decryptEncryptedBackup", ctx);
const data = {
  username: "al25133@sic",
  secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  settings: { autoFill: true, scombzAutoLogin: false }
};

test("optional backup password uses authenticated encryption", async () => {
  const envelope = await encrypt(data, "strong-backup-password");
  assert.equal(envelope.version, 3);
  assert.equal(envelope.vault.kdf, "PBKDF2-SHA256");
  assert.equal(envelope.vault.iterations, 310000);
  assert.equal(Object.hasOwn(envelope, "data"), false);
  assert.equal(JSON.stringify(envelope).includes(data.secret), false);
  const recovered = await decrypt(envelope, "strong-backup-password");
  assert.equal(recovered.secret, data.secret);
  assert.equal(recovered.username, data.username);
  assert.equal(recovered.settings.autoFill, true);
  assert.equal(recovered.password, undefined);
  assert.equal(recovered.scombzToken, undefined);
});

test("backup rejects incorrect passwords and altered ciphertext", async () => {
  const envelope = await encrypt(data, "strong-backup-password");
  await assert.rejects(decrypt(envelope, "wrong-password"), /パスワード/);
  envelope.vault.ciphertext = "AAAA" + envelope.vault.ciphertext.slice(4);
  await assert.rejects(decrypt(envelope, "strong-backup-password"), /破損/);
});

test("backup rejects unsupported encryption parameters", async () => {
  const envelope = await encrypt(data, "strong-backup-password");
  envelope.vault.iterations = 1;
  await assert.rejects(decrypt(envelope, "strong-backup-password"), /形式/);
});
