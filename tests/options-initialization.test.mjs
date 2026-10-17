import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const visibility = await readFile(new URL("../src/visibility.js", import.meta.url), "utf8");
const optionsHtml = await readFile(new URL("../src/options.html", import.meta.url), "utf8");
const background = await readFile(new URL("../src/background.js", import.meta.url), "utf8");

function visibilityHarness({ seedConfigured = false, codeResponse } = {}) {
  const callbacks = new Map();
  const codes = { code: "123456", remaining: 25 };
  const sent = [];
  const dialog = {
    shown: false,
    showModal() { this.shown = true; },
    close() { this.shown = false; },
    addEventListener() {}
  };
  const elements = {
    initialCodeDialog: dialog,
    initialCodeDialogClose: { addEventListener() {} },
    initialCodeDialogCode: { textContent: "------" },
    initialCodeDialogRemaining: { textContent: "" },
    message: { textContent: "", classList: { add() {} } }
  };
  const document = {
    head: { append() {} },
    createElement: () => ({ textContent: "" }),
    querySelectorAll: () => [],
    getElementById: (id) => elements[id] || null,
    addEventListener: (name, handler) => callbacks.set(name, handler)
  };
  const chrome = {
    runtime: {
      sendMessage: async (message) => {
        sent.push(message.type);
        if (message.type === "getConfig") {
          return { ok: true, secretConfigured: seedConfigured };
        }
        if (message.type === "currentCode") {
          return codeResponse || { ok: true, ...codes };
        }
        throw new Error("Unexpected message " + message.type);
      }
    }
  };
  vm.runInNewContext(visibility, {
    document,
    chrome,
    setInterval: () => 1,
    clearInterval() {}
  });
  return {
    fireInitialSeedSaved: async () => {
      callbacks.get("sit:initialized-with-seed")();
      await new Promise((resolve) => setImmediate(resolve));
    },
    dialog,
    elements,
    sent
  };
}

test("initial panel changes alone do not request TOTP", async () => {
  const ui = visibilityHarness();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(ui.sent, []);
  assert.equal(ui.dialog.shown, false);
});

test("no seed suppresses first-run TOTP error even if signaled", async () => {
  const ui = visibilityHarness();
  await ui.fireInitialSeedSaved();
  assert.deepEqual(ui.sent, ["getConfig"]);
  assert.equal(ui.dialog.shown, false);
  assert.equal(ui.elements.message.textContent, "");
});

test("registered seed shows the verification dialog once", async () => {
  const ui = visibilityHarness({ seedConfigured: true });
  await ui.fireInitialSeedSaved();
  assert.deepEqual(ui.sent, ["getConfig", "currentCode"]);
  assert.equal(ui.dialog.shown, true);
  assert.equal(ui.elements.initialCodeDialogCode.textContent, "123456");
  assert.equal(ui.elements.initialCodeDialogRemaining.textContent, "残り25秒");
  await ui.fireInitialSeedSaved();
  assert.equal(ui.sent.length, 2);
});

test("not-configured result from currentCode is not an error", async () => {
  const ui = visibilityHarness({
    seedConfigured: true,
    codeResponse: { ok: false, reason: "not-configured" }
  });
  await ui.fireInitialSeedSaved();
  assert.equal(ui.dialog.shown, false);
  assert.equal(ui.elements.message.textContent, "");
});

test("legacy ADFS automation defaults to off, explicit previous settings remain supported", () => {
  const start = background.indexOf("function normalizeSettings(");
  const end = background.indexOf("function getUnlockMode(", start);
  assert.ok(start >= 0 && end > start);
  const normalize = vm.runInNewContext(
    background.slice(start, end) + "\nnormalizeSettings",
    {}
  );
  const settings = normalize({});
  for (const key of [
    "autoLogin", "keepSignedIn", "autoSelectProvider", "autoFill", "autoSubmit"
  ]) {
    assert.equal(settings[key], false, key);
    assert.doesNotMatch(
      optionsHtml,
      new RegExp('id="initial' + key[0].toUpperCase() + key.slice(1) + '"[^>]*checked')
    );
  }
  const previous = normalize({
    autoLogin: true, keepSignedIn: true,
    autoSelectProvider: true, autoFill: true, autoSubmit: true
  });
  assert.equal(previous.autoFill, true);
  assert.equal(previous.autoLogin, true);
});
