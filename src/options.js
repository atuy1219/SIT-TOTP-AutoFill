"use strict";

const byId = (id) => document.getElementById(id);

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

function readInitialSettings() {
  return {
    autoLogin: byId("initialAutoLogin").checked,
    keepSignedIn: byId("initialKeepSignedIn").checked,
    autoSelectProvider: byId("initialAutoSelectProvider").checked,
    autoFill: byId("initialAutoFill").checked,
    autoSubmit: byId("initialAutoSubmit").checked,
    minRemainingSeconds: 5
  };
}

function readSettings() {
  return {
    autoLogin: byId("autoLogin").checked,
    keepSignedIn: byId("keepSignedIn").checked,
    autoSelectProvider: byId("autoSelectProvider").checked,
    autoFill: byId("autoFill").checked,
    autoSubmit: byId("autoSubmit").checked,
    minRemainingSeconds: Number(byId("minRemainingSeconds").value)
  };
}

async function refresh() {
  const status = await send("status");

  if (!status.initialized) {
    showState("initialize");
    return;
  }

  if (!status.unlocked) {
    showState("unlock");
    byId("unlockMasterPassword").focus();
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
  byId("minRemainingSeconds").value =
    String(config.settings.minRemainingSeconds);
}

byId("initializeButton").addEventListener("click", async () => {
  const masterPassword = byId("initialMasterPassword").value;
  if (masterPassword !== byId("initialMasterPasswordConfirm").value) {
    message("マスターパスワードの確認が一致しません。", true);
    return;
  }

  const result = await send("initialize", {
    masterPassword,
    username: byId("initialUsername").value,
    accountPassword: byId("initialAccountPassword").value,
    secret: byId("initialSecret").value,
    settings: readInitialSettings()
  });

  if (!result?.ok) {
    message(result?.error || "保存できませんでした。", true);
    return;
  }

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

byId("lockButton").addEventListener("click", async () => {
  await send("lock");
  message("ロックしました。");
  await refresh();
});

byId("resetButton").addEventListener("click", async () => {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  await send("reset");
  message("すべて削除しました。");
  await refresh();
});

refresh().catch((error) => message(error.message, true));
