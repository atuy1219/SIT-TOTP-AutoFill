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

function updateInitialMasterPasswordMode() {
  const useMasterPassword = byId("initialUseMasterPassword").checked;
  byId("initialMasterPasswordFields").hidden = !useMasterPassword;
  byId("deviceUnlockWarning").hidden = useMasterPassword;
  byId("initialMasterPassword").disabled = !useMasterPassword;
  byId("initialMasterPasswordConfirm").disabled = !useMasterPassword;

  if (!useMasterPassword) {
    byId("initialMasterPassword").value = "";
    byId("initialMasterPasswordConfirm").value = "";
  }
}

function updateInitialAutoLoginMode() {
  const autoLogin = byId("initialAutoLogin").checked;
  byId("initialUsername").disabled = !autoLogin;
  byId("initialAccountPassword").disabled = !autoLogin;
  byId("initialKeepSignedIn").disabled = !autoLogin;

  if (!autoLogin) {
    byId("initialUsername").value = "";
    byId("initialAccountPassword").value = "";
    byId("initialKeepSignedIn").checked = false;
  }
}

function readInitialSettings() {
  return {
    autoLogin: byId("initialAutoLogin").checked,
    keepSignedIn: byId("initialKeepSignedIn").checked,
    autoSelectProvider: byId("initialAutoSelectProvider").checked,
    autoFill: byId("initialAutoFill").checked,
    autoSubmit: byId("initialAutoSubmit").checked
  };
}

function readSettings() {
  return {
    autoLogin: byId("autoLogin").checked,
    keepSignedIn: byId("keepSignedIn").checked,
    autoSelectProvider: byId("autoSelectProvider").checked,
    autoFill: byId("autoFill").checked,
    autoSubmit: byId("autoSubmit").checked
  };
}

async function refresh() {
  const status = await send("status");

  if (!status.initialized) {
    showState("initialize");
    updateInitialMasterPasswordMode();
    updateInitialAutoLoginMode();
    return;
  }

  if (!status.unlocked) {
    const deviceMode = status.unlockMode === "device";
    showState("unlock");
    byId("unlockDescription").textContent = deviceMode
      ? "端末内の自動解除キーを読み込めません。データを削除して初期設定をやり直してください。"
      : "マスターパスワードを入力してください。";
    byId("unlockMasterPasswordLabel").hidden = deviceMode;
    byId("unlockButton").hidden = deviceMode;
    byId("resetLockedButton").hidden = !deviceMode;
    if (!deviceMode) byId("unlockMasterPassword").focus();
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

  const deviceMode = config.unlockMode === "device";
  byId("unlockModeStatus").textContent = deviceMode
    ? "マスターパスワードなし：端末内の自動解除キーを使用します。"
    : "マスターパスワードで暗号化されています。";
  byId("unlockModeStatus").classList.toggle("warning", deviceMode);
  byId("lockButton").hidden = deviceMode;
}

byId("initialUseMasterPassword").addEventListener(
  "change",
  updateInitialMasterPasswordMode
);
byId("initialAutoLogin").addEventListener("change", updateInitialAutoLoginMode);

byId("initializeButton").addEventListener("click", async () => {
  const useMasterPassword = byId("initialUseMasterPassword").checked;
  const masterPassword = byId("initialMasterPassword").value;

  if (
    useMasterPassword &&
    masterPassword !== byId("initialMasterPasswordConfirm").value
  ) {
    message("マスターパスワードの確認が一致しません。", true);
    return;
  }

  const autoLogin = byId("initialAutoLogin").checked;
  const result = await send("initialize", {
    useMasterPassword,
    masterPassword,
    username: autoLogin ? byId("initialUsername").value : "",
    accountPassword: autoLogin ? byId("initialAccountPassword").value : "",
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

byId("resetLockedButton").addEventListener("click", async () => {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  await send("reset");
  message("すべて削除しました。");
  await refresh();
});

byId("resetButton").addEventListener("click", async () => {
  if (!confirm("暗号化保管庫と設定を完全に削除しますか？")) return;
  await send("reset");
  message("すべて削除しました。");
  await refresh();
});

updateInitialMasterPasswordMode();
updateInitialAutoLoginMode();
refresh().catch((error) => message(error.message, true));
