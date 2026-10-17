"use strict";

const byId = (id) => document.getElementById(id);
let refreshTimer = null;
let copyResetTimer = null;
let lastCode = "";
let notificationTimer = null;

async function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra });
}

function showPanel(id) {
  for (const panel of ["setupPanel", "unlockPanel", "codePanel"]) {
    byId(panel).hidden = panel !== id;
  }
}

function message(text, error = false) {
  const element = byId("message");
  clearTimeout(notificationTimer);
  element.textContent = text;
  element.classList.toggle("error", error);
  if (!text) return;
  // Important errors stay longer, but neither success nor error permanently
  // covers the top of the screen.
  notificationTimer = setTimeout(() => {
    element.textContent = "";
    element.classList.remove("error");
  }, error ? 10000 : 5500);
}

function formatTotpCode(code) {
  return String(code).replace(/^(\d{3})(\d{3})$/, "$1 $2");
}

function resetCopyButton() {
  clearTimeout(copyResetTimer);
  const button = byId("copyButton");
  button.classList.remove("copied");
  button.title = "コードをコピー";
  button.setAttribute("aria-label", "コードをコピー");
}

async function refreshCode() {
  const result = await send("currentCode");
  if (!result?.ok) {
    clearInterval(refreshTimer);
    if (result?.reason === "not-configured") {
      lastCode = "";
      showPanel(null);
      return false;
    }
    message(result?.error || "コードを取得できません。", true);
    return false;
  }

  lastCode = result.code;
  byId("code").textContent = formatTotpCode(result.code);
  byId("remaining").textContent = `${result.remaining}秒`;
  byId("progressBar").style.width =
    String(Math.max(0, Math.min(100, (result.remaining / result.period) * 100))) + "%";
  return true;
}

async function refreshStatus() {
  const status = await send("status");
  clearInterval(refreshTimer);
  resetCopyButton();
  byId("scombzPanel").hidden = true;

  if (!status.initialized) {
    byId("setupMessage").textContent = "初期設定が必要です。";
    showPanel("setupPanel");
    return;
  }

  if (!status.unlocked) {
    if (status.unlockMode !== "legacy") {
      byId("setupMessage").textContent =
        "端末内の自動解除キーを読み込めません。設定からバックアップをインポートするか、再設定してください。";
      showPanel("setupPanel");
      return;
    }

    showPanel("unlockPanel");
    byId("unlockPassword").focus();
    return;
  }

  const config = await send("getConfig");
  if (!config?.ok) {
    message(config?.error || "設定を読み込めません。", true);
    return;
  }
  const useScombz = config.settings.scombzAutoLogin === true;
  const connected = config.scombzConnected === true;
  byId("scombzPanel").hidden = !useScombz && !connected;
  byId("scombzPopupStatus").textContent = connected
    ? "API接続済み"
    : "ScombApp APIへの接続が必要です。設定を開いてください。";
  if (!config.secretConfigured) {
    showPanel(null);
    return;
  }
  showPanel("codePanel");
  if (await refreshCode()) refreshTimer = setInterval(refreshCode, 1000);
}

byId("unlockButton").addEventListener("click", async () => {
  const result = await send("unlock", {
    masterPassword: byId("unlockPassword").value
  });
  if (!result?.ok) {
    message(result?.error || "解除できませんでした。", true);
    return;
  }
  byId("unlockPassword").value = "";
  message("旧データを移行しました。以後マスターパスワードは不要です。");
  await refreshStatus();
});

byId("unlockPassword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") byId("unlockButton").click();
});

byId("copyButton").addEventListener("click", async () => {
  if (!lastCode) return;
  try {
    await navigator.clipboard.writeText(lastCode);
    const button = byId("copyButton");
    button.classList.add("copied");
    button.title = "コピーしました";
    button.setAttribute("aria-label", "コピーしました");
    message("コードをコピーしました。");
    clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(resetCopyButton, 1400);
  } catch {
    message("クリップボードへコピーできませんでした。", true);
  }
});

byId("scombzPopupSettingsButton").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

byId("optionsButton").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

byId("openOptionsFromSetup").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

byId("extensionVersion").textContent = `v${chrome.runtime.getManifest().version}`;
refreshStatus().catch((error) => message(error.message, true));
