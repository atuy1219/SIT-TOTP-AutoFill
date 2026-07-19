"use strict";

const byId = (id) => document.getElementById(id);
let refreshTimer = null;
let copyResetTimer = null;
let lastCode = "";

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
  element.textContent = text;
  element.classList.toggle("error", error);
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
    message(result?.error || "コードを取得できません。", true);
    await refreshStatus();
    return;
  }

  lastCode = result.code;
  byId("code").textContent = result.code;
  byId("remaining").textContent = `${result.remaining}秒`;
  byId("progressBar").style.width =
    `${Math.max(0, Math.min(100, (result.remaining / result.period) * 100))}%`;
}

async function refreshStatus() {
  const status = await send("status");
  clearInterval(refreshTimer);
  resetCopyButton();

  if (!status.initialized) {
    byId("setupMessage").textContent = "初期設定が必要です。";
    showPanel("setupPanel");
    return;
  }

  if (!status.unlocked) {
    if (status.unlockMode === "device") {
      byId("setupMessage").textContent =
        "端末内の自動解除キーを読み込めません。設定からバックアップをインポートするか、再設定してください。";
      showPanel("setupPanel");
      return;
    }

    showPanel("unlockPanel");
    byId("unlockPassword").focus();
    return;
  }

  byId("lockButton").hidden = status.unlockMode === "device";
  showPanel("codePanel");
  await refreshCode();
  refreshTimer = setInterval(refreshCode, 1000);
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
  message("解除しました。");
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

byId("lockButton").addEventListener("click", async () => {
  await send("lock");
  message("ロックしました。");
  await refreshStatus();
});

byId("optionsButton").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

byId("openOptionsFromSetup").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

refreshStatus().catch((error) => message(error.message, true));
