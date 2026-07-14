"use strict";

const byId = (id) => document.getElementById(id);
let refreshTimer = null;
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

  if (!status.initialized) {
    showPanel("setupPanel");
    return;
  }

  if (!status.unlocked) {
    showPanel("unlockPanel");
    byId("unlockPassword").focus();
    return;
  }

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
  await navigator.clipboard.writeText(lastCode);
  message("コードをコピーしました。");
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
