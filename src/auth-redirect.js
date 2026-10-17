"use strict";

const panel = document.getElementById("recoveryPanel");
const message = document.getElementById("status");
const fallback = document.getElementById("manualLoginButton");
let recovering = true;

function showRecoveryError(text) {
  message.textContent = text;
  panel.hidden = false;
  fallback.disabled = false;
}

async function useNormalLogin() {
  if (!recovering) return;
  recovering = false;
  fallback.disabled = true;
  try {
    const response = await chrome.runtime.sendMessage({
      type: "scombzBypassFallback"
    });
    if (response?.ok) return;
    throw new Error("Fallback unavailable");
  } catch {
    recovering = true;
    showRecoveryError("自動認証を続行できません。設定画面からログイン画面の迂回を無効にしてください。");
  }
}

fallback.addEventListener("click", useNormalLogin);

// A browser redirect still requires an extension document for the DNR
// interception, but it need not display a status screen to the user.
chrome.runtime.sendMessage({ type: "scombzBypassLogin" }).then((result) => {
  if (result?.ok) return;
  // Most backend failures already navigated to the university login.
  // If not, try the explicit fallback without exposing transient UI.
  return useNormalLogin();
}).catch(useNormalLogin);

// Only show a manual escape hatch if browser/extension messaging is stuck.
setTimeout(() => {
  if (recovering) {
    showRecoveryError("認証に時間がかかっています。通常のログイン画面へ切り替えられます。");
  }
}, 30000);
