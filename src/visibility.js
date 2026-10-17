"use strict";

(() => {
  const eyeIcon = `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"></path>
      <circle cx="12" cy="12" r="2.75"></circle>
    </svg>`;
  let codeTimer = null;
  let confirmationShown = false;
  let confirmationInProgress = false;

  const style = document.createElement("style");
  style.textContent = `
    .secret-input-wrap {
      position: relative;
      display: block;
      margin-top: 5px;
    }
    .secret-input-wrap input[type="password"],
    .secret-input-wrap input[type="text"] {
      margin-top: 0;
      padding-right: 44px;
    }
    .password-toggle {
      position: absolute;
      top: 50%;
      right: 4px;
      transform: translateY(-50%);
      display: grid;
      place-items: center;
      width: 34px;
      height: 34px;
      margin: 0;
      padding: 6px;
      border: 0;
      background: transparent;
      color: var(--muted);
    }
    .password-toggle:hover,
    .password-toggle.visible {
      color: var(--primary);
      background: color-mix(in srgb, var(--primary) 9%, Canvas);
    }
    .password-toggle svg {
      width: 21px;
      height: 21px;
      fill: none;
      stroke: currentColor;
      stroke-width: 1.8;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .input-requirement {
      display: block;
      margin-top: 6px;
      color: var(--muted);
      font-size: 12px;
    }
    .code-dialog {
      width: min(420px, calc(100vw - 32px));
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      background: Canvas;
      color: CanvasText;
      box-shadow: 0 16px 48px rgba(0, 0, 0, .28);
    }
    .code-dialog::backdrop { background: rgba(0, 0, 0, .48); }
    .saved-code-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin: 18px 0;
      padding: 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface);
    }
    .dialog-code {
      font-size: 34px;
      letter-spacing: .12em;
      font-variant-numeric: tabular-nums;
    }
    #initialPreviewButton,
    #initialPreview { display: none !important; }
  `;
  document.head.append(style);

  for (const input of document.querySelectorAll('input[type="password"]')) {
    if (input.parentElement?.classList.contains("secret-input-wrap")) continue;
    const wrapper = document.createElement("span");
    wrapper.className = "secret-input-wrap";
    input.parentNode.insertBefore(wrapper, input);
    wrapper.append(input);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "password-toggle";
    button.title = "入力内容を表示";
    button.setAttribute("aria-label", "入力内容を表示");
    button.innerHTML = eyeIcon;
    button.addEventListener("click", () => {
      const visible = input.type === "text";
      input.type = visible ? "password" : "text";
      button.classList.toggle("visible", !visible);
      button.title = visible ? "入力内容を表示" : "入力内容を隠す";
      button.setAttribute(
        "aria-label",
        visible ? "入力内容を表示" : "入力内容を隠す"
      );
      input.focus();
    });
    wrapper.append(button);
  }

  const dialog = document.getElementById("initialCodeDialog");

  function stopCodeRefresh() {
    clearInterval(codeTimer);
    codeTimer = null;
  }

  async function refreshCode() {
    const result = await chrome.runtime.sendMessage({ type: "currentCode" });
    // ScombZ-only setup can validly omit the TOTP seed.
    if (result?.reason === "not-configured") return false;
    if (!result?.ok) throw new Error(result?.error || "コードを取得できません。");
    document.getElementById("initialCodeDialogCode").textContent = result.code;
    document.getElementById("initialCodeDialogRemaining").textContent =
      "残り" + result.remaining + "秒";
    return true;
  }

  async function showCodeConfirmation() {
    if (!dialog || confirmationShown || confirmationInProgress) return;
    confirmationInProgress = true;
    try {
      const config = await chrome.runtime.sendMessage({ type: "getConfig" });
      if (config?.ok && !config.secretConfigured) return;
      if (!config?.ok) throw new Error(config?.error || "設定を確認できません。");
      if (!await refreshCode()) return;
      confirmationShown = true;
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
      codeTimer = setInterval(() => {
        refreshCode().then((ok) => { if (!ok) stopCodeRefresh(); })
          .catch(stopCodeRefresh);
      }, 1000);
    } finally {
      confirmationInProgress = false;
    }
  }

  // Only initial setup with a saved seed may open this confirmation.
  // Panel visibility changes do not indicate that TOTP was configured.
  document.addEventListener("sit:initialized-with-seed", () => {
    showCodeConfirmation().catch((error) => {
      const message = document.getElementById("message");
      if (message) {
        message.textContent = error.message;
        message.classList.add("error");
      }
    });
  });

  document.getElementById("initialCodeDialogClose")?.addEventListener("click", () => {
    stopCodeRefresh();
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  });
  dialog?.addEventListener("close", stopCodeRefresh);
  dialog?.addEventListener("cancel", stopCodeRefresh);

})();
