"use strict";

(() => {
  const HOST_ID = "sit-adfs-totp-diagnostics";
  const UNKNOWN_DELAY_MS = 4000;
  let unknownSince = 0;
  let scheduled = null;

  function elementState(id) {
    return document.getElementById(id) ? "found" : "not found";
  }

  function detectScreen() {
    if (
      document.getElementById("userNameInput") &&
      document.getElementById("passwordInput") &&
      document.getElementById("submitButton")
    ) {
      return "login";
    }
    if (
      document.getElementById("AzureMfaAuthentication") &&
      document.getElementById("optionSelection")
    ) {
      return "provider-selection";
    }
    if (
      document.getElementById("verificationCodeInput") ||
      document.getElementById("pin")
    ) {
      return "totp";
    }
    return "unknown";
  }

  function diagnosticText() {
    const ids = [
      "userNameInput",
      "passwordInput",
      "submitButton",
      "AzureMfaAuthentication",
      "optionSelection",
      "verificationCodeInput",
      "pin",
      "signInButton",
      "continueButton",
      "loginForm"
    ];
    return [
      "SIT ADFS TOTP Autofill diagnostics",
      `Extension version: ${chrome.runtime.getManifest().version}`,
      `Page path: ${location.pathname}`,
      `Detected screen: ${detectScreen()}`,
      `Document state: ${document.readyState}`,
      `Forms: ${document.forms.length}`,
      "Elements:",
      ...ids.map((id) => `  ${id}: ${elementState(id)}`)
    ].join("\n");
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {}

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }

  function removePanel() {
    document.getElementById(HOST_ID)?.remove();
  }

  function showPanel() {
    if (!document.body || document.getElementById(HOST_ID)) return;

    const host = document.createElement("div");
    host.id = HOST_ID;
    host.style.position = "fixed";
    host.style.right = "16px";
    host.style.bottom = "16px";
    host.style.zIndex = "2147483647";
    host.style.width = "min(360px, calc(100vw - 32px))";
    const shadow = host.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .panel {
        box-sizing: border-box;
        border: 1px solid rgba(0, 0, 0, .2);
        border-radius: 10px;
        padding: 14px;
        background: #fff;
        color: #202124;
        box-shadow: 0 8px 28px rgba(0, 0, 0, .22);
        font: 13px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
      }
      strong { display: block; margin-bottom: 4px; font-size: 14px; }
      p { margin: 0 0 10px; }
      button {
        border: 0;
        border-radius: 7px;
        padding: 8px 11px;
        background: #4051a1;
        color: #fff;
        cursor: pointer;
        font: inherit;
        font-weight: 600;
      }
      button:focus-visible { outline: 2px solid #4051a1; outline-offset: 2px; }
      .status { min-height: 1.4em; margin-top: 7px; color: #4d5156; }
      @media (prefers-color-scheme: dark) {
        .panel { border-color: rgba(255, 255, 255, .24); background: #202124; color: #f1f3f4; }
        .status { color: #bdc1c6; }
      }
    `;

    const panel = document.createElement("div");
    panel.className = "panel";
    const title = document.createElement("strong");
    title.textContent = "ログイン画面を認識できません";
    const description = document.createElement("p");
    description.textContent =
      "大学側の画面構造が変更された可能性があります。認証情報を含まない診断情報をコピーできます。";
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "診断情報をコピー";
    const status = document.createElement("div");
    status.className = "status";
    status.setAttribute("aria-live", "polite");

    button.addEventListener("click", async () => {
      try {
        await copyText(diagnosticText());
        status.textContent = "診断情報をコピーしました。";
      } catch {
        status.textContent = "コピーできませんでした。";
      }
    });

    panel.append(title, description, button, status);
    shadow.append(style, panel);
    document.body.append(host);
  }

  function evaluate() {
    scheduled = null;
    if (detectScreen() !== "unknown") {
      unknownSince = 0;
      removePanel();
      return;
    }

    if (!unknownSince) unknownSince = Date.now();
    const elapsed = Date.now() - unknownSince;
    if (elapsed >= UNKNOWN_DELAY_MS) {
      showPanel();
      return;
    }
    schedule(UNKNOWN_DELAY_MS - elapsed);
  }

  function schedule(delay = 250) {
    clearTimeout(scheduled);
    scheduled = setTimeout(evaluate, delay);
  }

  const observer = new MutationObserver(() => schedule());
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["id", "class", "style"]
  });
  window.addEventListener("pageshow", () => schedule(0));
  schedule(0);
})();
