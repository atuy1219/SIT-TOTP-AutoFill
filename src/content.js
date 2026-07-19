"use strict";

(() => {
  const TARGET_PATH_PREFIX = "/adfs/ls";
  const STATUS_ID = "sit-adfs-totp-status";

  let scheduled = null;
  let loginSubmitted = false;
  let providerSubmitted = false;
  let lastFilledStep = null;
  let lastSubmittedStep = null;

  if (!location.pathname.startsWith(TARGET_PATH_PREFIX)) return;

  function setNativeValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value"
    )?.set;

    setter?.call(input, value);
    input.dispatchEvent(
      new InputEvent("input", {
        bubbles: true,
        composed: true,
        inputType: "insertText",
        data: value
      })
    );
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }

  function getLoginElements() {
    const username = document.getElementById("userNameInput");
    const password = document.getElementById("passwordInput");
    const submit = document.getElementById("submitButton");
    const form = document.getElementById("loginForm");
    const kmsi = document.getElementById("kmsiInput");

    if (
      username instanceof HTMLInputElement &&
      password instanceof HTMLInputElement &&
      submit instanceof HTMLElement &&
      form instanceof HTMLFormElement
    ) {
      return {
        username,
        password,
        submit,
        form,
        kmsi: kmsi instanceof HTMLInputElement ? kmsi : null
      };
    }
    return null;
  }

  function getProviderElements() {
    const link = document.getElementById("AzureMfaAuthentication");
    const selection = document.getElementById("optionSelection");
    const form = document.getElementById("options");
    const wheel = document.getElementById("waitingWheelDiv");

    if (
      link instanceof HTMLElement &&
      selection instanceof HTMLInputElement &&
      form instanceof HTMLFormElement
    ) {
      return { link, selection, form, wheel };
    }
    return null;
  }

  function getOtpElements() {
    const input =
      document.getElementById("verificationCodeInput") ||
      document.getElementById("pin");
    const submit =
      document.getElementById("signInButton") ||
      document.getElementById("continueButton");
    const form = document.getElementById("loginForm");

    if (
      input instanceof HTMLInputElement &&
      submit instanceof HTMLElement
    ) {
      return {
        input,
        submit,
        form: form instanceof HTMLFormElement ? form : null
      };
    }
    return null;
  }

  function statusAnchor() {
    return (
      document.getElementById("verificationCodeDiv") ||
      document.getElementById("authOptionLinks") ||
      document.getElementById("formsAuthenticationArea") ||
      document.getElementById("customAuthArea") ||
      document.getElementById("loginArea")
    );
  }

  function showStatus(text, kind = "info") {
    const anchor = statusAnchor();
    if (!(anchor instanceof HTMLElement)) return;

    let element = document.getElementById(STATUS_ID);
    if (!element) {
      element = document.createElement("p");
      element.id = STATUS_ID;
      element.style.margin = "8px 0 0";
      element.style.fontSize = "13px";
      element.style.lineHeight = "1.45";
      element.style.fontFamily = "system-ui, sans-serif";
      anchor.insertAdjacentElement("afterend", element);
    }

    const colors = {
      info: "#3854a5",
      success: "#176b45",
      warning: "#8a5700",
      error: "#b3261e"
    };
    element.style.color = colors[kind] || colors.info;
    element.textContent = text;
  }

  function explainError(errorText) {
    const error = String(errorText || "");
    if (error.includes("ロック")) {
      showStatus("拡張機能を開いて保管庫を解除してください。", "warning");
    } else if (error.includes("初期設定")) {
      showStatus("拡張機能の初期設定が必要です。", "warning");
    } else {
      showStatus(error || "拡張機能との通信に失敗しました。", "error");
    }
  }

  function schedule(delay = 100) {
    clearTimeout(scheduled);
    scheduled = setTimeout(runStateMachine, delay);
  }

  function hasLoginError() {
    const error = document.getElementById("error");
    const text = document.getElementById("errorText");
    return Boolean(
      error &&
      getComputedStyle(error).display !== "none" &&
      String(text?.textContent || "").trim()
    );
  }

  async function handleLoginScreen() {
    const elements = getLoginElements();
    if (!elements || loginSubmitted || hasLoginError()) return false;

    let response;
    try {
      response = await chrome.runtime.sendMessage({ type: "adfsCredentials" });
    } catch {
      showStatus("拡張機能との通信に失敗しました。", "error");
      return true;
    }

    if (!response?.ok) {
      if (response?.reason === "disabled") return true;
      if (response?.reason === "missing") {
        showStatus("設定画面で大学IDとパスワードを登録してください。", "warning");
        return true;
      }
      explainError(response?.error);
      return true;
    }

    loginSubmitted = true;
    setNativeValue(elements.username, response.username);
    setNativeValue(elements.password, response.password);

    if (elements.kmsi) {
      elements.kmsi.checked = response.keepSignedIn === true;
      elements.kmsi.dispatchEvent(
        new Event("change", { bubbles: true, composed: true })
      );
    }

    showStatus(
      response.keepSignedIn
        ? "IDとパスワードを入力し、「サインアウトしない」を有効にしてサインインしています。"
        : "IDとパスワードを入力し、サインインしています。",
      "info"
    );

    // ADFSのLogin.submitLoginRequestと同じPOSTを行う。拡張機能側で必要項目を検証済み。
    setTimeout(() => {
      if (!hasLoginError()) {
        HTMLFormElement.prototype.submit.call(elements.form);
      } else {
        loginSubmitted = false;
      }
    }, 80);

    return true;
  }

  async function handleProviderScreen() {
    const elements = getProviderElements();
    if (!elements || providerSubmitted) return false;

    let response;
    try {
      response = await chrome.runtime.sendMessage({ type: "adfsSettings" });
    } catch {
      showStatus("拡張機能との通信に失敗しました。", "error");
      return true;
    }

    if (!response?.ok) {
      explainError(response?.error);
      return true;
    }

    if (!response.settings?.autoSelectProvider) return true;

    providerSubmitted = true;
    elements.selection.value = "AzureMfaAuthentication";
    if (elements.wheel instanceof HTMLElement) {
      elements.wheel.style.display = "inline";
    }
    showStatus("Azure Multi-Factor Authenticationを選択しています。", "info");

    // SelectOption()と同じ処理を直ちに実行し、拡張機能由来の待ち時間を入れない。
    HTMLFormElement.prototype.submit.call(elements.form);
    return true;
  }

  async function handleOtpScreen() {
    const elements = getOtpElements();
    if (!elements || elements.input.disabled || elements.input.readOnly) {
      return false;
    }

    if (/^\d{6}$/.test(elements.input.value)) return true;
    if (elements.input.value.trim()) return true;

    let response;
    try {
      response = await chrome.runtime.sendMessage({ type: "adfsCode" });
    } catch {
      showStatus("拡張機能との通信に失敗しました。", "error");
      return true;
    }

    if (!response?.ok) {
      if (response?.reason === "disabled") return true;
      explainError(response?.error);
      return true;
    }

    if (lastFilledStep === response.step) return true;
    lastFilledStep = response.step;

    elements.input.focus();
    setNativeValue(elements.input, response.code);
    showStatus(
      `SHA-256 TOTPを入力しました。残り約${response.remaining}秒です。`,
      "success"
    );

    if (response.autoSubmit && lastSubmittedStep !== response.step) {
      lastSubmittedStep = response.step;
      setTimeout(() => {
        if (
          elements.input.value === response.code &&
          !elements.submit.disabled
        ) {
          elements.submit.click();
        }
      }, 120);
    }

    return true;
  }

  async function runStateMachine() {
    if (await handleOtpScreen()) return;
    if (await handleProviderScreen()) return;
    await handleLoginScreen();
  }

  const observer = new MutationObserver(() => schedule());
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["disabled", "readonly", "style", "class"]
  });

  window.addEventListener("pageshow", () => schedule(0));
  document.addEventListener("focusin", () => schedule(), true);
  schedule(0);
})();
