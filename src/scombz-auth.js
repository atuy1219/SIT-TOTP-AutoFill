"use strict";

// ScombZ Mobile API authentication is independent from Microsoft ADFS/TOTP.
// A browser navigation (not fetch) completes the OTKEY redirect so the browser
// receives the SESSION cookie through ordinary Set-Cookie handling.
const SCOMBZ_ORIGIN = "https://scombz.shibaura-it.ac.jp";
const SCOMBZ_MOBILE_ORIGIN = "https://mobile.scombz.shibaura-it.ac.jp";
const SCOMBZ_API_ORIGIN = "https://smob.sic.shibaura-it.ac.jp";
const SCOMBZ_API_BASE = SCOMBZ_API_ORIGIN + "/smob/api/";
const SCOMBZ_HOST = "scombz.shibaura-it.ac.jp";
const SCOMBZ_REQUEST_TIMEOUT = 25000;
const SCOMBZ_MAX_RESPONSE = 1024 * 1024;

function scombzStudentId(username) {
  const match = String(username || "").trim().match(/^([a-z]{2}\d{5})(?:@sic)?$/i);
  if (!match) throw new Error("ScombZ用に英字2文字＋数字5桁の学籍番号を設定してください。");
  return match[1].toUpperCase();
}

function scombzValidToken(value) {
  return typeof value === "string" &&
    value.length > 0 && value.length <= 8192 &&
    /^[\x21-\x7e]+$/.test(value);
}

async function scombzRequest(path, { token, user, password } = {}) {
  const url = new URL(path, SCOMBZ_API_BASE);
  if (url.origin !== SCOMBZ_API_ORIGIN || !url.pathname.startsWith("/smob/api/")) {
    throw new Error("ScombZ APIのURLが不正です。");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SCOMBZ_REQUEST_TIMEOUT);
  try {
    const login = path === "login";
    const response = await fetch(url.href, {
      method: login ? "POST" : "GET",
      redirect: "manual",
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(login ? { "Content-Type": "application/json" } : { Authorization: "Bearer " + token })
      },
      ...(login ? { body: JSON.stringify({ user, pass: password }) } : {})
    });
    if (response.status === 401 || response.status === 403) {
      const error = new Error("ScombApp APIの認証が失効しました。再接続してください。");
      error.authExpired = true;
      throw error;
    }
    if (!response.ok) throw new Error("ScombApp APIがHTTP " + response.status + "を返しました。");
    if (Number(response.headers.get("content-length") || 0) > SCOMBZ_MAX_RESPONSE) {
      throw new Error("ScombApp APIの応答が大きすぎます。");
    }
    const bodyText = await response.text();
    if (new TextEncoder().encode(bodyText).byteLength > SCOMBZ_MAX_RESPONSE) {
      throw new Error("ScombApp APIの応答が大きすぎます。");
    }
    let data;
    try { data = JSON.parse(bodyText); }
    catch { throw new Error("ScombApp APIの応答がJSONではありません。"); }
    if (data?.status !== "OK") {
      throw new Error("ScombApp APIが処理を拒否しました。");
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function scombzApiLogin(username, password) {
  if (typeof password !== "string" || !password || password.length > 1024) {
    throw new Error("ScombApp APIに接続するための大学パスワードを入力してください。");
  }
  const response = await scombzRequest("login", {
    user: scombzStudentId(username),
    password
  });
  if (!scombzValidToken(response.token)) {
    throw new Error("ScombApp APIから有効なBearer Tokenが返りませんでした。");
  }
  return response.token;
}

async function scombzGetOtkey(token) {
  if (!scombzValidToken(token)) {
    throw new Error("ScombZの接続設定がありません。再接続してください。");
  }
  const response = await scombzRequest("otkey", { token });
  if (!scombzValidToken(response.otkey) || response.otkey.length > 2048) {
    throw new Error("ScombApp APIから有効なOTKEYが返りませんでした。");
  }
  return response.otkey;
}


function scombzBridgeUrl(otkey) {
  if (!scombzValidToken(otkey) || otkey.length > 2048) {
    throw new Error("OTKEYが不正です。");
  }
  // The Mobile API bridge is only guaranteed to establish a Web SESSION
  // through /portal/home. Deep links are restored AFTER the cookie arrives.
  return SCOMBZ_MOBILE_ORIGIN + "/" + encodeURIComponent(otkey) +
    "/portal/home";
}

// Never put OTKEY, Bearer Token or the redirect URL in an error message or log.
