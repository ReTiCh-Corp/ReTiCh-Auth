"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/retich-auth.ts
var retich_auth_exports = {};
__export(retich_auth_exports, {
  ReTiChAuth: () => ReTiChAuth
});
module.exports = __toCommonJS(retich_auth_exports);
var STORAGE_PREFIX = "retich_";
var STORAGE_KEYS = {
  accessToken: `${STORAGE_PREFIX}access_token`,
  refreshToken: `${STORAGE_PREFIX}refresh_token`,
  expiresAt: `${STORAGE_PREFIX}expires_at`,
  user: `${STORAGE_PREFIX}user`,
  pkceVerifier: `${STORAGE_PREFIX}pkce_verifier`,
  pkceState: `${STORAGE_PREFIX}pkce_state`
};
function decodeJWT(token) {
  try {
    const payload = token.split(".")[1];
    return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return null;
  }
}
async function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}
var ReTiChAuth = class {
  constructor(config) {
    this._user = null;
    this._accessToken = null;
    this._refreshToken = null;
    this._expiresAt = null;
    this._refreshTimer = null;
    this._refreshPromise = null;
    this._observers = [];
    if (!config.baseUrl) throw new Error("baseUrl is required");
    if (!config.clientId) throw new Error("clientId is required");
    if (!config.clientSecret) throw new Error("clientSecret is required");
    if (!config.redirectUri) throw new Error("redirectUri is required");
    this._baseUrl = config.baseUrl.replace(/\/$/, "");
    this._clientId = config.clientId;
    this._clientSecret = config.clientSecret;
    this._redirectUri = config.redirectUri;
    this._restore();
  }
  // ── Auth state ──────────────────────────────────────────────────────────────
  get currentUser() {
    return this._user;
  }
  onAuthStateChanged(callback) {
    this._observers.push(callback);
    callback(this._user);
    return () => {
      this._observers = this._observers.filter((cb) => cb !== callback);
    };
  }
  // ── Sign In ─────────────────────────────────────────────────────────────────
  async signIn() {
    const verifier = await generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const state = generateState();
    sessionStorage.setItem(STORAGE_KEYS.pkceVerifier, verifier);
    sessionStorage.setItem(STORAGE_KEYS.pkceState, state);
    const params = new URLSearchParams({
      client_id: this._clientId,
      redirect_uri: this._redirectUri,
      response_type: "code",
      scope: "openid email profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state
    });
    window.location.href = `${this._baseUrl}/oauth/authorize?${params}`;
  }
  async handleRedirectResult() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (!code) return null;
    const savedState = sessionStorage.getItem(STORAGE_KEYS.pkceState);
    const verifier = sessionStorage.getItem(STORAGE_KEYS.pkceVerifier);
    if (!verifier) throw new Error("PKCE verifier manquant \u2014 flow corrompu");
    if (state !== savedState) throw new Error("State invalide \u2014 possible CSRF");
    sessionStorage.removeItem(STORAGE_KEYS.pkceVerifier);
    sessionStorage.removeItem(STORAGE_KEYS.pkceState);
    const res = await fetch(`${this._baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this._redirectUri,
        client_id: this._clientId,
        client_secret: this._clientSecret,
        code_verifier: verifier
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(
        err.error_description ?? "\xC9chec de l'\xE9change du code"
      );
    }
    const tokens = await res.json();
    this._setTokens(tokens);
    window.history.replaceState({}, "", window.location.pathname);
    return this._user;
  }
  // ── Sign Out ────────────────────────────────────────────────────────────────
  async signOut() {
    try {
      const token = await this.getAccessToken();
      if (token) {
        await fetch(`${this._baseUrl}/api/v1/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` }
        });
      }
    } catch {
    }
    this._clear();
  }
  // ── Token management ────────────────────────────────────────────────────────
  async getAccessToken() {
    if (!this._accessToken) return null;
    const now = Date.now();
    const expiresAt = this._expiresAt ?? 0;
    const shouldRefresh = expiresAt - now < 6e4;
    if (shouldRefresh) {
      await this._refresh();
    }
    return this._accessToken;
  }
  // ── Internals ───────────────────────────────────────────────────────────────
  async _refresh() {
    if (this._refreshPromise) return this._refreshPromise;
    this._refreshPromise = (async () => {
      if (!this._refreshToken) {
        this._clear();
        return;
      }
      try {
        const res = await fetch(`${this._baseUrl}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: this._refreshToken,
            client_id: this._clientId,
            client_secret: this._clientSecret
          })
        });
        if (!res.ok) {
          this._clear();
          return;
        }
        const tokens = await res.json();
        this._setTokens(tokens);
      } catch {
        this._clear();
      }
    })();
    try {
      await this._refreshPromise;
    } finally {
      this._refreshPromise = null;
    }
  }
  _setTokens(tokens) {
    const { access_token, refresh_token, expires_in } = tokens;
    this._accessToken = access_token;
    this._refreshToken = refresh_token ?? this._refreshToken;
    this._expiresAt = Date.now() + (expires_in ?? 900) * 1e3;
    const claims = decodeJWT(access_token);
    this._user = claims ? {
      id: claims.user_id,
      email: claims.email,
      ...claims
    } : null;
    this._persist();
    this._scheduleRefresh(expires_in ?? 900);
    this._notify();
  }
  _scheduleRefresh(expiresInSeconds) {
    if (this._refreshTimer) clearTimeout(this._refreshTimer);
    const delay = Math.max((expiresInSeconds - 60) * 1e3, 0);
    this._refreshTimer = setTimeout(() => this._refresh(), delay);
  }
  _persist() {
    localStorage.setItem(STORAGE_KEYS.accessToken, this._accessToken ?? "");
    localStorage.setItem(STORAGE_KEYS.refreshToken, this._refreshToken ?? "");
    localStorage.setItem(STORAGE_KEYS.expiresAt, String(this._expiresAt ?? ""));
    localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(this._user));
  }
  _restore() {
    const accessToken = localStorage.getItem(STORAGE_KEYS.accessToken);
    const refreshToken = localStorage.getItem(STORAGE_KEYS.refreshToken);
    const expiresAt = Number(localStorage.getItem(STORAGE_KEYS.expiresAt));
    const userRaw = localStorage.getItem(STORAGE_KEYS.user);
    if (!accessToken || !refreshToken) return;
    this._accessToken = accessToken;
    this._refreshToken = refreshToken;
    this._expiresAt = expiresAt || null;
    this._user = userRaw ? JSON.parse(userRaw) : null;
    if (!expiresAt || Date.now() > expiresAt - 6e4) {
      this._refresh();
    } else {
      const remainingSeconds = (expiresAt - Date.now()) / 1e3;
      this._scheduleRefresh(remainingSeconds);
    }
  }
  _clear() {
    if (this._refreshTimer) clearTimeout(this._refreshTimer);
    this._accessToken = null;
    this._refreshToken = null;
    this._expiresAt = null;
    this._user = null;
    this._refreshPromise = null;
    Object.values(STORAGE_KEYS).forEach((key) => localStorage.removeItem(key));
    this._notify();
  }
  _notify() {
    this._observers.forEach((cb) => cb(this._user));
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  ReTiChAuth
});
//# sourceMappingURL=retich-auth.js.map