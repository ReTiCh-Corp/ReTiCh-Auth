const STORAGE_PREFIX = "retich_"
const STORAGE_KEYS = {
  accessToken: `${STORAGE_PREFIX}access_token`,
  refreshToken: `${STORAGE_PREFIX}refresh_token`,
  expiresAt: `${STORAGE_PREFIX}expires_at`,
  user: `${STORAGE_PREFIX}user`,
  pkceVerifier: `${STORAGE_PREFIX}pkce_verifier`,
  pkceState: `${STORAGE_PREFIX}pkce_state`,
} as const

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ReTiChAuthConfig {
  /** URL du service ReTiCh Auth (ex: "https://auth.mondomaine.com") */
  baseUrl: string
  /** client_id obtenu via la console admin */
  clientId: string
  /** client_secret obtenu via la console admin */
  clientSecret: string
  /** URL de callback après login (ex: "https://monapp.com/callback") */
  redirectUri: string
}

export interface ReTiChUser {
  id: string
  email: string
  user_id: string
  email_verified?: boolean
  exp?: number
  iat?: number
  iss?: string
  aud?: string
  [key: string]: unknown
}

export type AuthStateCallback = (user: ReTiChUser | null) => void
export type Unsubscribe = () => void

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in?: number
  token_type?: string
  id_token?: string
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split(".")[1]
    return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")))
  } catch {
    return null
  }
}

async function generateCodeVerifier(): Promise<string> {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const digest = await crypto.subtle.digest("SHA-256", data)
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "")
}

function generateState(): string {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("")
}

// ─── SDK ─────────────────────────────────────────────────────────────────────

export class ReTiChAuth {
  private readonly _baseUrl: string
  private readonly _clientId: string
  private readonly _clientSecret: string
  private readonly _redirectUri: string

  private _user: ReTiChUser | null = null
  private _accessToken: string | null = null
  private _refreshToken: string | null = null
  private _expiresAt: number | null = null
  private _refreshTimer: ReturnType<typeof setTimeout> | null = null
  private _refreshPromise: Promise<void> | null = null
  private _observers: AuthStateCallback[] = []

  constructor(config: ReTiChAuthConfig) {
    if (!config.baseUrl) throw new Error("baseUrl is required")
    if (!config.clientId) throw new Error("clientId is required")
    if (!config.clientSecret) throw new Error("clientSecret is required")
    if (!config.redirectUri) throw new Error("redirectUri is required")

    this._baseUrl = config.baseUrl.replace(/\/$/, "")
    this._clientId = config.clientId
    this._clientSecret = config.clientSecret
    this._redirectUri = config.redirectUri

    this._restore()
  }

  // ── Auth state ──────────────────────────────────────────────────────────────

  get currentUser(): ReTiChUser | null {
    return this._user
  }

  onAuthStateChanged(callback: AuthStateCallback): Unsubscribe {
    this._observers.push(callback)
    callback(this._user)
    return () => {
      this._observers = this._observers.filter((cb) => cb !== callback)
    }
  }

  // ── Sign In ─────────────────────────────────────────────────────────────────

  async signIn(): Promise<void> {
    const verifier = await generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    const state = generateState()

    sessionStorage.setItem(STORAGE_KEYS.pkceVerifier, verifier)
    sessionStorage.setItem(STORAGE_KEYS.pkceState, state)

    const params = new URLSearchParams({
      client_id: this._clientId,
      redirect_uri: this._redirectUri,
      response_type: "code",
      scope: "openid email profile",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
    })

    window.location.href = `${this._baseUrl}/oauth/authorize?${params}`
  }

  async handleRedirectResult(): Promise<ReTiChUser | null> {
    const params = new URLSearchParams(window.location.search)
    const code = params.get("code")
    const state = params.get("state")

    if (!code) return null

    const savedState = sessionStorage.getItem(STORAGE_KEYS.pkceState)
    const verifier = sessionStorage.getItem(STORAGE_KEYS.pkceVerifier)

    if (!verifier) throw new Error("PKCE verifier manquant — flow corrompu")
    if (state !== savedState) throw new Error("State invalide — possible CSRF")

    sessionStorage.removeItem(STORAGE_KEYS.pkceVerifier)
    sessionStorage.removeItem(STORAGE_KEYS.pkceState)

    const res = await fetch(`${this._baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this._redirectUri,
        client_id: this._clientId,
        client_secret: this._clientSecret,
        code_verifier: verifier,
      }),
    })

    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(
        (err as { error_description?: string }).error_description ??
          "Échec de l'échange du code"
      )
    }

    const tokens: TokenResponse = await res.json()
    this._setTokens(tokens)

    window.history.replaceState({}, "", window.location.pathname)

    return this._user
  }

  // ── Sign Out ────────────────────────────────────────────────────────────────

  async signOut(): Promise<void> {
    try {
      const token = await this.getAccessToken()
      if (token) {
        await fetch(`${this._baseUrl}/api/v1/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        })
      }
    } catch {
      // Clear côté client dans tous les cas
    }
    this._clear()
  }

  // ── Token management ────────────────────────────────────────────────────────

  async getAccessToken(): Promise<string | null> {
    if (!this._accessToken) return null

    const now = Date.now()
    const expiresAt = this._expiresAt ?? 0
    const shouldRefresh = expiresAt - now < 60_000

    if (shouldRefresh) {
      await this._refresh()
    }

    return this._accessToken
  }

  // ── Internals ───────────────────────────────────────────────────────────────

  private async _refresh(): Promise<void> {
    if (this._refreshPromise) return this._refreshPromise

    this._refreshPromise = (async () => {
      if (!this._refreshToken) {
        this._clear()
        return
      }

      try {
        const res = await fetch(`${this._baseUrl}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: this._refreshToken,
            client_id: this._clientId,
            client_secret: this._clientSecret,
          }),
        })

        if (!res.ok) {
          this._clear()
          return
        }

        const tokens: TokenResponse = await res.json()
        this._setTokens(tokens)
      } catch {
        this._clear()
      }
    })()

    try {
      await this._refreshPromise
    } finally {
      this._refreshPromise = null
    }
  }

  private _setTokens(tokens: TokenResponse): void {
    const { access_token, refresh_token, expires_in } = tokens

    this._accessToken = access_token
    this._refreshToken = refresh_token ?? this._refreshToken
    this._expiresAt = Date.now() + (expires_in ?? 900) * 1000

    const claims = decodeJWT(access_token)
    this._user = claims
      ? ({
          id: claims.user_id as string,
          email: claims.email as string,
          ...claims,
        } as ReTiChUser)
      : null

    this._persist()
    this._scheduleRefresh(expires_in ?? 900)
    this._notify()
  }

  private _scheduleRefresh(expiresInSeconds: number): void {
    if (this._refreshTimer) clearTimeout(this._refreshTimer)
    const delay = Math.max((expiresInSeconds - 60) * 1000, 0)
    this._refreshTimer = setTimeout(() => this._refresh(), delay)
  }

  private _persist(): void {
    localStorage.setItem(STORAGE_KEYS.accessToken, this._accessToken ?? "")
    localStorage.setItem(STORAGE_KEYS.refreshToken, this._refreshToken ?? "")
    localStorage.setItem(STORAGE_KEYS.expiresAt, String(this._expiresAt ?? ""))
    localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(this._user))
  }

  private _restore(): void {
    const accessToken = localStorage.getItem(STORAGE_KEYS.accessToken)
    const refreshToken = localStorage.getItem(STORAGE_KEYS.refreshToken)
    const expiresAt = Number(localStorage.getItem(STORAGE_KEYS.expiresAt))
    const userRaw = localStorage.getItem(STORAGE_KEYS.user)

    if (!accessToken || !refreshToken) return

    this._accessToken = accessToken
    this._refreshToken = refreshToken
    this._expiresAt = expiresAt || null
    this._user = userRaw ? (JSON.parse(userRaw) as ReTiChUser) : null

    if (!expiresAt || Date.now() > expiresAt - 60_000) {
      this._refresh()
    } else {
      const remainingSeconds = (expiresAt - Date.now()) / 1000
      this._scheduleRefresh(remainingSeconds)
    }
  }

  private _clear(): void {
    if (this._refreshTimer) clearTimeout(this._refreshTimer)
    this._accessToken = null
    this._refreshToken = null
    this._expiresAt = null
    this._user = null
    this._refreshPromise = null

    Object.values(STORAGE_KEYS).forEach((key) => localStorage.removeItem(key))

    this._notify()
  }

  private _notify(): void {
    this._observers.forEach((cb) => cb(this._user))
  }
}
