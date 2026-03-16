interface ReTiChAuthConfig {
    /** URL du service ReTiCh Auth (ex: "https://auth.mondomaine.com") */
    baseUrl: string;
    /** client_id obtenu via la console admin */
    clientId: string;
    /** client_secret obtenu via la console admin */
    clientSecret: string;
    /** URL de callback après login (ex: "https://monapp.com/callback") */
    redirectUri: string;
}
interface ReTiChUser {
    id: string;
    email: string;
    user_id: string;
    email_verified?: boolean;
    exp?: number;
    iat?: number;
    iss?: string;
    aud?: string;
    [key: string]: unknown;
}
type AuthStateCallback = (user: ReTiChUser | null) => void;
type Unsubscribe = () => void;
declare class ReTiChAuth {
    private readonly _baseUrl;
    private readonly _clientId;
    private readonly _clientSecret;
    private readonly _redirectUri;
    private _user;
    private _accessToken;
    private _refreshToken;
    private _expiresAt;
    private _refreshTimer;
    private _refreshPromise;
    private _observers;
    constructor(config: ReTiChAuthConfig);
    get currentUser(): ReTiChUser | null;
    onAuthStateChanged(callback: AuthStateCallback): Unsubscribe;
    signIn(): Promise<void>;
    handleRedirectResult(): Promise<ReTiChUser | null>;
    signOut(): Promise<void>;
    getAccessToken(): Promise<string | null>;
    private _refresh;
    private _setTokens;
    private _scheduleRefresh;
    private _persist;
    private _restore;
    private _clear;
    private _notify;
}

export { type AuthStateCallback, ReTiChAuth, type ReTiChAuthConfig, type ReTiChUser, type Unsubscribe };
