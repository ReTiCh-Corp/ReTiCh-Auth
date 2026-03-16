package router

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/retich-corp/auth/internal/handlers"
	"github.com/retich-corp/auth/internal/middleware"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
)

type Deps struct {
	AuthHandler    *handlers.AuthHandler
	ProfileHandler *handlers.ProfileHandler
	OAuthHandler   *handlers.OAuthHandler
	AdminHandler   *handlers.AdminHandler
	JWTService     *tokenservice.JWTService
	Redis          *redis.Client
	OriginChecker  middleware.OriginChecker
}

func New(d Deps) http.Handler {
	r := mux.NewRouter()

	// Global middleware
	r.Use(middleware.Logger)
	r.Use(middleware.CORS(d.OriginChecker))

	// Health endpoints (no auth, no rate limit)
	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/ready", readyHandler).Methods(http.MethodGet)

	// Well-known endpoints
	r.HandleFunc("/.well-known/jwks.json", d.AuthHandler.JWKS).Methods(http.MethodGet)
	r.HandleFunc("/.well-known/openid-configuration", d.OAuthHandler.Discovery).Methods(http.MethodGet)

	// --- OAuth 2.0 / OIDC routes ---
	oauth := r.PathPrefix("/oauth").Subrouter()

	// Authorization endpoint (browser flow)
	oauth.HandleFunc("/authorize", d.OAuthHandler.Authorize).Methods(http.MethodGet)
	oauth.HandleFunc("/authorize", d.OAuthHandler.HandleConsent).Methods(http.MethodPost)

	// Login form for OAuth flow
	oauth.Handle("/login",
		middleware.RateLimit(d.Redis, "oauth-login", 10, time.Minute)(
			http.HandlerFunc(d.OAuthHandler.LoginForm),
		),
	).Methods(http.MethodGet)
	oauth.Handle("/login",
		middleware.RateLimit(d.Redis, "oauth-login", 10, time.Minute)(
			http.HandlerFunc(d.OAuthHandler.LoginSubmit),
		),
	).Methods(http.MethodPost)

	// Token endpoint (machine-to-machine)
	oauth.HandleFunc("/token", d.OAuthHandler.Token).Methods(http.MethodPost)

	// Registration during OAuth flow
	oauth.HandleFunc("/register", d.OAuthHandler.RegisterForm).Methods(http.MethodGet)
	oauth.HandleFunc("/register", d.OAuthHandler.RegisterSubmit).Methods(http.MethodPost)

	// Forgot password during OAuth flow
	oauth.Handle("/forgot-password",
		middleware.RateLimit(d.Redis, "forgot-password", 3, time.Minute)(
			http.HandlerFunc(d.OAuthHandler.ForgotPasswordForm),
		),
	).Methods(http.MethodGet)
	oauth.Handle("/forgot-password",
		middleware.RateLimit(d.Redis, "forgot-password", 3, time.Minute)(
			http.HandlerFunc(d.OAuthHandler.ForgotPasswordSubmit),
		),
	).Methods(http.MethodPost)

	// Interactive test playground (dev)
	oauth.HandleFunc("/playground", d.OAuthHandler.Playground).Methods(http.MethodGet)

	// UserInfo endpoint (protected by JWT)
	jwtMiddleware := middleware.JWTAuth(d.JWTService, d.Redis, "")
	oauthProtected := r.PathPrefix("/oauth").Subrouter()
	oauthProtected.Use(jwtMiddleware)
	oauthProtected.HandleFunc("/userinfo", d.OAuthHandler.UserInfo).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()

	// --- Admin routes ---
	admin := api.PathPrefix("/admin").Subrouter()
	admin.HandleFunc("/clients", d.AdminHandler.RegisterClient).Methods(http.MethodPost)
	admin.HandleFunc("/clients", d.AdminHandler.ListClients).Methods(http.MethodGet)
	admin.HandleFunc("/clients/{id}", d.AdminHandler.GetClient).Methods(http.MethodGet)
	admin.HandleFunc("/clients/{id}", d.AdminHandler.UpdateClient).Methods(http.MethodPatch)
	admin.HandleFunc("/clients/{id}", d.AdminHandler.DeleteClient).Methods(http.MethodDelete)
	admin.HandleFunc("/clients/{id}/activate", d.AdminHandler.ActivateClient).Methods(http.MethodPost)

	// --- Auth callback routes (used in email links) ---
	auth := api.PathPrefix("/auth").Subrouter()

	auth.HandleFunc("/verify-email", d.AuthHandler.VerifyEmail).Methods(http.MethodGet)
	auth.HandleFunc("/reset-password", d.AuthHandler.ResetPasswordForm).Methods(http.MethodGet)
	auth.HandleFunc("/reset-password", d.AuthHandler.ResetPassword).Methods(http.MethodPost)

	// --- Protected auth routes (JWT required) ---
	protected := api.PathPrefix("/auth").Subrouter()
	protected.Use(jwtMiddleware)

	protected.HandleFunc("/logout", d.AuthHandler.Logout).Methods(http.MethodPost)
	protected.HandleFunc("/logout-all", d.AuthHandler.LogoutAll).Methods(http.MethodPost)
	protected.HandleFunc("/me", d.ProfileHandler.Me).Methods(http.MethodGet)

	return r
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}
