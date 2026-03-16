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
	JWTService     *tokenservice.JWTService
	Redis          *redis.Client
	AllowedOrigins string
}

func New(d Deps) http.Handler {
	r := mux.NewRouter()

	// Global middleware
	r.Use(middleware.Logger)
	r.Use(middleware.CORS(d.AllowedOrigins))

	// Health endpoints (no auth, no rate limit)
	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/ready", readyHandler).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()

	// --- Public auth routes ---
	auth := api.PathPrefix("/auth").Subrouter()

	auth.Handle("/register",
		middleware.RateLimit(d.Redis, "register", 5, time.Minute)(
			http.HandlerFunc(d.AuthHandler.Register),
		),
	).Methods(http.MethodPost)

	auth.Handle("/login",
		middleware.RateLimit(d.Redis, "login", 10, time.Minute)(
			http.HandlerFunc(d.AuthHandler.Login),
		),
	).Methods(http.MethodPost)

	auth.HandleFunc("/refresh", d.AuthHandler.Refresh).Methods(http.MethodPost)
	auth.HandleFunc("/verify-email", d.AuthHandler.VerifyEmail).Methods(http.MethodGet)

	auth.Handle("/resend-verification",
		middleware.RateLimit(d.Redis, "resend-verification", 3, time.Minute)(
			http.HandlerFunc(d.AuthHandler.ResendVerification),
		),
	).Methods(http.MethodPost)

	auth.Handle("/forgot-password",
		middleware.RateLimit(d.Redis, "forgot-password", 3, time.Minute)(
			http.HandlerFunc(d.AuthHandler.ForgotPassword),
		),
	).Methods(http.MethodPost)

	auth.HandleFunc("/reset-password", d.AuthHandler.ResetPasswordForm).Methods(http.MethodGet)
	auth.HandleFunc("/reset-password", d.AuthHandler.ResetPassword).Methods(http.MethodPost)

	auth.Handle("/magic-link",
		middleware.RateLimit(d.Redis, "magic-link", 3, time.Minute)(
			http.HandlerFunc(d.AuthHandler.RequestMagicLink),
		),
	).Methods(http.MethodPost)
	auth.HandleFunc("/magic-link/verify", d.AuthHandler.VerifyMagicLink).Methods(http.MethodGet)

	// --- Protected auth routes (JWT required) ---
	jwtMiddleware := middleware.JWTAuth(d.JWTService, d.Redis)

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
