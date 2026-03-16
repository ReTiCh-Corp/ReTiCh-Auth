package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port        string
	Environment string

	DatabaseURL string
	RedisURL    string

	// RSAPrivateKeyPEM is the PEM-encoded RSA private key (PKCS#1 or PKCS#8) used
	// to sign JWTs with RS256. Set via RSA_PRIVATE_KEY env var.
	// If empty in non-production, an ephemeral key is generated (dev convenience).
	RSAPrivateKeyPEM       string
	JWTExpiration          time.Duration
	RefreshTokenExpiration time.Duration

	ResendAPIKey    string
	ResendFromEmail string
	ResendFromName  string

	// AppURL is the base URL of this service (used internally)
	AppURL string
	// FrontendURL is the default base URL used in email links.
	// Defaults to AppURL/api/v1/auth so links work without a separate frontend.
	FrontendURL string
	// AllowedRedirectURLs is the set of authorized base URLs that can be passed
	// as redirect_url in register/forgot-password requests (security allowlist).
	AllowedRedirectURLs map[string]struct{}
	AllowedOrigins      string

	BcryptCost              int
	AccountLockoutAttempts  int
	AccountLockoutDuration  time.Duration
	EmailVerificationExpiry time.Duration
	PasswordResetExpiry     time.Duration
	MagicLinkExpiry         time.Duration
	// RequireEmailVerification: if false, users can log in (password) without verifying their email.
	RequireEmailVerification bool

	// OAuth 2.0 / OIDC
	AdminAPIKey   string
	SessionSecret string
	SessionExpiry time.Duration
}

func Load() (*Config, error) {
	if os.Getenv("ENVIRONMENT") != "production" {
		_ = godotenv.Load()
	}

	appURL := getEnv("APP_URL", "http://localhost:8081")

	cfg := &Config{
		Port:            getEnv("PORT", "8081"),
		Environment:     getEnv("ENVIRONMENT", "development"),
		DatabaseURL:      mustGetEnv("DATABASE_URL"),
		RedisURL:         getEnv("REDIS_URL", "redis://localhost:6379"),
		RSAPrivateKeyPEM: os.Getenv("RSA_PRIVATE_KEY"),
		ResendAPIKey:     mustGetEnv("RESEND_API_KEY"),
		ResendFromEmail: getEnv("RESEND_FROM_EMAIL", "noreply@example.com"),
		ResendFromName:  getEnv("RESEND_FROM_NAME", "ReTiCh Auth"),
		AppURL:          appURL,
		// FRONTEND_URL defaults to the API path so email links work in dev without a frontend
		FrontendURL:    getEnv("FRONTEND_URL", appURL+"/api/v1/auth"),
		AllowedOrigins: getEnv("ALLOWED_ORIGINS", "http://localhost:3000"),
	}

	// Build allowlist from comma-separated ALLOWED_REDIRECT_URLS.
	// FrontendURL is always implicitly allowed.
	allowedSet := map[string]struct{}{
		cfg.FrontendURL: {},
	}
	if raw := os.Getenv("ALLOWED_REDIRECT_URLS"); raw != "" {
		for _, u := range strings.Split(raw, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				allowedSet[u] = struct{}{}
			}
		}
	}
	cfg.AllowedRedirectURLs = allowedSet

	var err error

	cfg.JWTExpiration, err = time.ParseDuration(getEnv("JWT_EXPIRATION", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_EXPIRATION: %w", err)
	}

	cfg.RefreshTokenExpiration, err = time.ParseDuration(getEnv("REFRESH_TOKEN_EXPIRATION", "168h"))
	if err != nil {
		return nil, fmt.Errorf("invalid REFRESH_TOKEN_EXPIRATION: %w", err)
	}

	cfg.AccountLockoutDuration, err = time.ParseDuration(getEnv("ACCOUNT_LOCKOUT_DURATION", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid ACCOUNT_LOCKOUT_DURATION: %w", err)
	}

	cfg.EmailVerificationExpiry, err = time.ParseDuration(getEnv("EMAIL_VERIFICATION_EXPIRY", "24h"))
	if err != nil {
		return nil, fmt.Errorf("invalid EMAIL_VERIFICATION_EXPIRY: %w", err)
	}

	cfg.PasswordResetExpiry, err = time.ParseDuration(getEnv("PASSWORD_RESET_EXPIRY", "1h"))
	if err != nil {
		return nil, fmt.Errorf("invalid PASSWORD_RESET_EXPIRY: %w", err)
	}

	cfg.MagicLinkExpiry, err = time.ParseDuration(getEnv("MAGIC_LINK_EXPIRY", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid MAGIC_LINK_EXPIRY: %w", err)
	}

	cfg.RequireEmailVerification = getEnvBool("REQUIRE_EMAIL_VERIFICATION", true)

	cfg.BcryptCost, err = strconv.Atoi(getEnv("BCRYPT_COST", "12"))
	if err != nil {
		return nil, fmt.Errorf("invalid BCRYPT_COST: %w", err)
	}

	cfg.AccountLockoutAttempts, err = strconv.Atoi(getEnv("ACCOUNT_LOCKOUT_ATTEMPTS", "5"))
	if err != nil {
		return nil, fmt.Errorf("invalid ACCOUNT_LOCKOUT_ATTEMPTS: %w", err)
	}

	cfg.AdminAPIKey = os.Getenv("ADMIN_API_KEY")
	cfg.SessionSecret = getEnv("SESSION_SECRET", "change-me-in-production-min-32-bytes")

	cfg.SessionExpiry, err = time.ParseDuration(getEnv("SESSION_EXPIRY", "24h"))
	if err != nil {
		return nil, fmt.Errorf("invalid SESSION_EXPIRY: %w", err)
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1" || v == "yes"
}

func mustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required environment variable %q is not set", key))
	}
	return v
}
