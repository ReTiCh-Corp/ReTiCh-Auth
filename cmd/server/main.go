package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/retich-corp/auth/internal/cache"
	"github.com/retich-corp/auth/internal/config"
	"github.com/retich-corp/auth/internal/database"
	"github.com/retich-corp/auth/internal/handlers"
	"github.com/retich-corp/auth/internal/middleware"
	"github.com/retich-corp/auth/internal/repository"
	"github.com/retich-corp/auth/internal/router"
	authservice "github.com/retich-corp/auth/internal/service/auth"
	emailservice "github.com/retich-corp/auth/internal/service/email"
	oauthservice "github.com/retich-corp/auth/internal/service/oauth"
	sessionsvc "github.com/retich-corp/auth/internal/service/session"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	// Run DB migrations
	if err := database.RunMigrations(cfg.DatabaseURL); err != nil {
		log.Fatalf("migration error: %v", err)
	}

	// Connect to PostgreSQL
	ctx := context.Background()
	pool, err := database.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database error: %v", err)
	}
	defer pool.Close()

	// In-memory cache (replaces Redis)
	appCache := cache.New()

	// Repositories
	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	sessionRepo := repository.NewSessionRepository(pool)
	oauthRepo := repository.NewOAuthRepository(pool)

	// Services
	jwtSvc, err := tokenservice.NewJWTService(cfg.RSAPrivateKeyPEM, cfg.JWTExpiration, cfg.AppURL)
	if err != nil {
		log.Fatalf("jwt service error: %v", err)
	}

	emailSvc, err := emailservice.NewEmailService(cfg.ResendAPIKey, cfg.ResendFromEmail, cfg.ResendFromName)
	if err != nil {
		log.Fatalf("email service error: %v", err)
	}

	authSvc := authservice.NewService(cfg, userRepo, tokenRepo, sessionRepo, jwtSvc, emailSvc, appCache)

	sessionService := sessionsvc.NewService(cfg.SessionSecret, cfg.SessionExpiry, cfg.Environment == "production")

	oauthSvc := oauthservice.NewService(cfg, oauthRepo, userRepo, tokenRepo, jwtSvc, sessionService, appCache)

	// Handlers
	authHandler := handlers.NewAuthHandler(authSvc, jwtSvc)
	profileHandler := handlers.NewProfileHandler(userRepo)
	oauthHandler := handlers.NewOAuthHandler(oauthSvc, authSvc, userRepo, sessionService, cfg.AppURL)
	adminHandler := handlers.NewAdminHandler(oauthSvc, cfg.AdminAPIKey)

	// CORS: static origins from config + dynamic origins from registered OAuth clients
	originChecker := middleware.DynamicOriginChecker(
		cfg.AllowedOrigins,
		func() ([]string, error) { return oauthRepo.GetAllowedOrigins(ctx) },
		30*time.Second,
	)

	// Router
	h := router.New(router.Deps{
		AuthHandler:    authHandler,
		ProfileHandler: profileHandler,
		OAuthHandler:   oauthHandler,
		AdminHandler:   adminHandler,
		JWTService:     jwtSvc,
		Cache:          appCache,
		OriginChecker:  originChecker,
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Auth Service starting on port %s (env: %s)", cfg.Port, cfg.Environment)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully")
}
