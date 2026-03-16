package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/retich-corp/auth/internal/config"
	"github.com/retich-corp/auth/internal/database"
	"github.com/retich-corp/auth/internal/handlers"
	redisclient "github.com/retich-corp/auth/internal/redis"
	"github.com/retich-corp/auth/internal/repository"
	"github.com/retich-corp/auth/internal/router"
	authservice "github.com/retich-corp/auth/internal/service/auth"
	emailservice "github.com/retich-corp/auth/internal/service/email"
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

	// Connect to Redis
	rdb, err := redisclient.NewClient(cfg.RedisURL)
	if err != nil {
		log.Fatalf("redis error: %v", err)
	}
	defer rdb.Close()

	// Repositories
	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)
	sessionRepo := repository.NewSessionRepository(pool)

	// Services
	jwtSvc := tokenservice.NewJWTService(cfg.JWTSecret, cfg.JWTExpiration)

	emailSvc, err := emailservice.NewEmailService(cfg.ResendAPIKey, cfg.ResendFromEmail, cfg.ResendFromName)
	if err != nil {
		log.Fatalf("email service error: %v", err)
	}

	authSvc := authservice.NewService(cfg, userRepo, tokenRepo, sessionRepo, jwtSvc, emailSvc, rdb)

	// Handlers
	authHandler := handlers.NewAuthHandler(authSvc, jwtSvc)
	profileHandler := handlers.NewProfileHandler(userRepo)

	// Router
	h := router.New(router.Deps{
		AuthHandler:    authHandler,
		ProfileHandler: profileHandler,
		JWTService:     jwtSvc,
		Redis:          rdb,
		AllowedOrigins: cfg.AllowedOrigins,
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
