package authservice

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/retich-corp/auth/internal/cache"
	"github.com/retich-corp/auth/internal/config"
	"github.com/retich-corp/auth/internal/models"
	"github.com/retich-corp/auth/internal/repository"
	emailservice "github.com/retich-corp/auth/internal/service/email"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
	"github.com/retich-corp/auth/pkg/apperrors"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	cfg         *config.Config
	userRepo    *repository.UserRepository
	tokenRepo   *repository.TokenRepository
	sessionRepo *repository.SessionRepository
	jwtSvc      *tokenservice.JWTService
	emailSvc    *emailservice.EmailService
	cache       *cache.Cache
}

func NewService(
	cfg *config.Config,
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	sessionRepo *repository.SessionRepository,
	jwtSvc *tokenservice.JWTService,
	emailSvc *emailservice.EmailService,
	c *cache.Cache,
) *Service {
	return &Service{
		cfg:         cfg,
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		sessionRepo: sessionRepo,
		jwtSvc:      jwtSvc,
		emailSvc:    emailSvc,
		cache:       c,
	}
}

// Register creates a new user and sends a verification email.
// redirectURL is the base URL used in the email link (e.g. "https://shop.com").
// If empty, FrontendURL from config is used.
func (s *Service) Register(ctx context.Context, email, password, redirectURL string) error {
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil {
		if existing.IsVerified {
			return apperrors.ErrEmailTaken
		}
		// Not verified yet: resend and treat as success
		if err := s.sendVerificationEmail(ctx, existing, redirectURL); err != nil {
			log.Printf("WARN: could not resend verification email to %s: %v", email, err)
		}
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	user, err := s.userRepo.Create(ctx, email, string(hash))
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}

	if err := s.sendVerificationEmail(ctx, user, redirectURL); err != nil {
		log.Printf("WARN: could not send verification email to %s: %v", user.Email, err)
	}

	return nil
}

type LoginResult struct {
	UserID       string `json:"user_id,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Login authenticates a user and returns tokens.
// audience identifies the calling app (e.g. "app-shop"). Pass "" for no restriction.
func (s *Service) Login(ctx context.Context, email, password, audience string, r *http.Request) (*LoginResult, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	// Check account lock
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, apperrors.ErrAccountLocked
	}

	// Check verification (skippable via REQUIRE_EMAIL_VERIFICATION=false)
	if !user.IsVerified && s.cfg.RequireEmailVerification {
		return nil, apperrors.ErrAccountNotVerified
	}

	// Check active
	if !user.IsActive {
		return nil, apperrors.ErrAccountInactive
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return s.handleFailedLogin(ctx, user)
	}

	// Reset failed attempts
	if err := s.userRepo.ResetFailedAttempts(ctx, user.ID); err != nil {
		return nil, err
	}

	return s.issueTokens(ctx, user, audience, r)
}

func (s *Service) handleFailedLogin(ctx context.Context, user *models.User) (*LoginResult, error) {
	nextAttempts := user.FailedLoginAttempts + 1
	var lockUntil *time.Time

	if nextAttempts >= s.cfg.AccountLockoutAttempts {
		t := time.Now().Add(s.cfg.AccountLockoutDuration)
		lockUntil = &t
	}

	_ = s.userRepo.IncrementFailedAttempts(ctx, user.ID, lockUntil)

	if lockUntil != nil {
		return nil, apperrors.ErrAccountLocked
	}
	return nil, apperrors.ErrInvalidCredentials
}

// VerifyEmail marks a user's email as verified using a token.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	hash := tokenservice.HashToken(rawToken)

	t, err := s.tokenRepo.FindVerificationToken(ctx, hash, models.TokenTypeEmailVerification)
	if err != nil {
		return apperrors.ErrTokenInvalid
	}

	if err := s.userRepo.SetVerified(ctx, t.UserID); err != nil {
		return err
	}

	return s.tokenRepo.MarkVerificationTokenUsed(ctx, t.ID)
}

// ResendVerification invalidates old tokens and sends a new verification email.
func (s *Service) ResendVerification(ctx context.Context, email, redirectURL string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil // anti-enumeration
	}
	if user.IsVerified {
		return nil
	}

	_ = s.tokenRepo.InvalidateVerificationTokensByType(ctx, user.ID, models.TokenTypeEmailVerification)

	return s.sendVerificationEmail(ctx, user, redirectURL)
}

type RefreshResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// RefreshToken rotates the refresh token and issues a new access token for the given audience.
func (s *Service) RefreshToken(ctx context.Context, rawRefreshToken, audience string, r *http.Request) (*RefreshResult, error) {
	hash := tokenservice.HashToken(rawRefreshToken)

	old, err := s.tokenRepo.FindRefreshToken(ctx, hash)
	if err != nil {
		return nil, apperrors.ErrTokenInvalid
	}

	user, err := s.userRepo.FindByID(ctx, old.UserID)
	if err != nil || !user.IsActive {
		return nil, apperrors.ErrUnauthorized
	}

	// Revoke old refresh token
	if err := s.tokenRepo.RevokeRefreshToken(ctx, old.ID); err != nil {
		return nil, err
	}

	result, err := s.issueTokens(ctx, user, audience, r)
	if err != nil {
		return nil, err
	}

	// Update session to point to new refresh token
	newHash := tokenservice.HashToken(result.RefreshToken)
	newToken, err := s.tokenRepo.FindRefreshToken(ctx, newHash)
	if err == nil {
		_ = s.sessionRepo.UpdateRefreshToken(ctx, old.ID, newToken.ID)
	}

	return &RefreshResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

// Logout revokes the refresh token and blacklists the JWT.
func (s *Service) Logout(ctx context.Context, rawRefreshToken, jwtJTI string, jwtTTL time.Duration) error {
	hash := tokenservice.HashToken(rawRefreshToken)

	rt, err := s.tokenRepo.FindRefreshToken(ctx, hash)
	if err == nil {
		_ = s.tokenRepo.RevokeRefreshToken(ctx, rt.ID)
		_ = s.sessionRepo.DeleteByRefreshTokenID(ctx, rt.ID)
	}

	// Blacklist JWT even if refresh token not found
	s.cache.Set("jwt_blacklist:"+jwtJTI, "1", jwtTTL)
	return nil
}

// LogoutAll revokes all sessions and tokens for the user, and blacklists current JWT.
func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID, jwtJTI string, jwtTTL time.Duration) error {
	_ = s.tokenRepo.RevokeAllRefreshTokensForUser(ctx, userID)
	_ = s.sessionRepo.DeleteAllForUser(ctx, userID)
	s.cache.Set("jwt_blacklist:"+jwtJTI, "1", jwtTTL)
	return nil
}

// ForgotPassword sends a password reset email.
// redirectURL is the base URL used in the email link. If empty, FrontendURL from config is used.
func (s *Service) ForgotPassword(ctx context.Context, email, redirectURL string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil // anti-enumeration
	}

	_ = s.tokenRepo.InvalidateVerificationTokensByType(ctx, user.ID, models.TokenTypePasswordReset)

	rawToken, hash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.PasswordResetExpiry)

	_, err = s.tokenRepo.CreateVerificationToken(ctx, user.ID, hash, models.TokenTypePasswordReset, expiresAt)
	if err != nil {
		return fmt.Errorf("creating reset token: %w", err)
	}

	base := s.resolveRedirectURL(redirectURL)
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", base, rawToken)
	return s.emailSvc.SendPasswordResetEmail(user.Email, resetURL)
}

// ValidateResetToken checks if a password reset token is valid without consuming it.
func (s *Service) ValidateResetToken(ctx context.Context, rawToken string) error {
	hash := tokenservice.HashToken(rawToken)
	_, err := s.tokenRepo.FindVerificationToken(ctx, hash, models.TokenTypePasswordReset)
	if err != nil {
		return apperrors.ErrTokenInvalid
	}
	return nil
}

// ResetPassword validates the reset token and updates the password.
func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	hash := tokenservice.HashToken(rawToken)

	t, err := s.tokenRepo.FindVerificationToken(ctx, hash, models.TokenTypePasswordReset)
	if err != nil {
		return apperrors.ErrTokenInvalid
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.cfg.BcryptCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, t.UserID, string(newHash)); err != nil {
		return err
	}

	if err := s.tokenRepo.MarkVerificationTokenUsed(ctx, t.ID); err != nil {
		return err
	}

	// Revoke all sessions (force re-login everywhere)
	_ = s.tokenRepo.RevokeAllRefreshTokensForUser(ctx, t.UserID)
	_ = s.sessionRepo.DeleteAllForUser(ctx, t.UserID)

	// Send confirmation email
	user, err := s.userRepo.FindByID(ctx, t.UserID)
	if err == nil {
		_ = s.emailSvc.SendPasswordChangedEmail(user.Email)
	}

	return nil
}

// --- helpers ---

func (s *Service) issueTokens(ctx context.Context, user *models.User, audience string, r *http.Request) (*LoginResult, error) {
	accessToken, _, err := s.jwtSvc.GenerateAccessToken(user.ID, user.Email, audience, "")
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	rawRefresh, refreshHash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiration)

	deviceInfo := r.UserAgent()
	ipAddress := extractIP(r)

	rt, err := s.tokenRepo.CreateRefreshToken(ctx, user.ID, refreshHash, deviceInfo, ipAddress, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("creating refresh token: %w", err)
	}

	_, err = s.sessionRepo.Create(ctx, user.ID, rt.ID, deviceInfo, ipAddress, r.UserAgent(), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	return &LoginResult{
		UserID:       user.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int(s.cfg.JWTExpiration.Seconds()),
	}, nil
}

func (s *Service) sendVerificationEmail(ctx context.Context, user *models.User, redirectURL string) error {
	_ = s.tokenRepo.InvalidateVerificationTokensByType(ctx, user.ID, models.TokenTypeEmailVerification)

	rawToken, hash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.EmailVerificationExpiry)

	_, err := s.tokenRepo.CreateVerificationToken(ctx, user.ID, hash, models.TokenTypeEmailVerification, expiresAt)
	if err != nil {
		return err
	}

	// Link always points to the API; the API then redirects to the frontend.
	// Only add redirect param when there's a real frontend (different from the API itself).
	frontendBase := s.resolveRedirectURL(redirectURL)
	verifyURL := fmt.Sprintf("%s/api/v1/auth/verify-email?token=%s", s.cfg.AppURL, rawToken)
	if !strings.HasPrefix(frontendBase, s.cfg.AppURL+"/api") {
		verifyURL += "&redirect=" + url.QueryEscape(frontendBase)
	}
	return s.emailSvc.SendVerificationEmail(user.Email, verifyURL)
}

// RequestMagicLink sends a one-time login link to the user's email.
// Always returns nil to prevent email enumeration.
func (s *Service) RequestMagicLink(ctx context.Context, email, redirectURL string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil || !user.IsActive {
		return nil // anti-enumeration
	}

	// Invalidate any previous magic link tokens for this user
	_ = s.tokenRepo.InvalidateVerificationTokensByType(ctx, user.ID, models.TokenTypeMagicLink)

	rawToken, hash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.MagicLinkExpiry)

	_, err = s.tokenRepo.CreateVerificationToken(ctx, user.ID, hash, models.TokenTypeMagicLink, expiresAt)
	if err != nil {
		return fmt.Errorf("creating magic link token: %w", err)
	}

	magicURL := fmt.Sprintf("%s/api/v1/auth/magic-link/verify?token=%s", s.cfg.AppURL, rawToken)
	frontendBase := s.resolveRedirectURL(redirectURL)
	if !strings.HasPrefix(frontendBase, s.cfg.AppURL+"/api") {
		magicURL += "&redirect=" + url.QueryEscape(frontendBase)
	}
	return s.emailSvc.SendMagicLinkEmail(user.Email, magicURL)
}

// VerifyMagicLink validates a magic link token and issues JWT + refresh token.
// Auto-verifies the user's email if not already verified.
func (s *Service) VerifyMagicLink(ctx context.Context, rawToken, audience string, r *http.Request) (*LoginResult, error) {
	hash := tokenservice.HashToken(rawToken)

	t, err := s.tokenRepo.FindVerificationToken(ctx, hash, models.TokenTypeMagicLink)
	if err != nil {
		return nil, apperrors.ErrTokenInvalid
	}

	user, err := s.userRepo.FindByID(ctx, t.UserID)
	if err != nil {
		return nil, apperrors.ErrNotFound
	}

	if !user.IsActive {
		return nil, apperrors.ErrAccountInactive
	}

	// Consume the token
	if err := s.tokenRepo.MarkVerificationTokenUsed(ctx, t.ID); err != nil {
		return nil, err
	}

	// Auto-verify email if needed
	if !user.IsVerified {
		if err := s.userRepo.SetVerified(ctx, user.ID); err != nil {
			return nil, err
		}
		user.IsVerified = true
	}

	return s.issueTokens(ctx, user, audience, r)
}

// ResolveRedirectURL is the public version of resolveRedirectURL, used by handlers.
func (s *Service) ResolveRedirectURL(redirectURL string) string {
	return s.resolveRedirectURL(redirectURL)
}

// resolveRedirectURL returns redirectURL only if it's in the allowlist, otherwise FrontendURL.
func (s *Service) resolveRedirectURL(redirectURL string) string {
	if redirectURL == "" {
		return s.cfg.FrontendURL
	}
	if _, ok := s.cfg.AllowedRedirectURLs[redirectURL]; ok {
		return redirectURL
	}
	log.Printf("WARN: redirect_url %q not in allowlist, using default", redirectURL)
	return s.cfg.FrontendURL
}

func extractIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// Take first IP in proxy chain, strip port if present
		parts := strings.SplitN(ip, ",", 2)
		return stripPort(strings.TrimSpace(parts[0]))
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return stripPort(ip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func stripPort(ip string) string {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}
