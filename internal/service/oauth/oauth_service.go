package oauthservice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/retich-corp/auth/internal/cache"
	"github.com/retich-corp/auth/internal/config"
	"github.com/retich-corp/auth/internal/models"
	"github.com/retich-corp/auth/internal/repository"
	sessionsvc "github.com/retich-corp/auth/internal/service/session"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
	"github.com/retich-corp/auth/pkg/apperrors"
	"golang.org/x/crypto/bcrypt"
)

// AuthRequest holds the validated parameters from GET /oauth/authorize.
type AuthRequest struct {
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// ConsentData is passed to the consent page template.
type ConsentData struct {
	Client      *models.OAuthClient
	Scopes      []string
	CSRFToken   string
	PendingKey  string
}

// TokenResponse is returned by POST /oauth/token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// TokenRequest holds the parameters from POST /oauth/token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
}

const (
	pendingAuthTTL = 10 * time.Minute
	codeTTL        = 10 * time.Minute
)

type Service struct {
	cfg         *config.Config
	oauthRepo   *repository.OAuthRepository
	userRepo    *repository.UserRepository
	tokenRepo   *repository.TokenRepository
	jwtSvc      *tokenservice.JWTService
	sessionSvc  *sessionsvc.Service
	cache       *cache.Cache
}

func NewService(
	cfg *config.Config,
	oauthRepo *repository.OAuthRepository,
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	jwtSvc *tokenservice.JWTService,
	sessionSvc *sessionsvc.Service,
	c *cache.Cache,
) *Service {
	return &Service{
		cfg:        cfg,
		oauthRepo:  oauthRepo,
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		jwtSvc:     jwtSvc,
		sessionSvc: sessionSvc,
		cache:      c,
	}
}

func (s *Service) ListClients(ctx context.Context) ([]*models.OAuthClient, error) {
	return s.oauthRepo.ListClients(ctx)
}

// ListClientUsers returns the users for a client. id can be the internal UUID or the OAuth client_id.
func (s *Service) ListClientUsers(ctx context.Context, id string) ([]*repository.ClientUser, error) {
	var clientID string

	// Try internal UUID first, then fall back to OAuth client_id
	uid, err := uuid.Parse(id)
	if err == nil {
		client, err := s.oauthRepo.GetClientByUUID(ctx, uid)
		if err == nil {
			clientID = client.ClientID
		} else {
			// UUID is valid but not an internal id — try as OAuth client_id
			client, err := s.oauthRepo.GetClientByClientID(ctx, id)
			if err != nil {
				return nil, apperrors.ErrNotFound
			}
			clientID = client.ClientID
		}
	} else {
		client, err := s.oauthRepo.GetClientByClientID(ctx, id)
		if err != nil {
			return nil, apperrors.ErrNotFound
		}
		clientID = client.ClientID
	}

	return s.oauthRepo.ListUsersByClientID(ctx, clientID)
}

func (s *Service) GetClient(ctx context.Context, id string) (*models.OAuthClient, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id")
	}
	return s.oauthRepo.GetClientByUUID(ctx, uid)
}

func (s *Service) UpdateClient(ctx context.Context, id, name, logoURL string, redirectURIs, scopes []string, isActive bool) (*models.OAuthClient, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid id")
	}
	if err := s.oauthRepo.UpdateClient(ctx, uid, name, logoURL, redirectURIs, scopes, isActive); err != nil {
		return nil, err
	}
	return s.oauthRepo.GetClientByUUID(ctx, uid)
}

func (s *Service) ActivateClient(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid id")
	}
	return s.oauthRepo.ActivateClient(ctx, uid)
}

func (s *Service) DeactivateClient(ctx context.Context, id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid id")
	}
	return s.oauthRepo.DeactivateClient(ctx, uid)
}

// ValidateAuthRequest checks that the client exists, redirect_uri is allowed,
// and the required OAuth params are present.
func (s *Service) ValidateAuthRequest(ctx context.Context, req AuthRequest) (*models.OAuthClient, error) {
	if req.ClientID == "" || req.RedirectURI == "" {
		return nil, fmt.Errorf("missing client_id or redirect_uri")
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return nil, fmt.Errorf("PKCE S256 is required")
	}

	client, err := s.oauthRepo.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, fmt.Errorf("unknown client_id")
		}
		return nil, err
	}
	if !client.IsActive {
		return nil, fmt.Errorf("client is disabled")
	}

	if !containsURI(client.RedirectURIs, req.RedirectURI) {
		return nil, fmt.Errorf("redirect_uri not allowed")
	}

	return client, nil
}

// StorePendingAuth saves the authorization request in cache and returns a short key.
// The key is included in the login redirect so the flow can resume after login.
func (s *Service) StorePendingAuth(ctx context.Context, req AuthRequest) (string, error) {
	key := uuid.New().String()
	val := encodePendingAuth(req)
	s.cache.Set(pendingKey(key), val, pendingAuthTTL)
	return key, nil
}

// LoadPendingAuth retrieves a pending authorization request by key.
func (s *Service) LoadPendingAuth(ctx context.Context, pendingKey string) (*AuthRequest, error) {
	val, ok := s.cache.Get(pendingKeyPrefix + pendingKey)
	if !ok {
		return nil, fmt.Errorf("pending auth not found or expired")
	}
	req, err := decodePendingAuth(val)
	if err != nil {
		return nil, fmt.Errorf("decoding pending auth: %w", err)
	}
	return req, nil
}

// GetConsentData returns the client info and CSRF token needed to render the consent page.
func (s *Service) GetConsentData(ctx context.Context, pendingAuthKey string) (*ConsentData, error) {
	req, err := s.LoadPendingAuth(ctx, pendingAuthKey)
	if err != nil {
		return nil, err
	}

	client, err := s.oauthRepo.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}

	csrfToken := uuid.New().String()
	s.cache.Set(csrfKey(pendingAuthKey), csrfToken, pendingAuthTTL)

	return &ConsentData{
		Client:     client,
		Scopes:     req.Scopes,
		CSRFToken:  csrfToken,
		PendingKey: pendingAuthKey,
	}, nil
}

// HasExistingConsent returns true if the user has previously approved all requested scopes for this client.
func (s *Service) HasExistingConsent(ctx context.Context, userID uuid.UUID, clientID string, requestedScopes []string) bool {
	consent, err := s.oauthRepo.GetConsent(ctx, userID, clientID)
	if err != nil {
		return false
	}
	for _, scope := range requestedScopes {
		if !contains(consent.Scopes, scope) {
			return false
		}
	}
	return true
}

// Approve processes user consent and returns an authorization code + redirect URI.
// csrfToken is empty when called from the auto-approve path (no browser form involved).
func (s *Service) Approve(ctx context.Context, userID uuid.UUID, pendingAuthKey, csrfToken string, scopes []string) (string, string, error) {
	// Verify CSRF token — skip when auto-approving (csrfToken == "")
	if csrfToken != "" {
		storedCSRF, ok := s.cache.Get(csrfKey(pendingAuthKey))
		if !ok || storedCSRF != csrfToken {
			return "", "", fmt.Errorf("invalid CSRF token")
		}
		s.cache.Del(csrfKey(pendingAuthKey))
	} else {
		// Clean up any stale CSRF key just in case
		s.cache.Del(csrfKey(pendingAuthKey))
	}

	req, err := s.LoadPendingAuth(ctx, pendingAuthKey)
	if err != nil {
		return "", "", err
	}

	// Persist consent
	if err := s.oauthRepo.UpsertConsent(ctx, userID, req.ClientID, scopes); err != nil {
		return "", "", fmt.Errorf("saving consent: %w", err)
	}

	// Generate authorization code
	rawCode, codeHash := tokenservice.GenerateOpaqueToken()
	code := &models.AuthorizationCode{
		CodeHash:      codeHash,
		ClientID:      req.ClientID,
		UserID:        userID,
		RedirectURI:   req.RedirectURI,
		Scopes:        scopes,
		CodeChallenge: req.CodeChallenge,
		Nonce:         req.Nonce,
		ExpiresAt:     time.Now().Add(codeTTL),
	}
	if err := s.oauthRepo.SaveAuthorizationCode(ctx, code); err != nil {
		return "", "", fmt.Errorf("saving authorization code: %w", err)
	}

	// Clean up pending auth
	s.cache.Del(pendingKeyPrefix + pendingAuthKey)

	redirectURI := req.RedirectURI + "?code=" + rawCode + "&state=" + req.State
	return rawCode, redirectURI, nil
}

// Deny clears the pending auth and returns the error redirect URI.
func (s *Service) Deny(ctx context.Context, pendingAuthKey string) (string, error) {
	req, err := s.LoadPendingAuth(ctx, pendingAuthKey)
	if err != nil {
		return "", err
	}
	s.cache.Del(pendingKeyPrefix + pendingAuthKey)
	s.cache.Del(csrfKey(pendingAuthKey))
	return req.RedirectURI + "?error=access_denied&state=" + req.State, nil
}

// ExchangeCode validates the authorization code + PKCE and issues tokens.
func (s *Service) ExchangeCode(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	client, err := s.oauthRepo.GetClientByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client")
	}
	if !client.IsActive {
		return nil, fmt.Errorf("client is disabled")
	}
	if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)) != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	codeHash := tokenservice.HashToken(req.Code)
	code, err := s.oauthRepo.GetAndConsumeAuthorizationCode(ctx, codeHash)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired code")
	}

	if code.ClientID != req.ClientID {
		return nil, fmt.Errorf("code was not issued to this client")
	}
	if code.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	// Verify PKCE
	if !verifyPKCE(req.CodeVerifier, code.CodeChallenge) {
		return nil, fmt.Errorf("PKCE verification failed")
	}

	user, err := s.userRepo.FindByID(ctx, code.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	scopeStr := strings.Join(code.Scopes, " ")
	accessToken, _, err := s.jwtSvc.GenerateAccessToken(user.ID, user.Email, req.ClientID, scopeStr)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	rawRefresh, refreshHash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiration)
	if err := s.oauthRepo.SaveOAuthRefreshToken(ctx, user.ID, refreshHash, expiresAt, req.ClientID); err != nil {
		return nil, fmt.Errorf("saving refresh token: %w", err)
	}

	resp := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.JWTExpiration.Seconds()),
		RefreshToken: rawRefresh,
		Scope:        scopeStr,
	}

	// Include ID token if openid scope was requested
	if contains(code.Scopes, "openid") {
		idToken, err := s.jwtSvc.GenerateIDToken(user.ID, user.Email, user.IsVerified, req.ClientID, code.Nonce)
		if err != nil {
			return nil, fmt.Errorf("generating id_token: %w", err)
		}
		resp.IDToken = idToken
	}

	return resp, nil
}

// RefreshOAuthToken rotates an OAuth refresh token and issues a new access token.
func (s *Service) RefreshOAuthToken(ctx context.Context, rawToken, clientID, clientSecret string) (*TokenResponse, error) {
	client, err := s.oauthRepo.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client")
	}
	if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)) != nil {
		return nil, fmt.Errorf("invalid client credentials")
	}

	tokenHash := tokenservice.HashToken(rawToken)
	rt, err := s.tokenRepo.FindRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	user, err := s.userRepo.FindByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Revoke old token
	if err := s.tokenRepo.RevokeRefreshToken(ctx, rt.ID); err != nil {
		return nil, fmt.Errorf("revoking old token: %w", err)
	}

	accessToken, _, err := s.jwtSvc.GenerateAccessToken(user.ID, user.Email, clientID, "")
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	newRaw, newHash := tokenservice.GenerateOpaqueToken()
	expiresAt := time.Now().Add(s.cfg.RefreshTokenExpiration)
	if err := s.oauthRepo.SaveOAuthRefreshToken(ctx, user.ID, newHash, expiresAt, clientID); err != nil {
		return nil, fmt.Errorf("saving new refresh token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.JWTExpiration.Seconds()),
		RefreshToken: newRaw,
	}, nil
}

// RegisterClient creates a new OAuth client. Returns the raw client secret (shown once).
func (s *Service) RegisterClient(ctx context.Context, name, logoURL string, redirectURIs, scopes []string) (*models.OAuthClient, string, error) {
	clientID := uuid.New().String()
	rawSecret := uuid.New().String()

	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), 12)
	if err != nil {
		return nil, "", fmt.Errorf("hashing secret: %w", err)
	}

	client := &models.OAuthClient{
		ClientID:      clientID,
		Name:          name,
		LogoURL:       logoURL,
		RedirectURIs:  redirectURIs,
		AllowedScopes: scopes,
		IsActive:      true,
	}
	if err := s.oauthRepo.CreateClient(ctx, client, string(hash)); err != nil {
		return nil, "", fmt.Errorf("creating client: %w", err)
	}
	return client, rawSecret, nil
}

// --- PKCE helpers ---

func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// --- pending auth key helpers ---

const pendingKeyPrefix = "oauth:pending:"

func pendingKey(key string) string {
	return pendingKeyPrefix + key
}

func csrfKey(pendingKey string) string {
	return "oauth:csrf:" + pendingKey
}

// encodePendingAuth serializes an AuthRequest as a pipe-separated string.
func encodePendingAuth(req AuthRequest) string {
	return strings.Join([]string{
		req.ClientID,
		req.RedirectURI,
		strings.Join(req.Scopes, " "),
		req.State,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		req.Nonce,
	}, "|")
}

func decodePendingAuth(val string) (*AuthRequest, error) {
	parts := strings.SplitN(val, "|", 7)
	if len(parts) != 7 {
		return nil, fmt.Errorf("invalid pending auth format")
	}
	scopes := []string{}
	if parts[2] != "" {
		scopes = strings.Split(parts[2], " ")
	}
	return &AuthRequest{
		ClientID:            parts[0],
		RedirectURI:         parts[1],
		Scopes:              scopes,
		State:               parts[3],
		CodeChallenge:       parts[4],
		CodeChallengeMethod: parts[5],
		Nonce:               parts[6],
	}, nil
}

// --- generic helpers ---

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsURI(slice []string, uri string) bool {
	for _, s := range slice {
		if s == uri {
			return true
		}
	}
	return false
}
