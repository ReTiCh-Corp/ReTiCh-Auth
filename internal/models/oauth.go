package models

import (
	"time"

	"github.com/google/uuid"
)

type OAuthClient struct {
	ID               uuid.UUID `json:"id"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	Name             string    `json:"name"`
	LogoURL          string    `json:"logo_url,omitempty"`
	RedirectURIs     []string  `json:"redirect_uris"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	IsActive         bool      `json:"is_active"`
	CreatedAt        time.Time `json:"created_at"`
}

type AuthorizationCode struct {
	ID            uuid.UUID  `json:"id"`
	CodeHash      string     `json:"-"`
	ClientID      string     `json:"client_id"`
	UserID        uuid.UUID  `json:"user_id"`
	RedirectURI   string     `json:"redirect_uri"`
	Scopes        []string   `json:"scopes"`
	CodeChallenge string     `json:"-"`
	Nonce         string     `json:"nonce,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
	UsedAt        *time.Time `json:"used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type OAuthConsent struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	ClientID  string     `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	GrantedAt time.Time  `json:"granted_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
