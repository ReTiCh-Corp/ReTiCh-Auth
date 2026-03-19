package repository

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/retich-corp/auth/internal/models"
	"github.com/retich-corp/auth/pkg/apperrors"
)

type OAuthRepository struct {
	pool *pgxpool.Pool
}

func NewOAuthRepository(pool *pgxpool.Pool) *OAuthRepository {
	return &OAuthRepository{pool: pool}
}

// --- OAuth Clients ---

func (r *OAuthRepository) CreateClient(ctx context.Context, client *models.OAuthClient, secretHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, name, logo_url, redirect_uris, allowed_scopes)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		client.ClientID, secretHash, client.Name, client.LogoURL,
		client.RedirectURIs, client.AllowedScopes,
	)
	return err
}

func (r *OAuthRepository) GetClientByClientID(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, logo_url, redirect_uris, allowed_scopes, is_active, created_at
		FROM oauth_clients WHERE client_id = $1`, clientID).Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.LogoURL,
		&c.RedirectURIs, &c.AllowedScopes, &c.IsActive, &c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

// GetAllowedOrigins returns unique origins extracted from all active clients' redirect_uris.
// Used by the CORS middleware to dynamically allow origins without server restarts.
func (r *OAuthRepository) GetAllowedOrigins(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT unnest(redirect_uris) FROM oauth_clients WHERE is_active = true`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	var origins []string
	for rows.Next() {
		var rawURI string
		if err := rows.Scan(&rawURI); err != nil {
			continue
		}
		u, err := url.Parse(rawURI)
		if err != nil || u.Host == "" {
			continue
		}
		origin := u.Scheme + "://" + u.Host
		if _, exists := seen[origin]; !exists {
			seen[origin] = struct{}{}
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

func (r *OAuthRepository) ListClients(ctx context.Context) ([]*models.OAuthClient, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, client_id, client_secret_hash, name, logo_url, redirect_uris, allowed_scopes, is_active, created_at
		FROM oauth_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*models.OAuthClient
	for rows.Next() {
		c := &models.OAuthClient{}
		if err := rows.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.LogoURL,
			&c.RedirectURIs, &c.AllowedScopes, &c.IsActive, &c.CreatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (r *OAuthRepository) GetClientByUUID(ctx context.Context, id uuid.UUID) (*models.OAuthClient, error) {
	c := &models.OAuthClient{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, logo_url, redirect_uris, allowed_scopes, is_active, created_at
		FROM oauth_clients WHERE id = $1`, id).Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.LogoURL,
		&c.RedirectURIs, &c.AllowedScopes, &c.IsActive, &c.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (r *OAuthRepository) UpdateClient(ctx context.Context, id uuid.UUID, name, logoURL string, redirectURIs, scopes []string, isActive bool) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE oauth_clients
		SET name = $2, logo_url = $3, redirect_uris = $4, allowed_scopes = $5, is_active = $6
		WHERE id = $1`,
		id, name, logoURL, redirectURIs, scopes, isActive,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *OAuthRepository) ActivateClient(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE oauth_clients SET is_active = true WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *OAuthRepository) DeactivateClient(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE oauth_clients SET is_active = false WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// --- Authorization Codes ---

func (r *OAuthRepository) SaveAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO authorization_codes
			(code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, nonce, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		code.CodeHash, code.ClientID, code.UserID, code.RedirectURI,
		code.Scopes, code.CodeChallenge, code.Nonce, code.ExpiresAt,
	)
	return err
}

// GetAndConsumeAuthorizationCode atomically fetches and marks the code as used.
// Returns apperrors.ErrNotFound if the code doesn't exist, is expired, or was already used.
func (r *OAuthRepository) GetAndConsumeAuthorizationCode(ctx context.Context, codeHash string) (*models.AuthorizationCode, error) {
	code := &models.AuthorizationCode{}
	err := r.pool.QueryRow(ctx, `
		UPDATE authorization_codes
		SET used_at = NOW()
		WHERE code_hash = $1
		  AND used_at IS NULL
		  AND expires_at > NOW()
		RETURNING id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, nonce, expires_at, used_at, created_at`,
		codeHash,
	).Scan(
		&code.ID, &code.CodeHash, &code.ClientID, &code.UserID,
		&code.RedirectURI, &code.Scopes, &code.CodeChallenge, &code.Nonce,
		&code.ExpiresAt, &code.UsedAt, &code.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return code, nil
}

// --- Consents ---

func (r *OAuthRepository) GetConsent(ctx context.Context, userID uuid.UUID, clientID string) (*models.OAuthConsent, error) {
	c := &models.OAuthConsent{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, client_id, scopes, granted_at, revoked_at
		FROM oauth_consents
		WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		userID, clientID,
	).Scan(&c.ID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt, &c.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

func (r *OAuthRepository) UpsertConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_consents (user_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, client_id) DO UPDATE
		SET scopes = $3, granted_at = NOW(), revoked_at = NULL`,
		userID, clientID, scopes,
	)
	return err
}

// ClientUser is a user who has granted consent to an OAuth client.
type ClientUser struct {
	ID         uuid.UUID  `json:"id"`
	Email      string     `json:"email"`
	IsVerified bool       `json:"is_verified"`
	IsActive   bool       `json:"is_active"`
	Scopes     []string   `json:"scopes"`
	GrantedAt  time.Time  `json:"granted_at"`
	LastLogin  *time.Time `json:"last_login_at"`
}

// ListUsersByClientID returns all users who have an active consent for the given client_id.
func (r *OAuthRepository) ListUsersByClientID(ctx context.Context, clientID string) ([]*ClientUser, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT u.id, u.email, u.is_verified, u.is_active, c.scopes, c.granted_at, u.last_login_at
		FROM oauth_consents c
		JOIN users u ON u.id = c.user_id
		WHERE c.client_id = $1 AND c.revoked_at IS NULL
		ORDER BY c.granted_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*ClientUser
	for rows.Next() {
		u := &ClientUser{}
		if err := rows.Scan(&u.ID, &u.Email, &u.IsVerified, &u.IsActive, &u.Scopes, &u.GrantedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// SaveOAuthRefreshToken stores an OAuth refresh token (reuses the existing refresh_tokens table).
func (r *OAuthRepository) SaveOAuthRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time, clientID string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, device_info, expires_at)
		VALUES ($1, $2, $3, $4)`,
		userID, tokenHash, "oauth:"+clientID, expiresAt,
	)
	return err
}
