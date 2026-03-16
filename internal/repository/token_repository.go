package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/retich-corp/auth/internal/models"
	"github.com/retich-corp/auth/pkg/apperrors"
)

type TokenRepository struct {
	pool *pgxpool.Pool
}

func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{pool: pool}
}

// --- Verification tokens (email verification + password reset) ---

func (r *TokenRepository) CreateVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash, tokenType string, expiresAt time.Time) (*models.VerificationToken, error) {
	t := &models.VerificationToken{}
	query := `
		INSERT INTO verification_tokens (id, user_id, token_hash, token_type, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
		RETURNING id, user_id, token_hash, token_type, expires_at, used_at, created_at`

	err := r.pool.QueryRow(ctx, query, userID, tokenHash, tokenType, expiresAt).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.TokenType, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt,
	)
	return t, err
}

func (r *TokenRepository) FindVerificationToken(ctx context.Context, tokenHash, tokenType string) (*models.VerificationToken, error) {
	t := &models.VerificationToken{}
	query := `
		SELECT id, user_id, token_hash, token_type, expires_at, used_at, created_at
		FROM verification_tokens
		WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > NOW()`

	err := r.pool.QueryRow(ctx, query, tokenHash, tokenType).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.TokenType, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, err
	}
	return t, nil
}

func (r *TokenRepository) MarkVerificationTokenUsed(ctx context.Context, tokenID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE verification_tokens SET used_at = NOW() WHERE id = $1`, tokenID)
	return err
}

func (r *TokenRepository) InvalidateVerificationTokensByType(ctx context.Context, userID uuid.UUID, tokenType string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE verification_tokens SET used_at = NOW() WHERE user_id = $1 AND token_type = $2 AND used_at IS NULL`,
		userID, tokenType)
	return err
}

// --- Refresh tokens ---

func (r *TokenRepository) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash, deviceInfo, ipAddress string, expiresAt time.Time) (*models.RefreshToken, error) {
	t := &models.RefreshToken{}
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, device_info, ip_address, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
		RETURNING id, user_id, token_hash, device_info, ip_address, expires_at, revoked_at, created_at`

	err := r.pool.QueryRow(ctx, query, userID, tokenHash, deviceInfo, ipAddress, expiresAt).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.DeviceInfo, &t.IPAddress,
		&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	)
	return t, err
}

func (r *TokenRepository) FindRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	t := &models.RefreshToken{}
	query := `
		SELECT id, user_id, token_hash, device_info, ip_address, expires_at, revoked_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.DeviceInfo, &t.IPAddress,
		&t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrTokenInvalid
		}
		return nil, err
	}
	return t, nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1`, tokenID)
	return err
}

func (r *TokenRepository) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}
