package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/retich-corp/auth/internal/models"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, userID, refreshTokenID uuid.UUID, deviceInfo, ipAddress, userAgent string, expiresAt interface{}) (*models.Session, error) {
	s := &models.Session{}
	query := `
		INSERT INTO sessions (id, user_id, refresh_token_id, device_info, ip_address, user_agent, last_activity_at, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, NOW(), $6)
		RETURNING id, user_id, refresh_token_id, device_info, ip_address, user_agent, last_activity_at, expires_at, created_at`

	err := r.pool.QueryRow(ctx, query, userID, refreshTokenID, deviceInfo, ipAddress, userAgent, expiresAt).Scan(
		&s.ID, &s.UserID, &s.RefreshTokenID, &s.DeviceInfo, &s.IPAddress,
		&s.UserAgent, &s.LastActivityAt, &s.ExpiresAt, &s.CreatedAt,
	)
	return s, err
}

func (r *SessionRepository) DeleteByRefreshTokenID(ctx context.Context, refreshTokenID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM sessions WHERE refresh_token_id = $1`, refreshTokenID)
	return err
}

func (r *SessionRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (r *SessionRepository) UpdateRefreshToken(ctx context.Context, oldRefreshTokenID, newRefreshTokenID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE sessions SET refresh_token_id = $2, last_activity_at = NOW() WHERE refresh_token_id = $1`,
		oldRefreshTokenID, newRefreshTokenID)
	return err
}
