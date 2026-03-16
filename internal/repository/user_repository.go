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

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, email, passwordHash string) (*models.User, error) {
	user := &models.User{}
	query := `
		INSERT INTO users (id, email, password_hash, is_verified, is_active)
		VALUES (gen_random_uuid(), $1, $2, false, true)
		RETURNING id, email, password_hash, is_verified, is_active,
		          failed_login_attempts, locked_until, last_login_at, created_at, updated_at`

	err := r.pool.QueryRow(ctx, query, email, passwordHash).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsActive,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, password_hash, is_verified, is_active,
		       failed_login_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users WHERE email = $1`

	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsActive,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, email, password_hash, is_verified, is_active,
		       failed_login_attempts, locked_until, last_login_at, created_at, updated_at
		FROM users WHERE id = $1`

	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.IsVerified, &user.IsActive,
		&user.FailedLoginAttempts, &user.LockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	return exists, err
}

func (r *UserRepository) SetVerified(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET is_verified = true WHERE id = $1`, userID)
	return err
}

func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID, lockUntil *time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET failed_login_attempts = failed_login_attempts + 1, locked_until = $2 WHERE id = $1`,
		userID, lockUntil)
	return err
}

func (r *UserRepository) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1`,
		userID)
	return err
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2 WHERE id = $1`, userID, passwordHash)
	return err
}
