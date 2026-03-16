package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                string     `json:"email"`
	PasswordHash         string     `json:"-"`
	IsVerified           bool       `json:"is_verified"`
	IsActive             bool       `json:"is_active"`
	FailedLoginAttempts  int        `json:"-"`
	LockedUntil          *time.Time `json:"-"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}
