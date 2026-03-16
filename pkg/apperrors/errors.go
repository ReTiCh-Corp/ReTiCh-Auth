package apperrors

import "errors"

var (
	ErrNotFound          = errors.New("not found")
	ErrEmailTaken        = errors.New("email already taken")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountNotVerified = errors.New("account not verified")
	ErrAccountLocked     = errors.New("account locked")
	ErrAccountInactive   = errors.New("account inactive")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenInvalid      = errors.New("token invalid")
	ErrTokenUsed         = errors.New("token already used")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrPasswordMismatch  = errors.New("passwords do not match")
)
