package tokenservice

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type JWTService struct {
	secret     []byte
	expiration time.Duration
}

func NewJWTService(secret string, expiration time.Duration) *JWTService {
	return &JWTService{
		secret:     []byte(secret),
		expiration: expiration,
	}
}

// GenerateAccessToken creates a signed JWT for the given user.
// audience identifies the target app (e.g. "app-shop"). Pass "" for no restriction.
func (s *JWTService) GenerateAccessToken(userID uuid.UUID, email, audience string) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now()

	registered := jwt.RegisteredClaims{
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.expiration)),
	}
	if audience != "" {
		registered.Audience = jwt.ClaimStrings{audience}
	}

	claims := &Claims{
		UserID:           userID.String(),
		Email:            email,
		RegisteredClaims: registered,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", "", fmt.Errorf("signing token: %w", err)
	}
	return signed, jti, nil
}

// ParseAccessToken validates the token and returns its claims.
func (s *JWTService) ParseAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// ExpirationFromClaims returns the remaining TTL of a token.
func ExpirationFromClaims(claims *Claims) time.Duration {
	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// HashToken returns a SHA-256 hex hash of a raw token string.
// Raw tokens are never stored in the DB — only their hashes.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// GenerateOpaqueToken generates a random opaque token (UUID-based) and returns
// the raw token (to send to the user) and its hash (to store in DB).
func GenerateOpaqueToken() (raw, hash string) {
	raw = uuid.New().String()
	hash = HashToken(raw)
	return raw, hash
}
