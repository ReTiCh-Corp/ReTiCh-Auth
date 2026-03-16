package tokenservice

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Scope  string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// IDTokenClaims are the claims for an OIDC ID token (RS256, issued alongside access token).
type IDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Nonce         string `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// JWK is a single JSON Web Key (RSA public key, RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is the /.well-known/jwks.json response body.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWTService struct {
	privateKey *rsa.PrivateKey
	kid        string
	expiration time.Duration
	issuer     string
}

// NewJWTService creates a JWTService from a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
// If pemKey is empty, a 2048-bit key is generated automatically (dev only —
// tokens are invalidated on every restart).
func NewJWTService(pemKey string, expiration time.Duration, issuer string) (*JWTService, error) {
	pemKey = strings.ReplaceAll(pemKey, `\n`, "\n")

	var privateKey *rsa.PrivateKey
	if pemKey == "" {
		log.Println("[WARN] RSA_PRIVATE_KEY not set — generating ephemeral key (dev only, tokens reset on restart)")
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generating RSA key: %w", err)
		}
	} else {
		block, _ := pem.Decode([]byte(pemKey))
		if block == nil {
			return nil, fmt.Errorf("failed to decode RSA_PRIVATE_KEY PEM block")
		}
		var err error
		switch block.Type {
		case "RSA PRIVATE KEY":
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
			if e != nil {
				return nil, fmt.Errorf("parsing PKCS8 private key: %w", e)
			}
			var ok bool
			privateKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("PKCS8 key is not RSA")
			}
		default:
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing RSA private key: %w", err)
		}
	}

	// kid = first 8 bytes of the SHA-256 fingerprint of the DER public key
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key for kid: %w", err)
	}
	fp := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(fp[:8])

	return &JWTService{
		privateKey: privateKey,
		kid:        kid,
		expiration: expiration,
		issuer:     issuer,
	}, nil
}

// PublicJWKSet returns the JWKS payload for /.well-known/jwks.json.
// Apps cache this and use it to verify tokens without contacting the auth service.
func (s *JWTService) PublicJWKSet() JWKSet {
	pub := &s.privateKey.PublicKey
	e := big.NewInt(int64(pub.E))
	return JWKSet{
		Keys: []JWK{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: s.kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(e.Bytes()),
		}},
	}
}

// GenerateAccessToken creates a signed JWT for the given user.
// audience identifies the target app (e.g. "shop"). Pass "" for no restriction.
// scope is the space-separated list of granted OAuth scopes (e.g. "openid email").
func (s *JWTService) GenerateAccessToken(userID uuid.UUID, email, audience, scope string) (string, string, error) {
	jti := uuid.New().String()
	now := time.Now()

	registered := jwt.RegisteredClaims{
		Issuer:    s.issuer,
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
		Scope:            scope,
		RegisteredClaims: registered,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("signing token: %w", err)
	}
	return signed, jti, nil
}

// GenerateIDToken creates an OIDC ID token for the given user.
// audience must be the client_id of the OAuth client.
func (s *JWTService) GenerateIDToken(userID uuid.UUID, email string, emailVerified bool, audience, nonce string) (string, error) {
	now := time.Now()
	claims := &IDTokenClaims{
		Email:         email,
		EmailVerified: emailVerified,
		Nonce:         nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiration)),
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing id_token: %w", err)
	}
	return signed, nil
}

// ParseAccessToken validates the RS256 token and returns its claims.
func (s *JWTService) ParseAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &s.privateKey.PublicKey, nil
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
