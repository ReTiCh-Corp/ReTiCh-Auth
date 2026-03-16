package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const cookieName = "retich_session"

// Service manages browser session cookies for the OAuth authorization flow.
// The cookie value is: base64(userID) + "." + base64(HMAC-SHA256(base64(userID), secret))
type Service struct {
	secret  []byte
	expiry  time.Duration
	secure  bool
}

func NewService(secret string, expiry time.Duration, secure bool) *Service {
	return &Service{
		secret: []byte(secret),
		expiry: expiry,
		secure: secure,
	}
}

// CreateSession writes a signed browser session cookie for the given userID.
func (s *Service) CreateSession(w http.ResponseWriter, userID string) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(userID))
	sig := s.sign(payload)
	value := payload + "." + sig

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(s.expiry.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetUserID reads and verifies the browser session cookie.
// Returns "" and an error if the cookie is absent, tampered, or expired.
func (s *Service) GetUserID(r *http.Request) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return "", fmt.Errorf("no session cookie")
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed session cookie")
	}

	payload, sig := parts[0], parts[1]
	if s.sign(payload) != sig {
		return "", fmt.Errorf("invalid session signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("invalid session payload")
	}
	return string(raw), nil
}

// DestroySession clears the browser session cookie.
func (s *Service) DestroySession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
