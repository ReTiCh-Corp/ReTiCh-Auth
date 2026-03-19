package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/retich-corp/auth/internal/cache"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
	"github.com/retich-corp/auth/pkg/response"
)

type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyJTI    contextKey = "jti"
	ContextKeyEmail  contextKey = "email"
)

// JWTAuth validates the Bearer JWT and checks the audience claim.
// Pass a non-empty audience to restrict the route to tokens issued for that specific client.
// Pass "" to accept tokens for any audience, but a token MUST still contain an audience claim.
func JWTAuth(jwtSvc *tokenservice.JWTService, c *cache.Cache, audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				response.Error(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			claims, err := jwtSvc.ParseAccessToken(tokenString)
			if err != nil {
				response.Error(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Tokens must always have an audience claim
			if len(claims.Audience) == 0 {
				response.Error(w, http.StatusUnauthorized, "token missing audience claim")
				return
			}

			// If a specific audience is required, check it matches
			if audience != "" {
				found := false
				for _, aud := range claims.Audience {
					if aud == audience {
						found = true
						break
					}
				}
				if !found {
					response.Error(w, http.StatusUnauthorized, "token audience mismatch")
					return
				}
			}

			// Check blacklist
			if c.Exists("jwt_blacklist:" + claims.ID) {
				response.Error(w, http.StatusUnauthorized, "token has been revoked")
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, ContextKeyJTI, claims.ID)
			ctx = context.WithValue(ctx, ContextKeyEmail, claims.Email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyUserID).(string)
	return v
}

func JTIFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyJTI).(string)
	return v
}

func EmailFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyEmail).(string)
	return v
}
