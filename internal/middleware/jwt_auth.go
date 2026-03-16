package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
	redisclient "github.com/retich-corp/auth/internal/redis"
	tokenservice "github.com/retich-corp/auth/internal/service/token"
	"github.com/retich-corp/auth/pkg/response"
)

type contextKey string

const (
	ContextKeyUserID contextKey = "user_id"
	ContextKeyJTI    contextKey = "jti"
	ContextKeyEmail  contextKey = "email"
)

// JWTAuth validates the Bearer JWT and optionally checks the audience.
// Pass a non-empty audience to restrict the route to tokens issued for a specific client.
// Pass "" to accept tokens from any client (e.g. internal auth routes).
func JWTAuth(jwtSvc *tokenservice.JWTService, rdb *redis.Client, audience string) func(http.Handler) http.Handler {
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

			// Check audience if required
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
			blacklisted, err := redisclient.IsJWTBlacklisted(r.Context(), rdb, claims.ID)
			if err != nil || blacklisted {
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
