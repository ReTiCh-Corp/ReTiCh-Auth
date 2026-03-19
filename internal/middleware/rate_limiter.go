package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/retich-corp/auth/internal/cache"
	"github.com/retich-corp/auth/pkg/response"
)

// RateLimit returns a middleware that allows at most `limit` requests per `window` per client IP.
// The key prefix is used to namespace the rate limit (e.g., "login", "register").
func RateLimit(c *cache.Cache, keyPrefix string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			key := fmt.Sprintf("rate:%s:%s", keyPrefix, ip)

			count := c.Incr(key, window)

			if count > int64(limit) {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", window.Seconds()))
				response.Error(w, http.StatusTooManyRequests, "too many requests, please try again later")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For may contain multiple IPs; take the first
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
