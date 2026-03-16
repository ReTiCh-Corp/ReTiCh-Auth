package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// OriginChecker is a function that returns true if the given origin is allowed.
type OriginChecker func(origin string) bool

// StaticOriginChecker builds an OriginChecker from a comma-separated list of origins.
func StaticOriginChecker(allowedOrigins string) OriginChecker {
	set := make(map[string]struct{})
	for _, o := range strings.Split(allowedOrigins, ",") {
		set[strings.TrimSpace(o)] = struct{}{}
	}
	return func(origin string) bool {
		_, ok := set[origin]
		return ok
	}
}

// DynamicOriginChecker combines static origins with a DB-backed loader that refreshes every ttl.
// This allows new OAuth clients to be added without restarting the server.
func DynamicOriginChecker(staticOrigins string, loader func() ([]string, error), ttl time.Duration) OriginChecker {
	static := StaticOriginChecker(staticOrigins)

	var mu sync.RWMutex
	var cached map[string]struct{}
	var expiresAt time.Time

	refresh := func() {
		origins, err := loader()
		if err != nil {
			return
		}
		set := make(map[string]struct{}, len(origins))
		for _, o := range origins {
			set[strings.TrimSpace(o)] = struct{}{}
		}
		mu.Lock()
		cached = set
		expiresAt = time.Now().Add(ttl)
		mu.Unlock()
	}

	// Prime the cache at startup
	refresh()

	return func(origin string) bool {
		if static(origin) {
			return true
		}

		mu.RLock()
		expired := time.Now().After(expiresAt)
		_, ok := cached[origin]
		mu.RUnlock()

		if expired {
			go refresh()
		}

		return ok
	}
}

func CORS(isAllowed OriginChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" && isAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
