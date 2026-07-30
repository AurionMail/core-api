package middleware

import (
	"net/http"
	"strings"
)

func InternalMiddleware(internalSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"Missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expected format: "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error":"Invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			if parts[1] != internalSecret {
				http.Error(w, `{"error":"Invalid internal secret"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
