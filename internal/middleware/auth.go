package middleware

import (
	"aurion-api/internal/auth"
	"aurion-api/internal/db"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
)

type contextKey string

const UserIDKey contextKey = "userID"

func AuthMiddleware(database *db.DB, jwtSecret string) func(http.Handler) http.Handler {
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

			claims, err := auth.ValidateToken(parts[1], jwtSecret)
			if err != nil {
				http.Error(w, `{"error":"Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}
			currentVersion, err := CheckUserVersion(database, r.Context(), claims.UserID)
			if err != nil || claims.TokenVersion < currentVersion {
				http.Error(w, `{"error":"Token has been revoked"}`, http.StatusUnauthorized)
				return
			}

			// Inject user ID into request context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserIDFromContext retrieves the user ID from the context in handlers
func GetUserIDFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(UserIDKey).(string); ok {
		return val
	}
	return ""
}

func CheckUserVersion(database *db.DB, ctx context.Context, userID string) (int, error) {
	var tokenVersion int
	query := `SELECT token_version FROM users WHERE id = $1`

	err := database.Pool.QueryRow(ctx, query, userID).Scan(&tokenVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("user not found")
		}
		return 0, err
	}

	return tokenVersion, nil
}
