package handlers

import (
	"aurion-api/internal/auth"
	"aurion-api/internal/bridge"
	"aurion-api/internal/config"
	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"
	"aurion-api/internal/wks"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
)

type AuthHandler struct {
	DB     *db.DB
	Cfg    *config.Config
	LDAP   *auth.LDAPAuthenticator
	Bridge *bridge.MemoryBridge
}

func NewAuthHandler(database *db.DB, cfg *config.Config, bridge *bridge.MemoryBridge) *AuthHandler {

	return &AuthHandler{
		DB:     database,
		Cfg:    cfg,
		LDAP:   auth.NewLDAPAuthenticator(cfg),
		Bridge: bridge,
	}
}

type setOpaqueRequest struct {
	Username string `json:"username"`
	Opaque   string `json:"opaque"`
}

type getOpaqueRequest struct {
	Username string `json:"username"`
}

type getOpaqueResponse struct {
	Opaque string `json:"opaque"`
}

func (h *AuthHandler) SetOpaque(w http.ResponseWriter, r *http.Request) {
	var req setOpaqueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Opaque = strings.TrimSpace(req.Opaque)

	if req.Username == "" || req.Opaque == "" {
		http.Error(w, `{"error":"username and opaque fields are required"}`, http.StatusBadRequest)
		return
	}

	wkdHash := wks.HashLocalPart(req.Username)

	query := `
		INSERT INTO users (username, wkd_hash, opaque_record)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) 
		DO UPDATE SET opaque_record = EXCLUDED.opaque_record, updated_at = NOW()`

	_, err := h.DB.Pool.Exec(r.Context(), query, req.Username, wkdHash, req.Opaque)
	if err != nil {
		log.Printf("Error saving OPAQUE record for user %s: %v", req.Username, err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "OPAQUE record stored successfully",
	})
}

func (h *AuthHandler) GetOpaque(w http.ResponseWriter, r *http.Request) {
	var req getOpaqueRequest

	// Support du format JSON Body

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)

	if req.Username == "" {
		http.Error(w, `{"error":"username parameter is required"}`, http.StatusBadRequest)
		return
	}

	var opaqueRecord string
	query := `SELECT opaque_record FROM users WHERE username = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, req.Username).Scan(&opaqueRecord)

	if err == pgx.ErrNoRows || opaqueRecord == "" {
		http.Error(w, `{"error":"User or OPAQUE record not found"}`, http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("Error retrieving OPAQUE record for user %s: %v", req.Username, err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getOpaqueResponse{
		Opaque: opaqueRecord,
	})
}

//---Automated Auth, with temp login tokens--------------

type LoginRequest struct {
	Token string `json:"token"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		http.Error(w, `{"error":"Invalid JSON format or missing token"}`, http.StatusBadRequest)
		return
	}

	// 1. Consume the token from RAM bridge (burn after reading)
	tokenBlob, ok := h.Bridge.ConsumeLoginToken(req.Token)
	if !ok {
		http.Error(w, `{"error":"Invalid or expired login token"}`, http.StatusUnauthorized)
		return
	}

	username := tokenBlob.Username

	// 2. Synchronization / Retrieval in the local database (to retain the user_id UUID)
	var user models.User
	query := `SELECT id, username, token_version, created_at FROM users WHERE username = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, username).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)

	if err == pgx.ErrNoRows {
		wkdHash := wks.HashLocalPart(username)
		// Auto-provisioning: valid user is added to the local DB
		insertQuery := `
			INSERT INTO users (username, wkd_hash) 
			VALUES ($1, $2) 
			RETURNING id, username, token_version, created_at`
		err = h.DB.Pool.QueryRow(r.Context(), insertQuery, username, wkdHash).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)
	}

	if err != nil {
		log.Printf("Error when synchronizing user %s: %v", username, err)
		http.Error(w, `{"error":"Error synchronizing account"}`, http.StatusInternalServerError)
		return
	}

	// 3. JWT token generation
	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		log.Printf("Error when generating JWT for user %s: %v", username, err)
		http.Error(w, `{"error":"Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token: token,
		User:  user,
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())

	var user models.User
	query := `SELECT id, username, created_at FROM users WHERE id = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, userID).Scan(&user.ID, &user.Username, &user.CreatedAt)

	if err != nil {
		log.Printf("Error when retrieving user %s (%s)", userID, err)
		http.Error(w, `{"error":"Error retrieving user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())

	// Increment the token version in the database to invalidate existing tokens
	updateQuery := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := h.DB.Pool.Exec(r.Context(), updateQuery, userID)
	if err != nil {
		log.Printf("Error when logging out user %s (%s)", userID, err)
		http.Error(w, `{"error":"Error logging out"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}

func (h *AuthHandler) LogoutOthers(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())

	var user models.User
	updateQuery := `
        UPDATE users 
        SET token_version = token_version + 1 
        WHERE id = $1 
        RETURNING id, username, token_version, created_at`

	err := h.DB.Pool.QueryRow(r.Context(), updateQuery, userID).Scan(
		&user.ID,
		&user.Username,
		&user.TokenVersion,
		&user.CreatedAt,
	)
	if err != nil {
		log.Printf("Error when invalidating other sessions for user %s (%s)", userID, err)
		http.Error(w, `{"error":"Error logging out other sessions"}`, http.StatusInternalServerError)
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		log.Printf("Error when generating token for user %s (%s)", user.Username, err)
		http.Error(w, `{"error":"Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token: token,
		User:  user,
	})
}
