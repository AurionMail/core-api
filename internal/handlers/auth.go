package handlers

import (
	"aurion-api/internal/auth"
	"aurion-api/internal/config"
	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"
	"encoding/json"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type AuthHandler struct {
	DB   *db.DB
	Cfg  *config.Config
	LDAP *auth.LDAPAuthenticator
}

func NewAuthHandler(database *db.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		DB:   database,
		Cfg:  cfg,
		LDAP: auth.NewLDAPAuthenticator(cfg),
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	// 1. Direct authentication against the LDAP server
	email, err := h.LDAP.Authenticate(req.Email, req.Password)
	if err != nil {
		log.Printf("Error when authenticating user %s (%s)", req.Email, err)
		http.Error(w, `{"error":"Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// 2. Synchronization / Retrieval in the local database (to retain the user_id UUID)
	var user models.User
	query := `SELECT id, email, created_at FROM users WHERE email = $1`
	err = h.DB.Pool.QueryRow(r.Context(), query, email).Scan(&user.ID, &user.Email, &user.CreatedAt)

	if err == pgx.ErrNoRows {
		// Auto-provisioning: valid LDAP user is added to the local DB
		insertQuery := `
            INSERT INTO users (email) 
            VALUES ($1) 
            RETURNING id, email, created_at`
		err = h.DB.Pool.QueryRow(r.Context(), insertQuery, email).Scan(&user.ID, &user.Email, &user.CreatedAt)
	}

	if err != nil {
		log.Printf("Error when synchronizing user %s (%s)", req.Email, err)
		http.Error(w, `{"error":"Error synchronizing account"}`, http.StatusInternalServerError)
		return
	}

	// 3. JWT token generation
	token, err := auth.GenerateToken(user.ID, user.Email, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		log.Printf("Error when generating token for user %s (%s)", req.Email, err)
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
	query := `SELECT id, email, created_at FROM users WHERE id = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, userID).Scan(&user.ID, &user.Email, &user.CreatedAt)

	if err != nil {
		log.Printf("Error when retrieving user %s (%s)", userID, err)
		http.Error(w, `{"error":"Error retrieving user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
