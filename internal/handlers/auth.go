package handlers

import (
	"aurion-api/internal/auth"
	"aurion-api/internal/config"
	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"
	"aurion-api/internal/wks"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	srp "github.com/opencoff/go-srp"
)

type SRPSession struct {
	UserID    string
	Email     string
	SRPServer *srp.Server
	SRPHandle *srp.SRP
	ExpiresAt time.Time
}

type AuthHandler struct {
	DB          *db.DB
	Cfg         *config.Config
	LDAP        *auth.LDAPAuthenticator
	srpSessions map[string]*SRPSession
	srpMutex    sync.RWMutex
}

func NewAuthHandler(database *db.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		DB:          database,
		Cfg:         cfg,
		LDAP:        auth.NewLDAPAuthenticator(cfg),
		srpSessions: make(map[string]*SRPSession),
	}
}

// --------SRP Auth----------

// Register stores the encoded SRP verifier and hashed identity returned by the client
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		SRPID       string `json:"srpId"`       // Hashed identity (I) from client/lib
		SRPVerifier string `json:"srpVerifier"` // Encoded verifier string (verif)
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.SRPID == "" || req.SRPVerifier == "" {
		http.Error(w, `{"error":"Missing required fields"}`, http.StatusBadRequest)
		return
	}

	wkdHash := wks.HashLocalPart(req.Email)

	var user models.User
	query := `
		INSERT INTO users (email, wkd_hash, srp_id, srp_verifier) 
		VALUES ($1, $2, $3, $4) 
		RETURNING id, email, token_version, created_at`

	err := h.DB.Pool.QueryRow(
		r.Context(),
		query,
		req.Email,
		wkdHash,
		req.SRPID,
		req.SRPVerifier,
	).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)

	if err != nil {
		log.Printf("Error creating user %s: %v", req.Email, err)
		http.Error(w, `{"error":"User already exists or server error"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// SRPChallenge handles step 1 of the SRP-6a authentication flow
func (h *AuthHandler) SRPChallenge(w http.ResponseWriter, r *http.Request) {
	var req models.SRPChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	// 1. Parse client credentials string (contains identity ID and public key A)
	srpID, clientA, err := srp.ServerBegin(req.A)
	if err != nil {
		log.Printf("Error parsing client credentials: %v", err)
		http.Error(w, `{"error":"Invalid credentials payload"}`, http.StatusBadRequest)
		return
	}

	// 2. Fetch user by hashed SRP ID
	var user struct {
		ID          string
		Email       string
		SRPVerifier string
	}
	query := `SELECT id, email, srp_verifier FROM users WHERE srp_id = $1`
	err = h.DB.Pool.QueryRow(r.Context(), query, srpID).Scan(&user.ID, &user.Email, &user.SRPVerifier)

	if err == pgx.ErrNoRows {
		http.Error(w, `{"error":"Invalid credentials"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Error retrieving user with SRP ID %s: %v", srpID, err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// 3. Reconstruct SRP and Verifier objects from stored string
	srpHandle, verifier, err := srp.MakeSRPVerifier(user.SRPVerifier)
	if err != nil {
		log.Printf("Error reconstructing SRP verifier: %v", err)
		http.Error(w, `{"error":"Corrupted authentication data"}`, http.StatusInternalServerError)
		return
	}

	// 4. Create new Server instance for this session
	srv, err := srpHandle.NewServer(verifier, clientA)
	if err != nil {
		log.Printf("Error creating SRP server instance: %v", err)
		http.Error(w, `{"error":"Failed to initiate SRP handshake"}`, http.StatusBadRequest)
		return
	}

	sessionID := uuid.New().String()

	h.srpMutex.Lock()
	h.srpSessions[sessionID] = &SRPSession{
		UserID:    user.ID,
		Email:     user.Email,
		SRPServer: srv,
		SRPHandle: srpHandle,
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}
	h.srpMutex.Unlock()

	// 5. Respond with server credentials (B and salt s encoded by go-srp)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.SRPChallengeResponse{
		SessionID: sessionID,
		B:         srv.Credentials(),
	})
}

// SRPVerify handles step 2 of the SRP-6a authentication flow
func (h *AuthHandler) SRPVerify(w http.ResponseWriter, r *http.Request) {
	var req models.SRPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	h.srpMutex.RLock()
	sess, exists := h.srpSessions[req.SessionID]
	h.srpMutex.RUnlock()

	if !exists || time.Now().After(sess.ExpiresAt) {
		http.Error(w, `{"error":"Session expired or invalid"}`, http.StatusUnauthorized)
		return
	}

	defer func() {
		h.srpMutex.Lock()
		delete(h.srpSessions, req.SessionID)
		h.srpMutex.Unlock()
	}()

	// 1. Authenticate client proof M1 and generate server proof M2
	serverProof, ok := sess.SRPServer.ClientOk(req.M1)
	if ok != false {
		http.Error(w, `{"error":"Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// 2. Fetch user profile and token version
	var user models.User
	query := `SELECT id, email, token_version, created_at FROM users WHERE id = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, sess.UserID).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)
	if err != nil {
		log.Printf("Error fetching user %s: %v", sess.UserID, err)
		http.Error(w, `{"error":"Error fetching user details"}`, http.StatusInternalServerError)
		return
	}

	// 3. Generate JWT
	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		log.Printf("Error generating JWT for user %s: %v", user.Username, err)
		http.Error(w, `{"error":"Error generating token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.SRPVerifyResponse{
		Token: token,
		M2:    serverProof,
		User:  user,
	})
}

//---Legacy Auth--------------

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

// email is not email, it is username.
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
	query := `SELECT id, email, token_version, created_at FROM users WHERE email = $1`
	err = h.DB.Pool.QueryRow(r.Context(), query, email).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)

	if err == pgx.ErrNoRows {
		wkdHash := wks.HashLocalPart(email)
		// Auto-provisioning: valid LDAP user is added to the local DB
		insertQuery := `
            INSERT INTO users (email, wkd_hash) 
            VALUES ($1, $2) 
            RETURNING id, email, token_version, created_at`
		err = h.DB.Pool.QueryRow(r.Context(), insertQuery, email, wkdHash).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)
	}

	if err != nil {
		log.Printf("Error when synchronizing user %s (%s)", req.Email, err)
		http.Error(w, `{"error":"Error synchronizing account"}`, http.StatusInternalServerError)
		return
	}

	// 3. JWT token generation
	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
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
        RETURNING id, email, token_version, created_at`

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

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserIDFromContext(r.Context())

	var user models.User
	query := `SELECT id, email FROM users WHERE id = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, userID).Scan(&user.ID, &user.Username)
	if err != nil {
		log.Printf("Error retrieving user for password change %s (%s)", userID, err)
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	}

	err = h.LDAP.ChangePassword(user.Username, req.CurrentPassword, req.NewPassword)
	if err != nil {
		log.Printf("Error changing LDAP password for user %s (%s)", user.Username, err)
		http.Error(w, `{"error":"Invalid credentials or password policy failed"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password updated successfully.",
	})
}
