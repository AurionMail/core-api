package handlers

import (
	"aurion-api/internal/auth"
	"aurion-api/internal/bridge"
	"aurion-api/internal/config"
	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"
	"aurion-api/internal/opaquei"
	"aurion-api/internal/wks"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytemare/opaque"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AuthHandler struct {
	DB             *db.DB
	Cfg            *config.Config
	LDAP           *auth.LDAPAuthenticator
	opaqueServer   *opaque.Server
	deserializer   *opaque.Deserializer
	opaqueSessions map[string]*models.OpaqueSession
	opaqueMutex    sync.RWMutex
	Bridge         *bridge.MemoryBridge
}

func NewAuthHandler(database *db.DB, cfg *config.Config, bridge *bridge.MemoryBridge) *AuthHandler {
	// serverID peut être le nom de ton domaine ou une chaîne unique fixe ex: "aurion-api"
	server, err := opaquei.InitOpaqueServer(cfg.OpaqueOPRFSeed, cfg.OpaquePrivateKey, "aurion-api")
	if err != nil {
		log.Fatalf("Échec de l'initialisation du serveur OPAQUE persisté : %v", err)
	}

	deserializer, err := opaque.DefaultConfiguration().Deserializer()
	if err != nil {
		log.Fatalf("Impossible de créer le désérialiseur OPAQUE : %v", err)
	}

	return &AuthHandler{
		DB:             database,
		Cfg:            cfg,
		LDAP:           auth.NewLDAPAuthenticator(cfg),
		opaqueServer:   server,
		deserializer:   deserializer,
		opaqueSessions: make(map[string]*models.OpaqueSession),
		Bridge:         bridge,
	}
}

// 1. Inscription : Init & Finalize
func (h *AuthHandler) RegisterInit(w http.ResponseWriter, r *http.Request) {
	var req models.OpaqueRegisterInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Format JSON invalide"}`, http.StatusBadRequest)
		return
	}

	reqBytes, err := hex.DecodeString(req.RegistrationRequest)
	if err != nil {
		http.Error(w, `{"error":"RegistrationRequest doit être du Hex"}`, http.StatusBadRequest)
		return
	}

	// Deserialisation de la requete d'inscription
	regReq, err := h.deserializer.RegistrationRequest(reqBytes)
	if err != nil {
		http.Error(w, `{"error":"RegistrationRequest invalide"}`, http.StatusBadRequest)
		return
	}

	// Appel direct sur opaque.Server
	resp, err := h.opaqueServer.RegistrationResponse(regReq, nil, nil)
	if err != nil {
		log.Printf("Erreur RegistrationResponse OPAQUE: %v", err)
		http.Error(w, `{"error":"Échec de l'initialisation OPAQUE"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.OpaqueRegisterInitResponse{
		RegistrationResponse: hex.EncodeToString(resp.Serialize()),
	})
}

// 2. Inscription : Stockage du record dans la BDD
func (h *AuthHandler) RegisterFinalize(w http.ResponseWriter, r *http.Request) {
	var req models.OpaqueRegisterFinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Format JSON invalide"}`, http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.RegistrationRecord == "" {
		http.Error(w, `{"error":"Champs requis manquants"}`, http.StatusBadRequest)
		return
	}

	wkdHash := wks.HashLocalPart(req.Email)

	var user models.User
	query := `
        INSERT INTO users (username, wkd_hash, opaque_record) 
        VALUES ($1, $2, $3) 
        RETURNING id, username, token_version, created_at`

	err := h.DB.Pool.QueryRow(
		r.Context(),
		query,
		req.Email,
		wkdHash,
		req.RegistrationRecord,
	).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)

	if err != nil {
		log.Printf("Erreur création utilisateur OPAQUE %s: %v", req.Email, err)
		http.Error(w, `{"error":"L'utilisateur existe déjà ou erreur serveur"}`, http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// 3. Authentification : Step 1 (Challenge -> KE1 à KE2)
func (h *AuthHandler) OpaqueChallenge(w http.ResponseWriter, r *http.Request) {
	var req models.OpaqueChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Format JSON invalide"}`, http.StatusBadRequest)
		return
	}

	ke1Bytes, err := hex.DecodeString(req.CredentialRequest)
	if err != nil {
		http.Error(w, `{"error":"CredentialRequest doit être du Hex"}`, http.StatusBadRequest)
		return
	}

	ke1Msg, err := h.deserializer.KE1(ke1Bytes)
	if err != nil {
		http.Error(w, `{"error":"Message KE1 invalide"}`, http.StatusBadRequest)
		return
	}

	// Récupération du record OPAQUE de l'utilisateur
	var user struct {
		ID           string
		Email        string
		OpaqueRecord string
	}
	query := `SELECT id, username, opaque_record FROM users WHERE username = $1`
	err = h.DB.Pool.QueryRow(r.Context(), query, req.Username).Scan(&user.ID, &user.Email, &user.OpaqueRecord)

	if err == pgx.ErrNoRows {
		http.Error(w, `{"error":"Identifiants invalides"}`, http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Erreur récupération utilisateur %s: %v", req.Username, err)
		http.Error(w, `{"error":"Erreur interne serveur"}`, http.StatusInternalServerError)
		return
	}

	recordBytes, err := hex.DecodeString(user.OpaqueRecord)
	if err != nil {
		http.Error(w, `{"error":"Enregistrement OPAQUE corrompu"}`, http.StatusInternalServerError)
		return
	}

	regRecord, err := h.deserializer.RegistrationRecord(recordBytes)
	if err != nil {
		http.Error(w, `{"error":"Format du record OPAQUE invalide"}`, http.StatusInternalServerError)
		return
	}

	clientRecord := &opaque.ClientRecord{
		RegistrationRecord:   regRecord,
		CredentialIdentifier: []byte(user.Email),
		ClientIdentity:       []byte(user.Email),
	}

	// Génération du message KE2 et des artefacts de session via le serveur OPAQUE
	ke2Msg, serverOutput, err := h.opaqueServer.GenerateKE2(ke1Msg, clientRecord)
	if err != nil {
		log.Printf("Erreur GenerateKE2 OPAQUE pour %s: %v", req.Username, err)
		http.Error(w, `{"error":"Échec d'initialisation du handshake"}`, http.StatusBadRequest)
		return
	}

	sessionID := uuid.New().String()

	h.opaqueMutex.Lock()
	h.opaqueSessions[sessionID] = &models.OpaqueSession{
		UserID:       user.ID,
		Email:        user.Email,
		ServerOutput: serverOutput,
		ExpiresAt:    time.Now().Add(2 * time.Minute),
	}
	h.opaqueMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.OpaqueChallengeResponse{
		SessionID:          sessionID,
		CredentialResponse: hex.EncodeToString(ke2Msg.Serialize()),
	})
}

// 4. Authentification : Step 2 (Verify -> KE3 validation)
func (h *AuthHandler) OpaqueVerify(w http.ResponseWriter, r *http.Request) {
	var req models.OpaqueVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Format JSON invalide"}`, http.StatusBadRequest)
		return
	}

	h.opaqueMutex.RLock()
	sess, exists := h.opaqueSessions[req.SessionID]
	h.opaqueMutex.RUnlock()

	if !exists || time.Now().After(sess.ExpiresAt) {
		http.Error(w, `{"error":"Session expirée ou invalide"}`, http.StatusUnauthorized)
		return
	}

	defer func() {
		h.opaqueMutex.Lock()
		delete(h.opaqueSessions, req.SessionID)
		h.opaqueMutex.Unlock()
	}()

	ke3Bytes, err := hex.DecodeString(req.CredentialFinalization)
	if err != nil {
		http.Error(w, `{"error":"CredentialFinalization invalide"}`, http.StatusBadRequest)
		return
	}

	ke3Msg, err := h.deserializer.KE3(ke3Bytes)
	if err != nil {
		http.Error(w, `{"error":"Message KE3 invalide"}`, http.StatusBadRequest)
		return
	}

	// Validation finale de KE3 avec la MAC attendue issue de ServerOutput
	err = h.opaqueServer.LoginFinish(ke3Msg, sess.ServerOutput.ClientMAC)
	if err != nil {
		http.Error(w, `{"error":"Identifiants invalides"}`, http.StatusUnauthorized)
		return
	}

	var user models.User
	query := `SELECT id, username, token_version, created_at FROM users WHERE id = $1`
	err = h.DB.Pool.QueryRow(r.Context(), query, sess.UserID).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)
	if err != nil {
		http.Error(w, `{"error":"Erreur lors de la récupération de l'utilisateur"}`, http.StatusInternalServerError)
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		http.Error(w, `{"error":"Erreur de génération de token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.OpaqueVerifyResponse{
		Token: token,
		User:  user,
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

	// The username retrieved from the bridge is mapped to the 'email' field/variable
	email := tokenBlob.Username

	// 2. Synchronization / Retrieval in the local database (to retain the user_id UUID)
	var user models.User
	query := `SELECT id, username, token_version, created_at FROM users WHERE username = $1`
	err := h.DB.Pool.QueryRow(r.Context(), query, email).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)

	if err == pgx.ErrNoRows {
		wkdHash := wks.HashLocalPart(email)
		// Auto-provisioning: valid user is added to the local DB
		insertQuery := `
			INSERT INTO users (username, wkd_hash) 
			VALUES ($1, $2) 
			RETURNING id, username, token_version, created_at`
		err = h.DB.Pool.QueryRow(r.Context(), insertQuery, email, wkdHash).Scan(&user.ID, &user.Username, &user.TokenVersion, &user.CreatedAt)
	}

	if err != nil {
		log.Printf("Error when synchronizing user %s: %v", email, err)
		http.Error(w, `{"error":"Error synchronizing account"}`, http.StatusInternalServerError)
		return
	}

	// 3. JWT token generation
	token, err := auth.GenerateToken(user.ID, user.Username, user.TokenVersion, h.Cfg.JWTSecret)
	if err != nil {
		log.Printf("Error when generating JWT for user %s: %v", email, err)
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

type ChangePasswordSRPRequest struct {
	SRPSalt     string `json:"srpSalt"`
	SRPVerifier string `json:"srpVerifier"`
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req ChangePasswordSRPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	req.SRPSalt = strings.TrimSpace(req.SRPSalt)
	req.SRPVerifier = strings.TrimSpace(req.SRPVerifier)

	if req.SRPSalt == "" || req.SRPVerifier == "" {
		http.Error(w, `{"error":"srpSalt and srpVerifier are required"}`, http.StatusBadRequest)
		return
	}

	userID := middleware.GetUserIDFromContext(r.Context())

	var username string
	checkQuery := `SELECT username FROM users WHERE id = $1`
	err := h.DB.Pool.QueryRow(r.Context(), checkQuery, userID).Scan(&username)
	if err == pgx.ErrNoRows {
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("Error retrieving user %s: %v", userID, err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	updateQuery := `
		UPDATE users 
		SET srp_salt = $1, srp_verifier = $2
		WHERE id = $3`

	_, err = h.DB.Pool.Exec(r.Context(), updateQuery, req.SRPSalt, req.SRPVerifier, userID)
	if err != nil {
		log.Printf("Error updating SRP credentials for user %s: %v", username, err)
		http.Error(w, `{"error":"Error updating password credentials"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password credentials updated successfully.",
	})
}
