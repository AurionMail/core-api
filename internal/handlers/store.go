package handlers

import (
	"aurion-api/internal/bridge"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

type BridgeHandler struct {
	Bridge *bridge.MemoryBridge
}

func NewBridgeHandler(b *bridge.MemoryBridge) *BridgeHandler {
	return &BridgeHandler{Bridge: b}
}

type PushSecretRequest struct {
	EncryptedData string `json:"encryptedData"`
	TTLSeconds    int    `json:"ttlSeconds,omitempty"` // Default: 300s (5 min)
	ID            string `json:"id,omitempty"`         // Optional custom ID (used by internal route)
}

type InternalPushSecretRequest struct {
	EncryptedData string `json:"encryptedData"`
	TTLSeconds    int    `json:"ttlSeconds,omitempty"` // Default: 300s (5 min)
	ID            string `json:"id,omitempty"`         // Optional custom ID (used by internal route)
	Token         string `json:"loginToken,omitempty"`
	Username      string `json:"username,omitempty"`
}

type PushSecretResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Fonction interne partagée pour gérer la logique d'enregistrement
func (h *BridgeHandler) handlePushSecret(w http.ResponseWriter, r *http.Request) {
	var req PushSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.EncryptedData) == "" {
		http.Error(w, `{"error":"Invalid or missing encrypted payload"}`, http.StatusBadRequest)
		return
	}

	ttl := 5 * time.Minute
	if req.TTLSeconds > 0 && req.TTLSeconds <= 3600 { // Max 1h
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	req.ID = "" // Ignore any provided ID for public route

	blob, err := h.Bridge.Store(req.EncryptedData, ttl, req.ID)
	if err != nil {
		http.Error(w, `{"error":"Error storing secret in memory"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(PushSecretResponse{
		ID:        blob.ID,
		ExpiresAt: blob.ExpiresAt,
	})
}

func (h *BridgeHandler) handleInternalPushSecret(w http.ResponseWriter, r *http.Request) {
	var req InternalPushSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	// Validation du TTL (Default: 5 min, Max: 1h)
	ttl := 5 * time.Minute
	if req.TTLSeconds > 0 && req.TTLSeconds <= 3600 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	req.EncryptedData = strings.TrimSpace(req.EncryptedData)
	req.Token = strings.TrimSpace(req.Token)
	req.Username = strings.TrimSpace(req.Username)

	var responseID string
	var responseExpiresAt time.Time

	if req.Token != "" && req.Username != "" {
		_, err := h.Bridge.StoreLoginToken(req.Username, req.Token, ttl)
		if err != nil {
			http.Error(w, `{"error":"Error storing login token in memory"}`, http.StatusInternalServerError)
			return
		}

	}
	secretBlob, err := h.Bridge.Store(req.EncryptedData, ttl, req.ID)
	if err != nil {
		http.Error(w, `{"error":"Error storing secret in memory"}`, http.StatusInternalServerError)
		return
	}
	responseID = secretBlob.ID
	responseExpiresAt = secretBlob.ExpiresAt

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(PushSecretResponse{
		ID:        responseID,
		ExpiresAt: responseExpiresAt,
	})
}

// POST /api/bridge/secret (Public) - Stores the secret in RAM
func (h *BridgeHandler) PushSecret(w http.ResponseWriter, r *http.Request) {
	h.handlePushSecret(w, r)
}

// POST /api/internal/bridge/secret (Internal) - Stores the secret in RAM
func (h *BridgeHandler) InternalPushSecret(w http.ResponseWriter, r *http.Request) {
	h.handleInternalPushSecret(w, r)
}

// GET /api/bridge/secret/{id} (Public) - Consumes the secret from RAM (Burn after reading)
func (h *BridgeHandler) ConsumeSecret(w http.ResponseWriter, r *http.Request) {
	// Extract URL parameter provided by Chi
	secretID := chi.URLParam(r, "id")

	if secretID == "" {
		http.Error(w, `{"error":"Missing secret ID"}`, http.StatusBadRequest)
		return
	}

	blob, ok := h.Bridge.Consume(secretID)
	if !ok {
		http.Error(w, `{"error":"Secret not found, already consumed, or expired"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"id":            blob.ID,
		"encryptedData": blob.EncryptedData,
	})
}
