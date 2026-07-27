package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"aurion-api/internal/bridge"

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
}

type PushSecretResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// POST /api/bridge/secret (Public) - Stores the secret in RAM
func (h *BridgeHandler) PushSecret(w http.ResponseWriter, r *http.Request) {
	var req PushSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.EncryptedData) == "" {
		http.Error(w, `{"error":"Invalid or missing encrypted payload"}`, http.StatusBadRequest)
		return
	}

	ttl := 5 * time.Minute
	if req.TTLSeconds > 0 && req.TTLSeconds <= 3600 { // Max 1h
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	blob, err := h.Bridge.Store(req.EncryptedData, ttl)
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
