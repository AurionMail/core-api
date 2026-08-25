package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"aurion-api/internal/db"
	"aurion-api/internal/models"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/go-chi/chi/v5"
)

type WKSHandler struct {
	db *db.DB
}

func NewWKSHandler(database *db.DB) *WKSHandler {
	return &WKSHandler{db: database}
}

func (h *WKSHandler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	hash := chi.URLParam(r, "hash")
	if hash == "" {
		http.Error(w, `{"error":"Missing hash"}`, http.StatusBadRequest)
		return
	}

	query := `
		SELECT v.keys 
		FROM user_vault v
		JOIN users u ON u.id = v.user_id
		WHERE u.wkd_hash = $1`

	var keysData []byte
	err := h.db.Pool.QueryRow(r.Context(), query, hash).Scan(&keysData)
	if err != nil {
		http.Error(w, `{"error":"Key not found"}`, http.StatusNotFound)
		return
	}

	var keys []models.PGPKey
	if err := json.Unmarshal(keysData, &keys); err != nil {
		http.Error(w, `{"error":"Internal error parsing keys"}`, http.StatusInternalServerError)
		return
	}

	var targetKey *models.PGPKey
	for i := range keys {
		key := &keys[i]
		if key.Main {
			targetKey = key
			break
		}
		if targetKey == nil {
			targetKey = key
		}
	}

	if targetKey == nil || targetKey.PublicKey == "" {
		http.Error(w, `{"error":"Key not found"}`, http.StatusNotFound)
		return
	}

	pubKeyData := targetKey.PublicKey

	w.Header().Set("Content-Type", "application/octet-stream")

	if strings.Contains(pubKeyData, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		block, err := armor.Decode(strings.NewReader(pubKeyData))
		if err == nil {
			rawBytes, readErr := io.ReadAll(block.Body)
			if readErr == nil {
				http.ServeContent(w, r, "", targetKey.NotBefore, bytes.NewReader(rawBytes))
				return
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pubKeyData))
}
