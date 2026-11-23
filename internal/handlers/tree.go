package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"

	"github.com/jackc/pgx/v5"
)

type TreeHandler struct {
	DB *db.DB
}

func NewTreeHandler(database *db.DB) *TreeHandler {
	return &TreeHandler{DB: database}
}

// GET /api/vault/tree
func (h *TreeHandler) GetTree(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	query := `
		SELECT user_id, encrypted_payload, created_at, updated_at
		FROM user_tree
		WHERE user_id = $1`

	var tree models.Tree
	err := h.DB.Pool.QueryRow(r.Context(), query, userID).Scan(
		&tree.UserID,
		&tree.EncryptedPayload,
		&tree.CreatedAt,
		&tree.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, `{"error":"Tree not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Error reading tree"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tree)
}

// POST /api/vault/tree
func (h *TreeHandler) SaveTree(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	var req models.SaveTreeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.EncryptedPayload) == "" {
		http.Error(w, `{"error":"encryptedPayload is required"}`, http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO user_tree (user_id, encrypted_payload, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (user_id)
		DO UPDATE SET
			encrypted_payload = EXCLUDED.encrypted_payload,
			updated_at = NOW()
		RETURNING user_id, encrypted_payload, created_at, updated_at`

	var tree models.Tree
	err := h.DB.Pool.QueryRow(r.Context(), query, userID, req.EncryptedPayload).Scan(
		&tree.UserID,
		&tree.EncryptedPayload,
		&tree.CreatedAt,
		&tree.UpdatedAt,
	)
	if err != nil {
		http.Error(w, `{"error":"Error saving tree"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tree)
}

// DELETE /api/vault/tree
func (h *TreeHandler) DeleteTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	query := `DELETE FROM user_tree WHERE user_id = $1`

	tag, err := h.DB.Pool.Exec(r.Context(), query, userID)
	if err != nil {
		http.Error(w, `{"error":"Error deleting tree"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "deleted",
		"deleted": tag.RowsAffected(),
	})
}
