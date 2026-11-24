package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"aurion-api/internal/db"
	"aurion-api/internal/middleware"
	"aurion-api/internal/models"

	"github.com/jackc/pgx/v5"
)

type VaultHandler struct {
	DB *db.DB
}

func NewVaultHandler(database *db.DB) *VaultHandler {
	return &VaultHandler{DB: database}
}

// GET /api/vault - Reconstructs the complete vault state for the user
func (h *VaultHandler) GetVault(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	backup := models.VaultBackup{
		MessageCache: []models.CachedMessage{},
		Keys:         []models.PGPKey{},
		PluginsData:  []models.PluginsData{},
	}

	var keysJSON []byte
	var updatedAt time.Time

	// 1. Retrieve the key block and metadata
	queryVault := `
        SELECT format, version, keys, updated_at 
        FROM user_vault 
        WHERE user_id = $1`

	err := h.DB.Pool.QueryRow(r.Context(), queryVault, userID).Scan(&backup.Format, &backup.Version, &keysJSON, &updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			backup.Format = "openpgp-plugin-backup"
			backup.Version = 7
			backup.CreatedAt = time.Now().UTC()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(backup)
			return
		}
		http.Error(w, `{"error":"Error reading vault"}`, http.StatusInternalServerError)
		return
	}

	backup.CreatedAt = updatedAt

	if len(keysJSON) > 0 {
		_ = json.Unmarshal(keysJSON, &backup.Keys)
	}

	// 2. Retrieve messages from the cache
	queryCache := `
        SELECT message_id, encrypted_payload, iv 
        FROM user_message_cache 
        WHERE user_id = $1`

	cacheRows, err := h.DB.Pool.Query(r.Context(), queryCache, userID)
	if err != nil {
		http.Error(w, `{"error":"Error reading message cache"}`, http.StatusInternalServerError)
		return
	}
	for cacheRows.Next() {
		var msg models.CachedMessage
		if err := cacheRows.Scan(&msg.ID, &msg.EncryptedPayload, &msg.IV); err != nil {
			cacheRows.Close()
			http.Error(w, `{"error":"Error scanning message cache"}`, http.StatusInternalServerError)
			return
		}
		backup.MessageCache = append(backup.MessageCache, msg)
	}
	if err := cacheRows.Err(); err != nil {
		cacheRows.Close()
		http.Error(w, `{"error":"Error iterating message cache"}`, http.StatusInternalServerError)
		return
	}
	cacheRows.Close()

	// 3. Retrieve plugins data
	queryPluginsData := `
        SELECT plugin_id, encrypted_payload
        FROM user_plugins_data 
        WHERE user_id = $1`

	pluginRows, err := h.DB.Pool.Query(r.Context(), queryPluginsData, userID)
	if err != nil {
		http.Error(w, `{"error":"Error reading plugins data"}`, http.StatusInternalServerError)
		return
	}
	for pluginRows.Next() {
		var item models.PluginsData
		var payload []byte
		if err := pluginRows.Scan(&item.ID, &payload); err != nil {
			pluginRows.Close()
			http.Error(w, `{"error":"Error scanning plugins data"}`, http.StatusInternalServerError)
			return
		}
		if len(payload) > 0 {
			item.Data = json.RawMessage(payload)
		} else {
			item.Data = json.RawMessage(`{}`)
		}
		backup.PluginsData = append(backup.PluginsData, item)
	}
	if err := pluginRows.Err(); err != nil {
		pluginRows.Close()
		http.Error(w, `{"error":"Error iterating plugins data"}`, http.StatusInternalServerError)
		return
	}
	pluginRows.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(backup)
}

// POST /api/vault - Ultra-fast synchronization via PGX Batching
func (h *VaultHandler) SyncVault(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	var payload models.VaultBackup
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	tx, err := h.DB.Pool.Begin(r.Context())
	if err != nil {
		http.Error(w, `{"error":"Server transaction error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// 1. Save/Update PGP keys vault
	if len(payload.Keys) > 0 {
		keysJSON, err := json.Marshal(payload.Keys)
		if err != nil {
			http.Error(w, `{"error":"Key serialization error"}`, http.StatusInternalServerError)
			return
		}

		queryVault := `
			INSERT INTO user_vault (user_id, format, version, keys, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (user_id) 
			DO UPDATE SET format = EXCLUDED.format, version = EXCLUDED.version, keys = EXCLUDED.keys, updated_at = NOW()`

		_, err = tx.Exec(r.Context(), queryVault, userID, payload.Format, payload.Version, keysJSON)
		if err != nil {
			http.Error(w, `{"error":"Error saving vault"}`, http.StatusInternalServerError)
			return
		}
	}

	// 2. Batching for message cache (PGX network optimization)
	if len(payload.MessageCache) > 0 {
		batch := &pgx.Batch{}
		queryCache := `
            INSERT INTO user_message_cache (user_id, message_id, encrypted_payload, iv, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (user_id, message_id) 
            DO UPDATE SET encrypted_payload = EXCLUDED.encrypted_payload, iv = EXCLUDED.iv, updated_at = NOW()`

		for _, msg := range payload.MessageCache {
			batch.Queue(queryCache, userID, msg.ID, msg.EncryptedPayload, msg.IV)
		}

		br := tx.SendBatch(r.Context(), batch)
		for range payload.MessageCache {
			if _, err := br.Exec(); err != nil {
				br.Close()
				http.Error(w, `{"error":"Error processing message cache"}`, http.StatusInternalServerError)
				return
			}
		}
		if err := br.Close(); err != nil {
			http.Error(w, `{"error":"Error closing message cache batch"}`, http.StatusInternalServerError)
			return
		}
	}

	// 3. Batching for plugins data
	if len(payload.PluginsData) > 0 {
		batch := &pgx.Batch{}
		queryPlugin := `
            INSERT INTO user_plugins_data (user_id, plugin_id, encrypted_payload, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id, plugin_id) 
            DO UPDATE SET user_id = EXCLUDED.user_id, encrypted_payload = EXCLUDED.encrypted_payload, updated_at = NOW()`

		for _, item := range payload.PluginsData {
			rawData := item.Data
			if len(rawData) == 0 {
				rawData = json.RawMessage(`{}`)
			} else if !json.Valid(rawData) {
				http.Error(w, `{"error":"Invalid JSON in plugin data"}`, http.StatusBadRequest)
				return
			}
			batch.Queue(queryPlugin, userID, item.ID, []byte(rawData))
		}

		br := tx.SendBatch(r.Context(), batch)
		for range payload.PluginsData {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				http.Error(w, `{"error":"Error processing plugins data"}`, http.StatusInternalServerError)
				return
			}
		}
		if err := br.Close(); err != nil {
			http.Error(w, `{"error":"Error closing plugins data batch"}`, http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, `{"error":"Error committing data"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"synced"}`))
}

type DeleteCacheRequest struct {
	MessageIDs []string `json:"message_ids"`
}

// DELETE /api/vault/cache/messages
func (h *VaultHandler) DeleteCachedMessages(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	var req DeleteCacheRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON format"}`, http.StatusBadRequest)
		return
	}

	if len(req.MessageIDs) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"deleted","deleted":0}`))
		return
	}

	query := `
        DELETE FROM user_message_cache 
        WHERE user_id = $1 AND message_id = ANY($2)`

	tag, err := h.DB.Pool.Exec(r.Context(), query, userID, req.MessageIDs)
	if err != nil {
		http.Error(w, `{"error":"Error deleting cached messages"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "deleted",
		"deleted": tag.RowsAffected(),
	})
}

// DELETE /api/vault/cache
func (h *VaultHandler) ClearMessageCache(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, `{"error":"Unidentified user"}`, http.StatusUnauthorized)
		return
	}

	query := `DELETE FROM user_message_cache WHERE user_id = $1`

	tag, err := h.DB.Pool.Exec(r.Context(), query, userID)
	if err != nil {
		http.Error(w, `{"error":"Error clearing message cache"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "cleared",
		"deleted": tag.RowsAffected(),
	})
}
