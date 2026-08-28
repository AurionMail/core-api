package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SecretBlob represents the encrypted secret container in RAM
type SecretBlob struct {
	ID            string    `json:"id"`
	EncryptedData string    `json:"encryptedData"` // The client-side encrypted payload
	ExpiresAt     time.Time `json:"expiresAt"`
	timer         *time.Timer
}

// LoginTokenBlob represents an unencrypted authentication token associated with a username
type LoginTokenBlob struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expiresAt"`
	timer     *time.Timer
}

type MemoryBridge struct {
	store sync.Map
}

func NewMemoryBridge() *MemoryBridge {
	return &MemoryBridge{}
}

// GenerateID generates a unique random identifier for the transfer session
func GenerateID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Store places the encrypted blob in RAM with a time-to-live (TTL)
func (b *MemoryBridge) Store(encryptedData string, ttl time.Duration, customID ...string) (*SecretBlob, error) {
	var id string
	var err error

	if len(customID) > 0 && customID[0] != "" {
		id = customID[0]
	} else {
		id, err = GenerateID()
		if err != nil {
			return nil, fmt.Errorf("error generating ID: %w", err)
		}
	}

	expiresAt := time.Now().UTC().Add(ttl)

	blob := &SecretBlob{
		ID:            id,
		EncryptedData: encryptedData,
		ExpiresAt:     expiresAt,
	}

	// Triggers automatic self-destruction after the TTL expires
	blob.timer = time.AfterFunc(ttl, func() {
		b.store.Delete(id)
	})

	b.store.Store(id, blob)
	return blob, nil
}

// Consume retrieves the secret and DELETES it immediately from RAM (Burn after reading)
func (b *MemoryBridge) Consume(id string) (*SecretBlob, bool) {
	value, ok := b.store.LoadAndDelete(id)
	if !ok {
		return nil, false
	}

	blob, ok := value.(*SecretBlob)
	if !ok {
		// Target element wasn't a SecretBlob (e.g. LoginTokenBlob)
		return nil, false
	}

	if blob.timer != nil {
		blob.timer.Stop() // Cancels the automatic expiration timer
	}

	// Safety check if the TTL has passed at the exact moment of reading
	if time.Now().UTC().After(blob.ExpiresAt) {
		return nil, false
	}

	return blob, true
}

// ============================================================================
// Login Token Methods
// ============================================================================

// StoreLoginToken places an unencrypted username/token payload in RAM with a TTL
func (b *MemoryBridge) StoreLoginToken(username, token string, ttl time.Duration) (*LoginTokenBlob, error) {
	var id string

	expiresAt := time.Now().UTC().Add(ttl)

	blob := &LoginTokenBlob{
		ID:        token, // Using the token itself as the ID for direct retrieval
		Username:  username,
		ExpiresAt: expiresAt,
	}

	blob.timer = time.AfterFunc(ttl, func() {
		b.store.Delete(id)
	})

	b.store.Store(id, blob)
	return blob, nil
}

// ConsumeLoginToken retrieves the login token and DELETES it immediately from RAM (Burn after reading)
func (b *MemoryBridge) ConsumeLoginToken(id string) (*LoginTokenBlob, bool) {
	value, ok := b.store.LoadAndDelete(id)
	if !ok {
		return nil, false
	}

	blob, ok := value.(*LoginTokenBlob)
	if !ok {
		// Target element wasn't a LoginTokenBlob (e.g. SecretBlob)
		return nil, false
	}

	if blob.timer != nil {
		blob.timer.Stop()
	}

	if time.Now().UTC().After(blob.ExpiresAt) {
		return nil, false
	}

	return blob, true
}
