package models

import "time"

type VaultBackup struct {
	Format       string          `json:"format"`
	Version      int             `json:"version"`
	CreatedAt    time.Time       `json:"createdAt"`
	Keys         []PGPKey        `json:"keys"`
	MessageCache []CachedMessage `json:"messageCache"`
}

type Argon2Params struct {
	MemoryCost  uint32 `json:"memoryCost,omitempty"`  // ex: 65536
	TimeCost    uint32 `json:"timeCost,omitempty"`    // ex: 3
	Parallelism uint8  `json:"parallelism,omitempty"` // ex: 4
}

// WebAuthnData stocke les métadonnées de chiffrement liées à un passkey / WebAuthn
type WebAuthnData struct {
	CredentialId        string `json:"credentialId"`        // Stocké en Base64 dans le JSON/DB
	EncryptedPassphrase string `json:"encryptedPassphrase"` // Stocké en Base64 dans le JSON/DB
	IV                  string `json:"iv"`                  // Stocké en Base64 dans le JSON/DB
}

type PGPKey struct {
	ID                  string          `json:"id"`
	Email               string          `json:"email"`
	AccountId           *string         `json:"accountId,omitempty"`
	PublicKey           string          `json:"publicKey"`
	EncryptedPrivateKey string          `json:"encryptedPrivateKey"`
	Salt                string          `json:"salt"`
	IV                  string          `json:"iv"`
	KdfIterations       int             `json:"kdfIterations"`
	WebAuthn            *WebAuthnData   `json:"webauthn,omitempty"`
	Issuer              string          `json:"issuer"`
	Subject             string          `json:"subject"`
	SerialNumber        string          `json:"serialNumber"`
	NotBefore           time.Time       `json:"notBefore"`
	NotAfter            *time.Time      `json:"notAfter,omitempty"`
	Fingerprint         string          `json:"fingerprint"`
	Algorithm           string          `json:"algorithm"`
	Capabilities        KeyCapabilities `json:"capabilities"`
	Default             bool            `json:"default,omitempty"`
	Recovery            bool            `json:"recovery,omitempty"`
	Recoverable         bool            `json:"recoverable,omitempty"`
	AESSalt             string          `json:"aesSalt,omitempty"`
	Argon2Params        *Argon2Params   `json:"argon2Params,omitempty"`
}

type KeyCapabilities struct {
	CanSign    bool `json:"canSign"`
	CanEncrypt bool `json:"canEncrypt"`
}

type CachedMessage struct {
	ID               string `json:"id"`
	EncryptedPayload string `json:"encryptedPayload"`
	IV               string `json:"iv"`
}
