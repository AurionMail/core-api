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
	MemoryCost  uint32 `json:"memoryCost,omitempty"`
	TimeCost    uint32 `json:"timeCost,omitempty"`
	Parallelism uint8  `json:"parallelism,omitempty"`
}

type WebAuthnData struct {
	CredentialId        string `json:"credentialId"`
	EncryptedPassphrase string `json:"encryptedPassphrase"`
	IV                  string `json:"iv"`
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
	Main                bool            `json:"main,omitempty"`
	Recovery            bool            `json:"recovery,omitempty"`
	Recoverable         bool            `json:"recoverable,omitempty"`
	AESSalt             string          `json:"aesSalt,omitempty"`
	Argon2Params        *Argon2Params   `json:"argon2Params,omitempty"`
	ServerSide          bool            `json:"serverSide,omitempty"`
}

type KeyCapabilities struct {
	CanSign    bool `json:"canSign"`
	CanEncrypt bool `json:"canEncrypt"`
}

type CachedMessage struct {
	ID               string `json:"id"`
	EncryptedPayload string `json:"encryptedPayload"`
	KeyRecordID      string `json:"keyRecordId"`
	IV               string `json:"iv"`
}
