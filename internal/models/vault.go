package models

import "time"

type VaultBackup struct {
	Format       string          `json:"format"`
	Version      int             `json:"version"`
	CreatedAt    time.Time       `json:"createdAt"`
	Keys         []PGPKey        `json:"keys"`
	MessageCache []CachedMessage `json:"messageCache"`
}

type PGPKey struct {
	ID                  string          `json:"id"`
	Email               string          `json:"email"`
	PublicKey           string          `json:"publicKey"`
	EncryptedPrivateKey string          `json:"encryptedPrivateKey"`
	Salt                string          `json:"salt"`
	IV                  string          `json:"iv"`
	KdfIterations       int             `json:"kdfIterations"`
	Issuer              string          `json:"issuer"`
	Subject             string          `json:"subject"`
	SerialNumber        string          `json:"serialNumber"`
	NotBefore           time.Time       `json:"notBefore"`
	NotAfter            *time.Time      `json:"notAfter"`
	Fingerprint         string          `json:"fingerprint"`
	Algorithm           string          `json:"algorithm"`
	Capabilities        KeyCapabilities `json:"capabilities"`
	Default             bool            `json:"default"`
	AESSalt             string          `json:"aesSalt"`
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
