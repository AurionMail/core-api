package models

import "time"

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"email"` // It is username in fact
	OpaqueRecord string    `json:"-"`
	WKDHash      string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	TokenVersion int       `json:"tokenVersion"`
}

type OpaqueRegisterInitRequest struct {
	RegistrationRequest string `json:"registrationRequest"` // Hex
}

type OpaqueRegisterInitResponse struct {
	RegistrationResponse string `json:"registrationResponse"` // Hex
}

type OpaqueRegisterFinalizeRequest struct {
	Email              string `json:"email"`
	RegistrationRecord string `json:"registrationRecord"` // Hex (opaqueRecord)
}

// Authentification OPAQUE (Étape 1)
type OpaqueChallengeRequest struct {
	Username          string `json:"username"`
	CredentialRequest string `json:"credentialRequest"` // Hex
}

type OpaqueChallengeResponse struct {
	SessionID          string `json:"sessionId"`
	CredentialResponse string `json:"credentialResponse"` // Hex
}

// Authentification OPAQUE (Étape 2)
type OpaqueVerifyRequest struct {
	SessionID              string `json:"sessionId"`
	CredentialFinalization string `json:"credentialFinalization"` // Hex
}

type OpaqueVerifyResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}
