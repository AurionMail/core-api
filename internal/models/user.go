package models

import "time"

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"email"` // It is username in fact
	SRPVerifier  string    `json:"-"`     // TODO migration
	SRPSalt      string    `json:"-"`     // TODO migrations
	WKDHash      string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	TokenVersion int       `json:"tokenVersion"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type SRPChallengeRequest struct {
	Username string `json:"username"`
	A        string `json:"a"` // client pub key (Hex)
}

type SRPChallengeResponse struct {
	SessionID string `json:"sessionId"` // temp ID for step 2
	Salt      string `json:"salt"`      // user salt (Hex)
	B         string `json:"b"`         // pub key server (Hex)
}

type SRPVerifyRequest struct {
	SessionID string `json:"sessionId"`
	M1        string `json:"m1"` // client proof
}

type SRPVerifyResponse struct {
	Token string `json:"token"`
	M2    string `json:"m2"` // server proof
	User  User   `json:"user"`
}
