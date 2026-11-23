package models

import "time"

type Tree struct {
	UserID           string    `json:"userId"`
	EncryptedPayload string    `json:"encryptedPayload"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type SaveTreeRequest struct {
	EncryptedPayload string `json:"encryptedPayload"`
}
