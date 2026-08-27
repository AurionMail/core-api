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
