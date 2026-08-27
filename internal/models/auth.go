package models

import (
	"time"

	"github.com/bytemare/opaque"
)

type OpaqueSession struct {
	UserID       string
	Email        string
	ServerOutput *opaque.ServerOutput
	ExpiresAt    time.Time
}
