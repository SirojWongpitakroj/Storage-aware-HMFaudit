package domain

import (
	"time"
	"uuid"
)

type Log struct {
	LogID uuid.UUID `json:"logID"`

	EventTime time.Time `json:"event_time"`
	RegionID  string    `json:"region_id"`
	TenantID  string    `json:"tenant_id"`
	ServiceID string    `json:"service_id"`
	LogType   string    `json:"log_type"`

	Ciphertext []byte
	Tag        []byte
	nonce      []byte
	digest     [32]byte
}
