package domain

import (
	"bytes"
	"encoding/binary"
	"time"
	"uuid"
)

type Log struct {
	LogID uuid.UUID

	EventTime time.Time
	RegionID  string
	TenantID  string
	ServiceID string
	LogType   string

	Ciphertext []byte
	Tag        []byte
	Nonce      []byte
	Digest     [32]byte
	AD         []byte
}

func writeString(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.BigEndian, uint32(len(s)))
	buf.WriteString(s)
}

func EncodeAD(log *Log) []byte {
	var buf bytes.Buffer

	writeString(&buf, log.TenantID)
	writeString(&buf, log.ServiceID)
	writeString(&buf, log.LogType)
	writeString(&buf, log.RegionID)

	//timestamp
	binary.Write(
		&buf, binary.BigEndian, log.EventTime.UnixNano(),
	)

	buf.Write(log.LogID[:])

	return buf.Bytes()
}
