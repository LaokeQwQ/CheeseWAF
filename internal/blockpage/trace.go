package blockpage

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func NewTraceID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "cw-" + time.Now().UTC().Format("20060102150405")
	}
	return "cw-" + hex.EncodeToString(buf[:])
}
