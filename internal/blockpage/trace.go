package blockpage

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

var traceFallbackCounter uint64
var readTraceRandom = rand.Read

func NewTraceID() string {
	var buf [8]byte
	if _, err := readTraceRandom(buf[:]); err != nil {
		return "cw-" + time.Now().UTC().Format("20060102150405") + "-" + hex.EncodeToString(fallbackTraceCounterBytes())
	}
	return "cw-" + hex.EncodeToString(buf[:])
}

func fallbackTraceCounterBytes() []byte {
	var buf [8]byte
	value := atomic.AddUint64(&traceFallbackCounter, 1)
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i] = byte(value)
		value >>= 8
	}
	return buf[:]
}
