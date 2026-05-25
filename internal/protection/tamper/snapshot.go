package tamper

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Snapshot struct {
	URL        string    `json:"url"`
	Hash       string    `json:"hash"`
	Size       int       `json:"size"`
	CapturedAt time.Time `json:"captured_at"`
}

type Drift struct {
	URL      string `json:"url"`
	Changed  bool   `json:"changed"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

func Capture(url string, body []byte, now time.Time) Snapshot {
	sum := sha256.Sum256(body)
	return Snapshot{
		URL:        url,
		Hash:       hex.EncodeToString(sum[:]),
		Size:       len(body),
		CapturedAt: now.UTC(),
	}
}

func Compare(snapshot Snapshot, body []byte) Drift {
	actual := Capture(snapshot.URL, body, time.Now()).Hash
	return Drift{
		URL:      snapshot.URL,
		Changed:  snapshot.Hash != actual,
		Expected: snapshot.Hash,
		Actual:   actual,
	}
}
