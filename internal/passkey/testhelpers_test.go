package passkey

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: testNow}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(duration)
}

func newTestService(t *testing.T, store Store, clock *testClock) *Service {
	t.Helper()

	config := validConfig()
	config.ChallengeTTL = 2 * time.Minute

	service, err := NewService(config, Options{
		Store:      store,
		SessionKey: bytes.Repeat([]byte{0x42}, MinSessionKeyLen),
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

func testCredential(userID string, seed byte) *Credential {
	credentialID := bytes.Repeat([]byte{seed, 0x11, 0x22, 0x33}, 5)

	return &Credential{
		ID:             hex.EncodeToString(credentialID),
		UserID:         userID,
		CredentialID:   credentialID,
		PublicKey:      []byte{0xa1, 0x01, 0x03, 0x26},
		SignCount:      0,
		Transports:     []string{"internal"},
		AAGUID:         bytes.Repeat([]byte{seed}, 16),
		BackupEligible: false,
		CreatedAt:      testNow,
		Name:           "Test Passkey",
	}
}
