package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func auditSigningConfig(t *testing.T, dir string) (config.AuditSigningConfig, string) {
	t.Helper()
	privatePath, publicPath, keyID := writeEd25519Fixture(t, dir)
	journalDir := filepath.Join(dir, "journal")
	return config.AuditSigningConfig{
		Enabled:         true,
		StreamID:        "control",
		JournalDir:      journalDir,
		SignerKeyID:     keyID,
		SignerKeyFile:   privatePath,
		Verifiers:       []config.AuditVerifierConfig{{KeyID: keyID, PublicKeyFile: publicPath}},
		CheckpointEvery: 1,
		QueueCapacity:   8,
	}, journalDir
}

func TestOpenAuditRuntimeSignsCheckpointsAndDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	cfg, journalDir := auditSigningConfig(t, dir)
	runtime, journal, err := openAuditRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || journal == nil {
		t.Fatal("enabled audit signing must compose a runtime and journal")
	}
	event := audit.Event{
		EventID:     "event-1",
		StreamID:    "control",
		TenantID:    "tenant-a",
		Actor:       "admin",
		Type:        audit.EventTypeConfigChanged,
		Action:      "POST",
		Resource:    "/api/users/u-1",
		Outcome:     audit.OutcomeSuccess,
		Class:       audit.EventClassCritical,
		At:          time.Unix(1700000000, 0).UTC(),
		PolicyEpoch: 7,
	}
	if _, err := runtime.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	streamPath := filepath.Join(journalDir, "control.jsonl")
	raw, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"signature"`) || !strings.Contains(string(raw), `"key_id"`) {
		t.Fatalf("stream has no signed checkpoint: %s", string(raw))
	}

	reopened, err := audit.OpenFileJournal(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := audit.NewRuntime(audit.RuntimeOptions{Journal: reopened, StreamID: "control", Signer: mustSigner(t, cfg), CheckpointEvery: 1}); err != nil {
		t.Fatalf("clean journal must reopen: %v", err)
	}

	tampered := append([]byte(nil), raw...)
	tampered[10] ^= 0xff
	if err := os.WriteFile(streamPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	broken, err := audit.OpenFileJournal(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	if _, err := audit.NewRuntime(audit.RuntimeOptions{Journal: broken, StreamID: "control", Signer: mustSigner(t, cfg), CheckpointEvery: 1}); err == nil {
		t.Fatal("tampered journal must fail to open")
	}
}

func mustSigner(t *testing.T, cfg config.AuditSigningConfig) audit.Signer {
	t.Helper()
	signer, _, err := loadAuditSigning(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
