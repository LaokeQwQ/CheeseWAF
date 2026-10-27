package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// openAuditRuntime composes the durable audit journal, the Ed25519 signer, and
// the audit worker owned by the serving process. Both returned values are
// nil when audit signing is disabled. The caller owns Close on both; the
// runtime must be closed before the journal so pending appends are flushed.
func openAuditRuntime(cfg config.AuditSigningConfig) (*audit.Runtime, *audit.FileJournal, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	journal, err := audit.OpenFileJournal(cfg.JournalDir)
	if err != nil {
		return nil, nil, fmt.Errorf("audit signing: %w", err)
	}
	signer, verifiers, err := loadAuditSigning(cfg)
	if err != nil {
		_ = journal.Close()
		return nil, nil, err
	}
	runtime, err := audit.NewRuntime(audit.RuntimeOptions{
		Journal:         journal,
		Signer:          signer,
		Verifiers:       verifiers,
		StreamID:        cfg.StreamID,
		QueueCapacity:   cfg.QueueCapacity,
		CheckpointEvery: cfg.CheckpointEvery,
	})
	if err != nil {
		_ = journal.Close()
		return nil, nil, fmt.Errorf("audit signing: %w", err)
	}
	return runtime, journal, nil
}
