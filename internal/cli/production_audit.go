package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const productionAuditStream = "management"

// productionAuditRuntime owns the database handle used by the audit journal.
// Closing the Runtime before the database preserves the journal's final flush.
type productionAuditRuntime struct {
	runtime *audit.Runtime
	db      *sql.DB
	once    sync.Once
	err     error
}

func (d *productionAuditRuntime) Append(ctx context.Context, event audit.Event) (audit.Record, error) {
	if d == nil || d.runtime == nil {
		return audit.Record{}, audit.ErrUnavailable
	}
	return d.runtime.Append(ctx, event)
}

// Durable reports whether the canonical journal is durable. The temporary
// network broker refuses a non-durable audit sink in production.
func (d *productionAuditRuntime) Durable() bool {
	return d != nil && d.runtime != nil && d.runtime.Durable()
}

func (d *productionAuditRuntime) Close() error {
	if d == nil {
		return nil
	}
	d.once.Do(func() {
		if d.runtime != nil {
			if err := d.runtime.Close(); err != nil {
				d.err = err
			}
		}
		if d.db != nil {
			if err := d.db.Close(); err != nil && d.err == nil {
				d.err = err
			}
		}
	})
	return d.err
}

// checkpointSeedFile persists the Ed25519 seed used to sign audit checkpoints.
// Losing it does not lose records, but new checkpoints would use a different
// key, so it lives beside the data directory and is created once with 0600.
const checkpointSeedFile = "checkpoint-ed25519.key"

// loadAuditCheckpointSigner loads or creates the durable checkpoint signer.
// Critical audit events refuse to append without a signer, so production must
// always provide one.
func loadAuditCheckpointSigner(dataDir string) (*audit.Ed25519Signer, error) {
	if strings.TrimSpace(dataDir) == "" || !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("audit checkpoint data directory must be absolute")
	}
	dir := filepath.Join(dataDir, "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create audit checkpoint directory: %w", err)
	}
	path := filepath.Join(dir, checkpointSeedFile)
	seed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("generate audit checkpoint seed: %w", err)
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, fmt.Errorf("persist audit checkpoint seed: %w", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure audit checkpoint seed: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read audit checkpoint seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("audit checkpoint seed must be %d bytes", ed25519.SeedSize)
	}
	return &audit.Ed25519Signer{ID: "checkpoint-ed25519", PrivateKey: ed25519.NewKeyFromSeed(seed)}, nil
}

func openProductionAudit(ctx context.Context, cfg config.ManagementPostgreSQLConfig, dataDir string) (ProductionAuditDependency, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("durable audit PostgreSQL DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open durable audit PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	closeDB := func(openErr error) (ProductionAuditDependency, error) {
		_ = db.Close()
		return nil, openErr
	}
	if err := db.PingContext(ctx); err != nil {
		return closeDB(fmt.Errorf("ping durable audit PostgreSQL: %w", err))
	}
	journal, err := audit.NewPostgresJournal(db)
	if err != nil {
		return closeDB(fmt.Errorf("create durable audit journal: %w", err))
	}
	if err := journal.Migrate(ctx); err != nil {
		return closeDB(fmt.Errorf("migrate durable audit journal: %w", err))
	}
	signer, err := loadAuditCheckpointSigner(dataDir)
	if err != nil {
		return closeDB(err)
	}
	runtime, err := audit.NewRuntime(audit.RuntimeOptions{
		Journal:       journal,
		StreamID:      productionAuditStream,
		QueueCapacity: 64,
		Signer:        signer,
	})
	if err != nil {
		return closeDB(fmt.Errorf("restore durable audit runtime: %w", err))
	}
	return &productionAuditRuntime{runtime: runtime, db: db}, nil
}
