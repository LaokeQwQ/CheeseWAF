package cli

import (
	"context"
	"database/sql"
	"fmt"
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

func openProductionAudit(ctx context.Context, cfg config.ManagementPostgreSQLConfig) (ProductionAuditDependency, error) {
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
	runtime, err := audit.NewRuntime(audit.RuntimeOptions{
		Journal:       journal,
		StreamID:      productionAuditStream,
		QueueCapacity: 64,
	})
	if err != nil {
		return closeDB(fmt.Errorf("restore durable audit runtime: %w", err))
	}
	return &productionAuditRuntime{runtime: runtime, db: db}, nil
}
