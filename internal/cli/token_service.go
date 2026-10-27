package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
	tokenspostgres "github.com/LaokeQwQ/CheeseWAF/internal/tokens/postgres"
	tokensservice "github.com/LaokeQwQ/CheeseWAF/internal/tokens/service"
)

// policyEpochSource adapts the serving process's current control-plane fencing
// generation to the token service. A zero epoch is a hard error: a token must
// never be issued or accepted against an unestablished policy epoch.
type policyEpochSource struct {
	read func() uint64
}

func (s policyEpochSource) CurrentEpoch(ctx context.Context, tenant string) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.read == nil {
		return 0, fmt.Errorf("token service: policy epoch source is not configured")
	}
	epoch := s.read()
	if epoch == 0 {
		return 0, fmt.Errorf("token service: policy epoch is not established for tenant %q", tenant)
	}
	return epoch, nil
}

type tokenServiceClock struct {
	clock timekeeper.Clock
}

func (c tokenServiceClock) Now() time.Time { return c.clock.Now() }

// openDurableTokenService opens the PostgreSQL-backed scoped token store and
// composes the token service over it. The returned closer closes the SQL store;
// it is nil when durable storage is not configured.
func openDurableTokenService(ctx context.Context, cfg config.ManagementAPITokenDurableConfig, readEpoch func() uint64) (*tokensservice.Service, io.Closer, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if env := strings.TrimSpace(cfg.DSNEnv); env != "" {
		dsn = strings.TrimSpace(os.Getenv(env))
		if dsn == "" {
			return nil, nil, fmt.Errorf("token service: environment variable %s is empty", env)
		}
	}
	if dsn == "" {
		return nil, nil, fmt.Errorf("token service: durable store DSN is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	openCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	store, err := tokenspostgres.Open(openCtx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("token service: %w", err)
	}
	if err := store.Migrate(openCtx); err != nil {
		_ = store.Close()
		return nil, nil, fmt.Errorf("token service: migrate: %w", err)
	}
	service, err := tokensservice.New(tokensservice.Config{
		Persistence: store,
		Clock:       tokenServiceClock{clock: timekeeper.SystemClock{}},
		Epochs:      policyEpochSource{read: readEpoch},
		LeaseID:     cfg.LeaseID,
	})
	if err != nil {
		_ = store.Close()
		return nil, nil, fmt.Errorf("token service: %w", err)
	}
	return service, store, nil
}
