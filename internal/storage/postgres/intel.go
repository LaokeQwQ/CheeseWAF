package postgres

import (
	"errors"

	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

// IntelStore returns the intel persistence adapter over this store's PostgreSQL
// handle. The adapter shares the connection pool and the management schema.
func (s *Store) IntelStore() (*intelstore.PostgresStore, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("intelstore: postgres store is not open")
	}
	return intelstore.NewPostgres(s.db)
}
