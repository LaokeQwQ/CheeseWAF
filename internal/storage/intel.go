package storage

import (
	"errors"

	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

// IntelStore returns the intel persistence adapter over this store's SQLite
// handle. The adapter shares the connection pool and the management schema.
func (s *SQLiteStore) IntelStore() (*intelstore.SQLiteStore, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("intelstore: sqlite store is not open")
	}
	return intelstore.NewSQLite(s.db)
}

type sqliteIntelStoreProvider interface {
	IntelStore() (*intelstore.SQLiteStore, error)
}

type postgresIntelStoreProvider interface {
	IntelStore() (*intelstore.PostgresStore, error)
}

// AsIntelStore exposes the intel persistence adapter for the concrete store in
// use. It returns an error for stores that do not implement intel persistence.
func AsIntelStore(store Store) (intelstore.Store, error) {
	switch provider := store.(type) {
	case sqliteIntelStoreProvider:
		return provider.IntelStore()
	case postgresIntelStoreProvider:
		return provider.IntelStore()
	default:
		return nil, errors.New("intelstore: store does not provide intel persistence")
	}
}
