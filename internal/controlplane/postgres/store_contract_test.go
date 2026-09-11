package postgres

import (
	"reflect"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestStoreDoesNotPretendToBeManagementStore(t *testing.T) {
	concrete := reflect.TypeOf((*Store)(nil))
	durable := reflect.TypeOf((*controlplane.DurableStore)(nil)).Elem()
	durableBootstrap := reflect.TypeOf((*controlplane.DurableBootstrap)(nil)).Elem()
	management := reflect.TypeOf((*storage.Store)(nil)).Elem()

	if !concrete.Implements(durable) {
		t.Fatal("control-plane PostgreSQL store must implement controlplane.DurableStore")
	}
	if !concrete.Implements(durableBootstrap) {
		t.Fatal("control-plane PostgreSQL store must implement controlplane.DurableBootstrap")
	}
	if got := (&Store{}).Backend(); got != "postgresql" {
		t.Fatalf("Backend()=%q, want postgresql", got)
	}
	if concrete.Implements(management) {
		t.Fatal("control-plane PostgreSQL store must not be treated as storage.Store")
	}
}
