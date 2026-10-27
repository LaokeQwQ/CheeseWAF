package migration

import (
	"testing"
	"time"
)

// A never-used passkey is written as an empty string. PostgreSQL declares
// last_used_at NOT NULL, so the migration must map it to the same epoch value
// the NULL branch uses instead of aborting on the first such row.
func TestPGSnapshotValuesUsesEpochForEmptyPasskeyLastUsed(t *testing.T) {
	table := snapshotTable{Name: "passkey_credentials", Columns: []string{"last_used_at"}}
	epoch := time.Unix(0, 0).UTC()

	for _, cell := range []snapshotCell{{Kind: "null"}, {Kind: "text", Text: ""}} {
		values, err := pgSnapshotValues(table, []snapshotCell{cell})
		if err != nil {
			t.Fatalf("snapshot values: %v", err)
		}
		got, ok := values[0].(time.Time)
		if !ok || !got.Equal(epoch) {
			t.Fatalf("last_used_at = %#v, want %s", values[0], epoch)
		}
	}

	// Another table's empty timestamp keeps its previous meaning: NULL.
	other := snapshotTable{Name: "users", Columns: []string{"last_login_at"}}
	values, err := pgSnapshotValues(other, []snapshotCell{{Kind: "text", Text: ""}})
	if err != nil {
		t.Fatalf("snapshot values: %v", err)
	}
	if values[0] != nil {
		t.Fatalf("users.last_login_at = %#v, want nil", values[0])
	}
}
