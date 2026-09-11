package cli

import "testing"

func TestRootRegistersTemporaryToProductionMigration(t *testing.T) {
	root := newRootCommand()
	command, _, err := root.Find([]string{"migration", "temporary-to-production"})
	if err != nil {
		t.Fatalf("find migration command: %v", err)
	}
	if command == nil || command.Use != "temporary-to-production" {
		t.Fatalf("migration command=%v", command)
	}
	recover, _, err := root.Find([]string{"migration", "recover"})
	if err != nil || recover == nil || recover.Use != "recover" {
		t.Fatalf("migration recovery command=%v err=%v", recover, err)
	}
}
