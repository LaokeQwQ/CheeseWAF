package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDefaultStorageProfileIsTemporary(t *testing.T) {
	cfg := Default()
	if cfg.Storage.Profile != StorageProfileTemporary {
		t.Fatalf("storage profile = %q, want %q", cfg.Storage.Profile, StorageProfileTemporary)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("default temporary profile rejected: %v", err)
	}
}

func TestValidateStorageProfileRejectsUnknownValue(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = "durable-ish"

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "storage.profile must be temporary or production") {
		t.Fatalf("Validate() error = %v, want unknown profile rejection", err)
	}
}

func TestValidateProductionStorageRequiresManagementPostgreSQLDSN(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction

	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "storage.management_postgresql.dsn is required") {
		t.Fatalf("Validate() error = %v, want management PostgreSQL DSN requirement", err)
	}
}

func TestValidateProductionStorageRequiresIndependentControlPostgreSQLDSN(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/control"

	err := Validate(&cfg)
	if !errors.Is(err, ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "control_postgresql") {
		t.Fatalf("Validate() error = %v, want independent control PostgreSQL requirement", err)
	}
}

func TestValidateProductionStorageRequiresRedisAndExplicitNativeRaft(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/control"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Cluster.Consensus.NativeRaft.Mode = "bootstrap"
	cfg.Cluster.Consensus.NativeRaft.Listen = "127.0.0.1:9451"

	err := Validate(&cfg)
	if !errors.Is(err, ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "Redis") {
		t.Fatalf("Validate() error = %v, want Redis production requirement", err)
	}

	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"
	if err := Validate(&cfg); err != nil && !errors.Is(err, ErrProductionStorageUnavailable) {
		t.Fatalf("Validate() unexpectedly rejected production prerequisites: %v", err)
	}
}

func TestValidateProductionStorageRequiresRedisInstanceID(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/control"
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
	cfg.Cluster.ClusterID = "cluster-a"
	cfg.Storage.Redis.Enabled = true
	cfg.Storage.Redis.Address = "127.0.0.1:6379"

	err := Validate(&cfg)
	if !errors.Is(err, ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "instance_id") {
		t.Fatalf("Validate() error = %v, want Redis instance identity requirement", err)
	}
}

func TestValidateProductionStorageRejectsDirtyRedisInstanceID(t *testing.T) {
	for _, instanceID := range []string{"node a", " node-a", "node-a ", "node-\u200b"} {
		cfg := Default()
		cfg.Storage.Profile = StorageProfileProduction
		cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/control"
		cfg.Storage.ControlPostgreSQL.DSN = "postgres://control.example.invalid/control"
		cfg.Cluster.ClusterID = "cluster-a"
		cfg.Storage.Redis.Enabled = true
		cfg.Storage.Redis.Address = "127.0.0.1:6379"
		cfg.Storage.Redis.InstanceID = instanceID

		if err := Validate(&cfg); !errors.Is(err, ErrProductionStorageUnavailable) || !strings.Contains(err.Error(), "instance_id") {
			t.Fatalf("instance identity %q error=%v, want production identity rejection", instanceID, err)
		}
	}
}

func TestValidateProductionStorageFailsClosedUntilClusterEpochBackendIsReady(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://control.example.invalid/cheesewaf"

	err := Validate(&cfg)
	if !errors.Is(err, ErrProductionStorageUnavailable) {
		t.Fatalf("Validate() error = %v, want ErrProductionStorageUnavailable", err)
	}
	for _, text := range []string{"cluster/epoch", "native-raft", "refusing SQLite fallback"} {
		if !strings.Contains(err.Error(), text) {
			t.Fatalf("Validate() error = %q, want %q", err, text)
		}
	}
}

func TestValidateProductionStorageDocumentsNonInterchangeableStoreContracts(t *testing.T) {
	cfg := Default()
	cfg.Storage.Profile = StorageProfileProduction
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://control.example.invalid/cheesewaf"

	err := Validate(&cfg)
	if !errors.Is(err, ErrProductionStorageUnavailable) {
		t.Fatalf("Validate() error = %v, want ErrProductionStorageUnavailable", err)
	}
	for _, fragment := range []string{"storage.Store", "controlplane.DurableStore", "cannot satisfy", "one startup unit"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("Validate() error = %q, want fragment %q", err, fragment)
		}
	}
}

func TestManagementPostgreSQLConfigIsIndependentFromLogSink(t *testing.T) {
	cfg := Default()
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://management.example.invalid/control"
	cfg.Storage.PostgreSQL.DSN = "postgres://logs.example.invalid/access"

	if cfg.Storage.ManagementPostgreSQL.DSN == cfg.Storage.PostgreSQL.DSN {
		t.Fatal("management PostgreSQL DSN must not alias the asynchronous log sink DSN")
	}
}

func TestManagementPostgreSQLDSNIsNotExposedInJSONConfig(t *testing.T) {
	cfg := Default()
	cfg.Storage.ManagementPostgreSQL.DSN = "postgres://secret.example.invalid/control"
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret.example.invalid") || strings.Contains(string(data), "management_postgresql\":{\"dsn") {
		t.Fatalf("management DSN leaked through JSON config: %s", data)
	}
}

func TestControlPostgreSQLDSNIsNotExposedInJSONConfig(t *testing.T) {
	cfg := Default()
	cfg.Storage.ControlPostgreSQL.DSN = "postgres://control-secret.example.invalid/control"
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "control-secret.example.invalid") || strings.Contains(string(data), "control_postgresql\":{\"dsn") {
		t.Fatalf("control PostgreSQL DSN leaked through JSON config: %s", data)
	}
}
