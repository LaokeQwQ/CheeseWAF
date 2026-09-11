package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"gopkg.in/yaml.v3"
)

const (
	managementSnapshotVersion      = 1
	supportedSQLiteSchemaVersion   = 5
	securityArtifactSnapshotMaxLen = 32 << 20
)

type managementSnapshot struct {
	Version             int             `json:"version"`
	SQLiteSchemaVersion int             `json:"sqlite_schema_version"`
	Tables              []snapshotTable `json:"tables"`
	ConfigFile          fileSnapshot    `json:"config_file"`
	SetupURL            fileSnapshot    `json:"setup_url"`
	ClusterIdentity     fileSnapshot    `json:"cluster_identity"`
}

type snapshotTable struct {
	Name    string           `json:"name"`
	Columns []string         `json:"columns"`
	Rows    [][]snapshotCell `json:"rows"`
}

type snapshotCell struct {
	Kind    string  `json:"kind"`
	Text    string  `json:"text,omitempty"`
	Integer int64   `json:"integer,omitempty"`
	Real    float64 `json:"real,omitempty"`
	Blob    []byte  `json:"blob,omitempty"`
}

type fileSnapshot struct {
	Exists bool        `json:"exists"`
	Mode   os.FileMode `json:"mode,omitempty"`
	Data   []byte      `json:"data,omitempty"`
}

type managementTableSpec struct {
	name       string
	columns    []string
	orderBy    []string
	importToPG bool
	booleans   map[string]bool
	nullEmpty  map[string]bool
}

var managementTableSpecs = []managementTableSpec{
	{name: "sites", columns: []string{"id", "name", "domains", "upstreams", "listen_port", "loadbalance", "enable_ssl", "cert_file", "key_file", "waf_enabled", "waf_mode", "paranoia_level", "advanced", "enabled", "created_at", "updated_at"}, orderBy: []string{"id"}, importToPG: true, booleans: stringSet("enable_ssl", "waf_enabled", "enabled")},
	{name: "rules", columns: []string{"id", "site_id", "name", "description", "pattern", "location", "action", "severity", "enabled", "priority"}, orderBy: []string{"id"}, importToPG: true, booleans: stringSet("enabled")},
	{name: "users", columns: []string{"id", "username", "password_hash", "role", "two_fa_enabled", "two_fa_secret", "created_at", "updated_at", "credential_epoch"}, orderBy: []string{"id"}, importToPG: true, booleans: stringSet("two_fa_enabled")},
	{name: "admin_sessions", columns: []string{"id", "user_id", "username", "role", "issued_at", "expires_at", "revoked_at", "created_at", "updated_at", "credential_epoch"}, orderBy: []string{"id"}},
	{name: "notifications", columns: []string{"id", "user_id", "type", "title", "message", "target", "is_read", "is_pinned", "created_at", "updated_at"}, orderBy: []string{"id"}, importToPG: true, booleans: stringSet("is_read", "is_pinned")},
	{name: "review_items", columns: []string{"id", "trace_id", "site_id", "client_ip", "method", "uri", "category", "severity", "payload", "protection_level", "shape", "source", "param_name", "fingerprint", "status", "ai_verdict", "decided_by_subject", "decided_by_name", "decided_by_role", "decided_at", "decision", "applied_rule_id", "decision_claim", "created_at"}, orderBy: []string{"id"}, importToPG: true, nullEmpty: stringSet("decided_at")},
	{name: "site_promotes", columns: []string{"site_id", "until_at"}, orderBy: []string{"site_id"}, importToPG: true},
	{name: "totp_consumed", columns: []string{"user_id", "counter", "expires_at", "created_at"}, orderBy: []string{"user_id", "counter"}, importToPG: true},
	{name: "user_username_repairs", columns: []string{"id", "user_id", "old_username", "new_username", "actor", "reason", "revoked_sessions", "created_at"}, orderBy: []string{"id"}, importToPG: true},
}

type runtimeTemporarySource struct {
	db               *sql.DB
	profile          string
	configPath       string
	dataDir          string
	expectedDigest   string
	candidate        []byte
	candidateDigest  string
	initialState     []byte
	actor            string
	confirmationID   string
	clusterID        string
	initialStateHash string
	now              func() time.Time
	mu               sync.Mutex
	currentSnapshot  setupmigration.Snapshot
}

func (s *runtimeTemporarySource) Profile(context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", setupmigration.ErrSourceUnavailable
	}
	return s.profile, nil
}

func (s *runtimeTemporarySource) Snapshot(ctx context.Context) (setupmigration.Snapshot, error) {
	if s == nil || s.db == nil || s.configPath == "" || s.dataDir == "" {
		return setupmigration.Snapshot{}, setupmigration.ErrSourceUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	configFile, err := captureFile(s.configPath)
	if err != nil || !configFile.Exists {
		return setupmigration.Snapshot{}, fmt.Errorf("capture runtime configuration: %w", err)
	}
	configDigest := digestBytes(configFile.Data)
	if configDigest != s.expectedDigest {
		return setupmigration.Snapshot{}, errors.New("runtime configuration changed after authorization")
	}
	setupURL, err := captureFile(filepath.Join(s.dataDir, setup.URLFileName))
	if err != nil {
		return setupmigration.Snapshot{}, fmt.Errorf("capture setup URL state: %w", err)
	}
	clusterIdentity, err := captureFile(filepath.Join(s.dataDir, "cluster", "identity.json"))
	if err != nil {
		return setupmigration.Snapshot{}, fmt.Errorf("capture cluster identity state: %w", err)
	}
	databaseState, err := captureManagementTables(ctx, s.db)
	if err != nil {
		return setupmigration.Snapshot{}, err
	}
	databaseState.ConfigFile = configFile
	databaseState.SetupURL = setupURL
	databaseState.ClusterIdentity = clusterIdentity
	raw, err := json.Marshal(databaseState)
	if err != nil {
		return setupmigration.Snapshot{}, err
	}
	legacyTokens, err := legacyTokenSnapshotFromConfigFile(configFile.Data)
	if err != nil {
		return setupmigration.Snapshot{}, err
	}
	tokens, err := json.Marshal(legacyTokens)
	if err != nil {
		return setupmigration.Snapshot{}, err
	}
	sum := sha256.New()
	_, _ = sum.Write(raw)
	_, _ = sum.Write(tokens)
	_, _ = sum.Write([]byte(configDigest))
	snapshotID := "snapshot-" + hex.EncodeToString(sum.Sum(nil)[:16])
	snapshot := setupmigration.Snapshot{ID: snapshotID, ConfigDigest: configDigest, ManagementState: raw, TokenMetadata: tokens}
	s.mu.Lock()
	s.currentSnapshot = cloneMigrationSnapshot(snapshot)
	s.mu.Unlock()
	return snapshot, nil
}

func (s *runtimeTemporarySource) InvalidateTemporaryState(ctx context.Context) (setupmigration.InvalidationReceipt, error) {
	if s == nil || s.db == nil {
		return setupmigration.InvalidationReceipt{}, setupmigration.ErrSourceUnavailable
	}
	s.mu.Lock()
	snapshot := cloneMigrationSnapshot(s.currentSnapshot)
	s.mu.Unlock()
	if snapshot.ID == "" {
		return setupmigration.InvalidationReceipt{}, errors.New("temporary snapshot is unavailable")
	}
	now := runtimeNow(s.now)
	record := recoveryRecord{
		Version:          recoveryRecordVersion,
		Snapshot:         snapshot,
		Candidate:        append([]byte(nil), s.candidate...),
		CandidateDigest:  s.candidateDigest,
		InitialState:     append([]byte(nil), s.initialState...),
		Actor:            s.actor,
		ConfirmationID:   s.confirmationID,
		ClusterID:        s.clusterID,
		InitialStateHash: s.initialStateHash,
		CreatedAt:        now,
	}
	if err := prepareCutoverArtifacts(s.dataDir, record, now); err != nil {
		return setupmigration.InvalidationReceipt{}, err
	}
	receipt := setupmigration.InvalidationReceipt{}
	if err := invalidateSQLiteSecurityState(ctx, s.db, now); err != nil {
		return receipt, err
	}
	receipt.Sessions = true
	if err := setup.RemoveURL(s.dataDir); err != nil {
		return receipt, err
	}
	receipt.Setup = true
	if err := revokePersistedJoinTokens(filepath.Join(s.dataDir, "cluster", "identity.json")); err != nil {
		return receipt, err
	}
	receipt.Join = true
	// The root-held PID lease proves no service process owns the in-memory
	// CAPTCHA receipt or lock registries while this adapter runs.
	receipt.CAPTCHA = true
	receipt.Locks = true
	return receipt, nil
}

func (s *runtimeTemporarySource) RestoreTemporaryState(ctx context.Context, snapshot setupmigration.Snapshot, _ setupmigration.InvalidationReceipt) error {
	if s == nil || s.db == nil {
		return setupmigration.ErrRollbackFailed
	}
	s.mu.Lock()
	expectedID := s.currentSnapshot.ID
	s.mu.Unlock()
	if snapshot.ID == "" || snapshot.ID != expectedID || snapshot.ConfigDigest != s.expectedDigest {
		return setupmigration.ErrRollbackFailed
	}
	state, err := decodeManagementSnapshot(snapshot.ManagementState)
	if err != nil {
		return err
	}
	if err := restoreSQLiteSecurityState(ctx, s.db, state); err != nil {
		return err
	}
	if err := restoreFile(s.configPath, state.ConfigFile); err != nil {
		return err
	}
	if err := restoreFile(filepath.Join(s.dataDir, setup.URLFileName), state.SetupURL); err != nil {
		return err
	}
	if err := restoreFile(filepath.Join(s.dataDir, "cluster", "identity.json"), state.ClusterIdentity); err != nil {
		return err
	}
	return removeCutoverArtifacts(s.dataDir, snapshot.ID, false)
}

func cloneMigrationSnapshot(snapshot setupmigration.Snapshot) setupmigration.Snapshot {
	snapshot.ManagementState = append([]byte(nil), snapshot.ManagementState...)
	snapshot.TokenMetadata = append([]byte(nil), snapshot.TokenMetadata...)
	return snapshot
}

func captureManagementTables(ctx context.Context, db *sql.DB) (managementSnapshot, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return managementSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var schemaVersion int
	if err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		return managementSnapshot{}, err
	}
	if schemaVersion != supportedSQLiteSchemaVersion {
		return managementSnapshot{}, fmt.Errorf("unsupported SQLite schema version %d", schemaVersion)
	}
	state := managementSnapshot{Version: managementSnapshotVersion, SQLiteSchemaVersion: schemaVersion, Tables: make([]snapshotTable, 0, len(managementTableSpecs))}
	for _, spec := range managementTableSpecs {
		table, err := captureTable(ctx, tx, spec)
		if err != nil {
			return managementSnapshot{}, fmt.Errorf("capture %s: %w", spec.name, err)
		}
		state.Tables = append(state.Tables, table)
	}
	if err := tx.Commit(); err != nil {
		return managementSnapshot{}, err
	}
	return state, nil
}

func captureTable(ctx context.Context, tx *sql.Tx, spec managementTableSpec) (snapshotTable, error) {
	query := "SELECT " + strings.Join(spec.columns, ",") + " FROM " + spec.name
	if len(spec.orderBy) > 0 {
		query += " ORDER BY " + strings.Join(spec.orderBy, ",")
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return snapshotTable{}, err
	}
	defer rows.Close()
	table := snapshotTable{Name: spec.name, Columns: append([]string(nil), spec.columns...)}
	for rows.Next() {
		values := make([]any, len(spec.columns))
		destinations := make([]any, len(values))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			return snapshotTable{}, err
		}
		row := make([]snapshotCell, len(values))
		for i, value := range values {
			cell, err := encodeSnapshotCell(value)
			if err != nil {
				return snapshotTable{}, err
			}
			row[i] = cell
		}
		table.Rows = append(table.Rows, row)
	}
	return table, rows.Err()
}

// productionManagementMatchesSnapshot verifies the durable management state
// independently of the cutover ledger. The ledger proves the import
// transaction committed; this comparison proves the imported rows still match
// the recovery snapshot before a production configuration can be published.
func productionManagementMatchesSnapshot(ctx context.Context, db *sql.DB, raw []byte) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil {
		return false, ErrCutoverAmbiguous
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	matches, err := productionManagementMatchesSnapshotTx(ctx, tx, raw)
	if err != nil || !matches {
		return matches, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func productionManagementMatchesSnapshotTx(ctx context.Context, tx *sql.Tx, raw []byte) (bool, error) {
	if tx == nil {
		return false, ErrCutoverAmbiguous
	}
	state, err := decodeManagementSnapshot(raw)
	if err != nil {
		return false, err
	}
	for _, table := range state.Tables {
		spec, ok := managementSpec(table.Name)
		if !ok || !spec.importToPG {
			continue
		}
		query := "SELECT " + strings.Join(spec.columns, ",") + " FROM " + spec.name
		if len(spec.orderBy) > 0 {
			query += " ORDER BY " + strings.Join(spec.orderBy, ",")
		}
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return false, err
		}
		rowIndex := 0
		matches := true
		for rows.Next() {
			if rowIndex >= len(table.Rows) {
				matches = false
				err = fmt.Errorf("production management snapshot has extra %s row", table.Name)
				break
			}
			actualValues := make([]any, len(spec.columns))
			destinations := make([]any, len(actualValues))
			for index := range actualValues {
				destinations[index] = &actualValues[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				return false, err
			}
			expectedValues, err := expectedProductionValues(table, table.Rows[rowIndex])
			if err != nil {
				_ = rows.Close()
				return false, err
			}
			for index, column := range spec.columns {
				expected, err := canonicalProductionValue(column, expectedValues[index])
				if err != nil {
					_ = rows.Close()
					return false, err
				}
				actual, err := canonicalProductionValue(column, actualValues[index])
				if err != nil {
					_ = rows.Close()
					return false, err
				}
				if !reflect.DeepEqual(actual, expected) {
					matches = false
					err = fmt.Errorf("production management snapshot differs at %s row %d column %s", table.Name, rowIndex, column)
					break
				}
			}
			if !matches {
				break
			}
			rowIndex++
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		if rowsErr != nil {
			return false, rowsErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		if !matches {
			return false, err
		}
		if rowIndex != len(table.Rows) {
			return false, fmt.Errorf("production management snapshot is missing %s rows", table.Name)
		}
	}
	return true, nil
}

func expectedProductionValues(table snapshotTable, row []snapshotCell) ([]any, error) {
	values, err := pgSnapshotValues(table, row)
	if err != nil {
		return nil, err
	}
	if table.Name == "users" {
		epochIndex := columnIndex(table.Columns, "credential_epoch")
		if epochIndex < 0 {
			return nil, errors.New("user credential epoch is missing")
		}
		epoch, ok := values[epochIndex].(int64)
		if !ok || epoch == int64(math.MaxInt64) {
			return nil, errors.New("user credential epoch is invalid")
		}
		values[epochIndex] = epoch + 1
	}
	return values, nil
}

func canonicalProductionValue(column string, value any) (snapshotCell, error) {
	if value == nil {
		return snapshotCell{Kind: "null"}, nil
	}
	if column == "enable_ssl" || column == "waf_enabled" || column == "enabled" || column == "two_fa_enabled" || column == "is_read" || column == "is_pinned" {
		boolean, ok := canonicalDatabaseBool(value)
		if !ok {
			return snapshotCell{}, errors.New("invalid production boolean")
		}
		if boolean {
			return snapshotCell{Kind: "integer", Integer: 1}, nil
		}
		return snapshotCell{Kind: "integer"}, nil
	}
	if strings.HasSuffix(column, "_at") || column == "created_at" || column == "updated_at" {
		switch typed := value.(type) {
		case time.Time:
			return snapshotCell{Kind: "text", Text: typed.UTC().Format(time.RFC3339Nano)}, nil
		case string:
			if typed == "" {
				return snapshotCell{Kind: "null"}, nil
			}
			parsed, err := parseSnapshotTime(typed)
			if err != nil {
				return snapshotCell{}, err
			}
			return snapshotCell{Kind: "text", Text: parsed.Format(time.RFC3339Nano)}, nil
		case []byte:
			return canonicalProductionValue(column, string(typed))
		default:
			return snapshotCell{}, errors.New("invalid production timestamp")
		}
	}
	if column == "domains" || column == "upstreams" || column == "advanced" {
		var raw []byte
		switch typed := value.(type) {
		case string:
			raw = []byte(typed)
		case []byte:
			raw = typed
		default:
			return snapshotCell{}, errors.New("invalid production JSON value")
		}
		var decoded any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return snapshotCell{}, errors.New("invalid production JSON value")
		}
		canonical, err := json.Marshal(decoded)
		if err != nil {
			return snapshotCell{}, err
		}
		return snapshotCell{Kind: "text", Text: string(canonical)}, nil
	}
	switch typed := value.(type) {
	case int:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case int8:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case int16:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case int32:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return snapshotCell{}, errors.New("production integer is out of range")
		}
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case uint8:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case uint16:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case uint32:
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case uint64:
		if typed > math.MaxInt64 {
			return snapshotCell{}, errors.New("production integer is out of range")
		}
		return snapshotCell{Kind: "integer", Integer: int64(typed)}, nil
	case float32:
		return encodeSnapshotCell(float64(typed))
	default:
		return encodeSnapshotCell(value)
	}
}

func canonicalDatabaseBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case int:
		return typed != 0, typed == 0 || typed == 1
	case int64:
		return typed != 0, typed == 0 || typed == 1
	case string:
		switch strings.ToLower(typed) {
		case "0", "false", "f":
			return false, true
		case "1", "true", "t":
			return true, true
		}
	case []byte:
		return canonicalDatabaseBool(string(typed))
	}
	return false, false
}

func encodeSnapshotCell(value any) (snapshotCell, error) {
	switch typed := value.(type) {
	case nil:
		return snapshotCell{Kind: "null"}, nil
	case int64:
		return snapshotCell{Kind: "integer", Integer: typed}, nil
	case float64:
		return snapshotCell{Kind: "real", Real: typed}, nil
	case string:
		return snapshotCell{Kind: "text", Text: typed}, nil
	case []byte:
		return snapshotCell{Kind: "blob", Blob: append([]byte(nil), typed...)}, nil
	case bool:
		if typed {
			return snapshotCell{Kind: "integer", Integer: 1}, nil
		}
		return snapshotCell{Kind: "integer"}, nil
	case time.Time:
		return snapshotCell{Kind: "text", Text: typed.UTC().Format(time.RFC3339Nano)}, nil
	default:
		return snapshotCell{}, fmt.Errorf("unsupported SQLite value type %T", value)
	}
}

func (c snapshotCell) value() (any, error) {
	switch c.Kind {
	case "null":
		return nil, nil
	case "integer":
		return c.Integer, nil
	case "real":
		if math.IsNaN(c.Real) || math.IsInf(c.Real, 0) {
			return nil, errors.New("invalid real snapshot value")
		}
		return c.Real, nil
	case "text":
		return c.Text, nil
	case "blob":
		return append([]byte(nil), c.Blob...), nil
	default:
		return nil, errors.New("invalid snapshot cell kind")
	}
}

func decodeManagementSnapshot(raw []byte) (managementSnapshot, error) {
	var state managementSnapshot
	if len(raw) == 0 || json.Unmarshal(raw, &state) != nil || state.Version != managementSnapshotVersion || state.SQLiteSchemaVersion != supportedSQLiteSchemaVersion || len(state.Tables) != len(managementTableSpecs) {
		return managementSnapshot{}, errors.New("invalid management snapshot")
	}
	for index, spec := range managementTableSpecs {
		table := state.Tables[index]
		if table.Name != spec.name || !reflect.DeepEqual(table.Columns, spec.columns) {
			return managementSnapshot{}, errors.New("management snapshot schema mismatch")
		}
		for _, row := range table.Rows {
			if len(row) != len(table.Columns) {
				return managementSnapshot{}, errors.New("management snapshot row mismatch")
			}
			for _, cell := range row {
				if _, err := cell.value(); err != nil {
					return managementSnapshot{}, err
				}
			}
		}
	}
	return state, nil
}

func invalidateSQLiteSecurityState(ctx context.Context, db *sql.DB, now time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var exhausted int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE credential_epoch>=?`, int64(math.MaxInt64)).Scan(&exhausted); err != nil {
		return err
	}
	if exhausted != 0 {
		return errors.New("credential epoch is exhausted")
	}
	formatted := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET credential_epoch=credential_epoch+1,updated_at=?`, formatted); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE admin_sessions SET revoked_at=CASE WHEN revoked_at='' THEN ? ELSE revoked_at END,updated_at=?`, formatted, formatted); err != nil {
		return err
	}
	return tx.Commit()
}

func restoreSQLiteSecurityState(ctx context.Context, db *sql.DB, state managementSnapshot) error {
	users, ok := snapshotTableNamed(state, "users")
	if !ok {
		return errors.New("users snapshot is missing")
	}
	sessions, ok := snapshotTableNamed(state, "admin_sessions")
	if !ok {
		return errors.New("session snapshot is missing")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	userID := columnIndex(users.Columns, "id")
	updatedAt := columnIndex(users.Columns, "updated_at")
	epoch := columnIndex(users.Columns, "credential_epoch")
	if userID < 0 || updatedAt < 0 || epoch < 0 {
		return errors.New("users snapshot columns are incomplete")
	}
	for _, row := range users.Rows {
		id, err := row[userID].value()
		if err != nil {
			return err
		}
		updated, err := row[updatedAt].value()
		if err != nil {
			return err
		}
		originalEpoch, err := row[epoch].value()
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE users SET credential_epoch=?,updated_at=? WHERE id=?`, originalEpoch, updated, id)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			return errors.New("restore user security state failed")
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions`); err != nil {
		return err
	}
	for _, row := range sessions.Rows {
		values, err := snapshotRowValues(row)
		if err != nil {
			return err
		}
		query := "INSERT INTO admin_sessions(" + strings.Join(sessions.Columns, ",") + ") VALUES(" + sqlitePlaceholders(len(values)) + ")"
		if _, err := tx.ExecContext(ctx, query, values...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func revokePersistedJoinTokens(path string) error {
	snapshot, err := captureFile(path)
	if err != nil || !snapshot.Exists {
		return err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(snapshot.Data, &document); err != nil {
		return errors.New("parse cluster identity state")
	}
	rawTokens, ok := document["tokens"]
	if !ok {
		return errors.New("cluster identity token state is missing")
	}
	var tokens []map[string]json.RawMessage
	if err := json.Unmarshal(rawTokens, &tokens); err != nil {
		return errors.New("parse cluster join tokens")
	}
	for index := range tokens {
		tokens[index]["revoked"] = json.RawMessage("true")
		tokens[index]["value"] = json.RawMessage(`""`)
	}
	encodedTokens, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	document["tokens"] = encodedTokens
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writePrivateFileAtomic(path, raw, 0o600)
}

func captureFile(path string) (fileSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileSnapshot{}, nil
	}
	if err != nil {
		return fileSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > securityArtifactSnapshotMaxLen {
		return fileSnapshot{}, errors.New("security state is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fileSnapshot{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, securityArtifactSnapshotMaxLen+1))
	closeErr := file.Close()
	if readErr != nil {
		return fileSnapshot{}, readErr
	}
	if closeErr != nil {
		return fileSnapshot{}, closeErr
	}
	if len(raw) > securityArtifactSnapshotMaxLen {
		return fileSnapshot{}, errors.New("security state file is too large")
	}
	return fileSnapshot{Exists: true, Mode: info.Mode().Perm(), Data: raw}, nil
}

func restoreFile(path string, snapshot fileSnapshot) error {
	if !snapshot.Exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	mode := snapshot.Mode
	if mode == 0 {
		mode = 0o600
	}
	return writePrivateFileAtomic(path, snapshot.Data, mode)
}

func snapshotTableNamed(state managementSnapshot, name string) (snapshotTable, bool) {
	for _, table := range state.Tables {
		if table.Name == name {
			return table, true
		}
	}
	return snapshotTable{}, false
}

func snapshotRowValues(row []snapshotCell) ([]any, error) {
	values := make([]any, len(row))
	for index, cell := range row {
		value, err := cell.value()
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func columnIndex(columns []string, name string) int {
	for index, column := range columns {
		if column == name {
			return index
		}
	}
	return -1
}

func sqlitePlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", count), ",")
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func legacyTokenSnapshotFromConfigFile(raw []byte) ([]config.ManagementAPITokenConfig, error) {
	// Config files are YAML. Load is intentionally avoided here because it
	// applies defaults and validates unrelated runtime dependencies.
	var document struct {
		APISec struct {
			ManagementAPI struct {
				Tokens []config.ManagementAPITokenConfig `yaml:"tokens"`
			} `yaml:"management_api"`
		} `yaml:"apisec"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if document.APISec.ManagementAPI.Tokens == nil {
		return []config.ManagementAPITokenConfig{}, nil
	}
	return document.APISec.ManagementAPI.Tokens, nil
}
