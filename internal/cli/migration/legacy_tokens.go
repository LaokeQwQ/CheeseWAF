package migration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

const migratedLegacyTokenStatus = "revoked"

func decodeLegacyTokenMetadata(raw []byte) ([]config.ManagementAPITokenConfig, error) {
	if len(raw) == 0 {
		return []config.ManagementAPITokenConfig{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var tokens []config.ManagementAPITokenConfig
	if err := decoder.Decode(&tokens); err != nil {
		return nil, ErrRuntimeConfiguration
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrRuntimeConfiguration
	}
	if len(tokens) > config.MaxManagementAPITokens {
		return nil, ErrRuntimeConfiguration
	}
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if !controlplane.ValidIdentity(token.ID) || !validLegacyTokenName(token.Name) || !controlplane.ValidIdentity(token.Prefix) || !validLegacyTokenHash(token.Hash) || len(token.Scopes) == 0 {
			return nil, ErrRuntimeConfiguration
		}
		if _, ok := seen[token.ID]; ok {
			return nil, ErrRuntimeConfiguration
		}
		seen[token.ID] = struct{}{}
		for _, scope := range token.Scopes {
			if !controlplane.ValidIdentity(scope) {
				return nil, ErrRuntimeConfiguration
			}
		}
		if token.NeverExpire && !token.ExpiresAt.IsZero() {
			return nil, ErrRuntimeConfiguration
		}
		if !token.CreatedAt.IsZero() && !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(token.CreatedAt) {
			return nil, ErrRuntimeConfiguration
		}
		if !token.CreatedAt.IsZero() && !token.LastUsedAt.IsZero() && token.LastUsedAt.Before(token.CreatedAt) {
			return nil, ErrRuntimeConfiguration
		}
	}
	return tokens, nil
}

func validLegacyTokenName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validLegacyTokenHash(value string) bool {
	switch {
	case strings.HasPrefix(value, "bcrypt:"):
		return len(value) >= len("bcrypt:")+20
	case strings.HasPrefix(value, "sha256:"):
		digest := strings.TrimPrefix(value, "sha256:")
		if len(digest) != 64 || digest != strings.ToLower(digest) {
			return false
		}
		_, err := hex.DecodeString(digest)
		return err == nil
	default:
		return false
	}
}

func insertLegacyTokenMetadata(ctx context.Context, tx *sql.Tx, snapshotID, actor string, raw []byte, migratedAt time.Time) error {
	if tx == nil || !controlplane.ValidIdentity(snapshotID) || !controlplane.ValidIdentity(actor) || migratedAt.IsZero() {
		return ErrRuntimeConfiguration
	}
	tokens, err := decodeLegacyTokenMetadata(raw)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		scopes, err := json.Marshal(token.Scopes)
		if err != nil {
			return ErrRuntimeConfiguration
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO cheesewaf_migration_legacy_tokens(snapshot_id,token_id,name,prefix,scopes,notes,was_enabled,never_expire,created_at,updated_at,last_used_at,expires_at,source_revoked_at,migrated_at,actor_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			snapshotID, token.ID, token.Name, token.Prefix, scopes, token.Notes, token.Enabled, token.NeverExpire,
			nullableMigrationTime(token.CreatedAt), nullableMigrationTime(token.UpdatedAt), nullableMigrationTime(token.LastUsedAt),
			nullableMigrationTime(token.ExpiresAt), nullableMigrationTime(token.RevokedAt), migratedAt.UTC(), actor, migratedLegacyTokenStatus)
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyLegacyTokenMetadataTx(ctx context.Context, tx *sql.Tx, snapshotID, actor string, raw []byte) (bool, error) {
	if tx == nil || !controlplane.ValidIdentity(snapshotID) || !controlplane.ValidIdentity(actor) {
		return false, ErrRuntimeConfiguration
	}
	expected, err := decodeLegacyTokenMetadata(raw)
	if err != nil {
		return false, err
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].ID < expected[j].ID })
	rows, err := tx.QueryContext(ctx, `SELECT token_id,name,prefix,scopes,notes,was_enabled,never_expire,created_at,updated_at,last_used_at,expires_at,source_revoked_at,actor_id,status FROM cheesewaf_migration_legacy_tokens WHERE snapshot_id=$1 ORDER BY token_id`, snapshotID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		if index >= len(expected) {
			return false, nil
		}
		var tokenID, name, prefix, notes, gotActor, status string
		var scopesRaw []byte
		var wasEnabledRaw, neverExpireRaw any
		var createdAt, updatedAt, lastUsedAt, expiresAt, sourceRevokedAt sql.NullTime
		if err := rows.Scan(&tokenID, &name, &prefix, &scopesRaw, &notes, &wasEnabledRaw, &neverExpireRaw, &createdAt, &updatedAt, &lastUsedAt, &expiresAt, &sourceRevokedAt, &gotActor, &status); err != nil {
			return false, err
		}
		var scopes []string
		if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
			return false, err
		}
		wasEnabled, okEnabled := canonicalDatabaseBool(wasEnabledRaw)
		neverExpire, okNever := canonicalDatabaseBool(neverExpireRaw)
		want := expected[index]
		if !okEnabled || !okNever || tokenID != want.ID || name != want.Name || prefix != want.Prefix || notes != want.Notes ||
			wasEnabled != want.Enabled || neverExpire != want.NeverExpire || gotActor != actor || status != migratedLegacyTokenStatus ||
			!reflect.DeepEqual(scopes, want.Scopes) || !nullableMigrationTimeEqual(createdAt, want.CreatedAt) ||
			!nullableMigrationTimeEqual(updatedAt, want.UpdatedAt) || !nullableMigrationTimeEqual(lastUsedAt, want.LastUsedAt) ||
			!nullableMigrationTimeEqual(expiresAt, want.ExpiresAt) || !nullableMigrationTimeEqual(sourceRevokedAt, want.RevokedAt) {
			return false, nil
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return index == len(expected), nil
}

func validateLegacyTokenRotation(candidate *config.Config, raw []byte, now time.Time) error {
	if candidate == nil || now.IsZero() {
		return ErrRuntimeConfiguration
	}
	source, err := decodeLegacyTokenMetadata(raw)
	if err != nil || len(candidate.APISec.ManagementAPI.Tokens) != len(source) {
		return ErrRuntimeConfiguration
	}
	byID := make(map[string]config.ManagementAPITokenConfig, len(source))
	for _, token := range source {
		byID[token.ID] = token
	}
	seen := make(map[string]struct{}, len(source))
	for _, token := range candidate.APISec.ManagementAPI.Tokens {
		original, ok := byID[token.ID]
		if !ok {
			return ErrRuntimeConfiguration
		}
		if _, duplicate := seen[token.ID]; duplicate {
			return ErrRuntimeConfiguration
		}
		seen[token.ID] = struct{}{}
		if token.Enabled || token.Hash != "" || token.NeverExpire || token.RevokedAt.IsZero() || token.RevokedAt.After(now) || token.ExpiresAt.IsZero() || token.ExpiresAt.After(now) {
			return ErrRuntimeConfiguration
		}
		if token.Name != original.Name || token.Prefix != original.Prefix || token.Notes != original.Notes || !reflect.DeepEqual(token.Scopes, original.Scopes) || token.CreatedAt != original.CreatedAt || token.LastUsedAt != original.LastUsedAt {
			return ErrRuntimeConfiguration
		}
	}
	return nil
}

func nullableMigrationTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableMigrationTimeEqual(actual sql.NullTime, expected time.Time) bool {
	if expected.IsZero() {
		return !actual.Valid
	}
	return actual.Valid && actual.Time.UTC().Equal(expected.UTC())
}
