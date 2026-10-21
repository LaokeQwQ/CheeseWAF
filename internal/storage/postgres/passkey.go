package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// PasskeyStore adapts the management PostgreSQL database to passkey.Store.
// Credential IDs and AAGUIDs are stored as unpadded base64url text; public keys
// stay BYTEA and transports stay JSONB arrays.
type PasskeyStore struct {
	db *sql.DB
}

var _ passkey.Store = (*PasskeyStore)(nil)

// PasskeyStore returns a passkey.Store bound to this database. It returns nil
// for a nil store so composition roots can treat an unusable store as absent.
func (s *Store) PasskeyStore() passkey.Store {
	if s == nil || s.db == nil {
		return nil
	}
	return &PasskeyStore{db: s.db}
}

func (s *PasskeyStore) checkReady(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("passkey store is not initialized")
	}
	if ctx == nil {
		return errors.New("passkey store requires a context")
	}
	return nil
}

func (s *PasskeyStore) ListByUser(ctx context.Context, userID string) ([]*passkey.Credential, error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, err
	}
	if err := validatePasskeyUserID(userID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, rebind(`SELECT id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at FROM passkey_credentials WHERE user_id=? ORDER BY created_at,id`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	credentials := make([]*passkey.Credential, 0, 4)
	for rows.Next() {
		credential, err := scanPostgresPasskeyCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return credentials, nil
}

func (s *PasskeyStore) GetByCredentialID(ctx context.Context, credentialID []byte) (*passkey.Credential, error) {
	if err := s.checkReady(ctx); err != nil {
		return nil, err
	}
	if len(credentialID) == 0 || len(credentialID) > passkey.MaxCredentialIDLen {
		return nil, passkey.ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, rebind(`SELECT id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at FROM passkey_credentials WHERE credential_id=?`), encodePasskeyBytes(credentialID))
	credential, err := scanPostgresPasskeyCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, passkey.ErrNotFound
	}
	return credential, err
}

func (s *PasskeyStore) Create(ctx context.Context, credential *passkey.Credential) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if credential == nil {
		return passkey.ErrInvalidCredential
	}
	if err := credential.Validate(); err != nil {
		return err
	}
	transports, err := encodePasskeyTransports(credential.Transports)
	if err != nil {
		return err
	}
	createdAt := credential.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, rebind(`INSERT INTO passkey_credentials(id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`),
		credential.ID, credential.UserID, encodePasskeyBytes(credential.CredentialID), credential.PublicKey,
		int64(credential.SignCount), transports, encodePasskeyBytes(credential.AAGUID), credential.BackupEligible,
		credential.Name, createdAt.UTC(), passkeyLastUsedValue(credential.LastUsedAt))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return passkey.ErrCredentialExists
		}
		return err
	}
	return nil
}

func (s *PasskeyStore) UpdateSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return passkey.ErrNotFound
	}
	result, err := s.db.ExecContext(ctx, rebind(`UPDATE passkey_credentials SET sign_count=?,last_used_at=? WHERE id=? AND (sign_count < ? OR sign_count = 0)`),
		int64(signCount), lastUsedAt.UTC(), id, int64(signCount))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		var one int
		err := s.db.QueryRowContext(ctx, rebind(`SELECT 1 FROM passkey_credentials WHERE id=?`), id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return passkey.ErrNotFound
		}
		if err != nil {
			return err
		}
		return passkey.ErrCloneWarning
	}
	return nil
}

func (s *PasskeyStore) Delete(ctx context.Context, id string) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return passkey.ErrNotFound
	}
	result, err := s.db.ExecContext(ctx, rebind(`DELETE FROM passkey_credentials WHERE id=?`), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return passkey.ErrNotFound
	}
	return nil
}

// DeleteByUser removes credentials and recovery codes in one transaction.
func (s *PasskeyStore) DeleteByUser(ctx context.Context, userID string) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if err := validatePasskeyUserID(userID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, rebind(`DELETE FROM passkey_credentials WHERE user_id=?`), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, rebind(`DELETE FROM passkey_recovery_codes WHERE user_id=?`), userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PasskeyStore) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte, createdAt time.Time) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if err := validatePasskeyUserID(userID); err != nil {
		return err
	}
	if len(hashes) > passkey.MaxRecoveryCodes {
		return fmt.Errorf("%w: too many recovery codes", passkey.ErrInvalidRecoveryCode)
	}
	for _, hash := range hashes {
		if len(hash) == 0 || len(hash) > 64 {
			return fmt.Errorf("%w: invalid recovery hash", passkey.ErrInvalidRecoveryCode)
		}
	}
	created := timestamp(createdAt)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, rebind(`DELETE FROM passkey_recovery_codes WHERE user_id=?`), userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err := tx.ExecContext(ctx, rebind(`INSERT INTO passkey_recovery_codes(id,user_id,code_hash,used_at,created_at) VALUES(?,?,?,NULL,?)`),
			uuid.NewString(), userID, encodePasskeyHash(hash), created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConsumeRecoveryCode removes the matching unused row in one conditional
// statement, so concurrent callers cannot both consume the same code.
func (s *PasskeyStore) ConsumeRecoveryCode(ctx context.Context, userID string, hash []byte, _ time.Time) (bool, error) {
	if err := s.checkReady(ctx); err != nil {
		return false, err
	}
	if err := validatePasskeyUserID(userID); err != nil {
		return false, err
	}
	if len(hash) == 0 || len(hash) > 64 {
		return false, nil
	}
	result, err := s.db.ExecContext(ctx, rebind(`DELETE FROM passkey_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL`), userID, encodePasskeyHash(hash))
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func (s *PasskeyStore) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if err := validatePasskeyUserID(userID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, rebind(`DELETE FROM passkey_recovery_codes WHERE user_id=?`), userID)
	return err
}

func (s *PasskeyStore) RecordAudit(ctx context.Context, event passkey.AuditEvent) error {
	if err := s.checkReady(ctx); err != nil {
		return err
	}
	if err := validatePasskeyUserID(event.UserID); err != nil {
		return err
	}
	if event.Type == "" || len(event.Type) > 128 {
		return errors.New("passkey audit type must be 1..128 bytes")
	}
	if len(event.Actor) > 128 || len(event.Reason) > 512 {
		return errors.New("passkey audit actor or reason exceeds its bound")
	}
	at := timestamp(event.At)
	_, err := s.db.ExecContext(ctx, rebind(`INSERT INTO passkey_audit_events(id,type,user_id,actor,reason,created_at) VALUES(?,?,?,?,?,?)`),
		uuid.NewString(), event.Type, event.UserID, event.Actor, event.Reason, at)
	return err
}

func scanPostgresPasskeyCredential(row scanner) (*passkey.Credential, error) {
	var (
		credential     passkey.Credential
		credentialID   string
		publicKey      []byte
		signCount      int64
		transports     []byte
		aaguid         string
		backupEligible bool
		createdAt      dbTime
		lastUsedAt     dbTime
	)
	if err := row.Scan(&credential.ID, &credential.UserID, &credentialID, &publicKey, &signCount, &transports, &aaguid, &backupEligible, &credential.Name, &createdAt, &lastUsedAt); err != nil {
		return nil, err
	}
	decodedID, err := decodePasskeyBytes(credentialID)
	if err != nil {
		return nil, fmt.Errorf("decode passkey credential id: %w", err)
	}
	decodedAAGUID, err := decodePasskeyBytes(aaguid)
	if err != nil {
		return nil, fmt.Errorf("decode passkey aaguid: %w", err)
	}
	decodedTransports, err := decodePasskeyTransports(transports)
	if err != nil {
		return nil, err
	}
	credential.CredentialID = decodedID
	credential.PublicKey = append([]byte(nil), publicKey...)
	credential.SignCount = uint32(signCount)
	credential.Transports = decodedTransports
	credential.AAGUID = decodedAAGUID
	credential.BackupEligible = backupEligible
	credential.CreatedAt = createdAt.Time
	if !lastUsedAt.Time.IsZero() && lastUsedAt.Time.Unix() != 0 {
		credential.LastUsedAt = lastUsedAt.Time
	}
	if err := credential.Validate(); err != nil {
		return nil, err
	}
	return &credential, nil
}

func validatePasskeyUserID(userID string) error {
	if userID == "" || strings.TrimSpace(userID) != userID || len(userID) > passkey.MaxUserIDLen {
		return fmt.Errorf("%w: invalid user ID", passkey.ErrInvalidUser)
	}
	return nil
}

func encodePasskeyBytes(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodePasskeyBytes(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(value)
}

func encodePasskeyHash(hash []byte) string {
	return hex.EncodeToString(hash)
}

func encodePasskeyTransports(transports []string) ([]byte, error) {
	if len(transports) == 0 {
		return []byte("[]"), nil
	}
	encoded, err := json.Marshal(transports)
	if err != nil {
		return nil, fmt.Errorf("%w: encode transports: %v", passkey.ErrInvalidCredential, err)
	}
	return encoded, nil
}

func decodePasskeyTransports(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 4<<10 {
		return nil, fmt.Errorf("%w: transports exceed their bound", passkey.ErrInvalidCredential)
	}
	var transports []string
	if err := json.Unmarshal(raw, &transports); err != nil {
		return nil, fmt.Errorf("%w: decode transports: %v", passkey.ErrInvalidCredential, err)
	}
	return transports, nil
}

// passkeyLastUsedValue maps the zero time to Unix epoch because the schema
// requires a non-NULL timestamp. Readers map epoch back to the zero time.
func passkeyLastUsedValue(value time.Time) time.Time {
	if value.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return value.UTC()
}
