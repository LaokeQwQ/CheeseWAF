package storage

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
)

// PasskeyStore adapts the SQLite management database to passkey.Store.
// Credential IDs and AAGUIDs are stored as unpadded base64url text; public keys
// stay raw bytes and transports stay JSON arrays.
type PasskeyStore struct {
	db *sql.DB
}

var _ passkey.Store = (*PasskeyStore)(nil)

// PasskeyStore returns a passkey.Store bound to this database. It returns nil
// for a nil store so composition roots can treat an unusable store as absent.
func (s *SQLiteStore) PasskeyStore() passkey.Store {
	if s == nil || s.db == nil {
		return nil
	}
	return &PasskeyStore{db: s.db}
}

// AsPasskeyStore extracts a passkey.Store from a management store that provides
// one. It returns nil for other implementations, which makes passkey wiring
// fail closed instead of panicking.
func AsPasskeyStore(store Store) passkey.Store {
	provider, ok := store.(interface{ PasskeyStore() passkey.Store })
	if !ok {
		return nil
	}
	return provider.PasskeyStore()
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
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at FROM passkey_credentials WHERE user_id=? ORDER BY created_at,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	credentials := make([]*passkey.Credential, 0, 4)
	for rows.Next() {
		credential, err := scanSQLitePasskeyCredential(rows)
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
	row := s.db.QueryRowContext(ctx, `SELECT id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at FROM passkey_credentials WHERE credential_id=?`, encodePasskeyBytes(credentialID))
	credential, err := scanSQLitePasskeyCredential(row)
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
	lastUsedAt := ""
	if !credential.LastUsedAt.IsZero() {
		lastUsedAt = formatTime(credential.LastUsedAt)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO passkey_credentials(id,user_id,credential_id,public_key,sign_count,transports,aaguid,backup_eligible,name,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		credential.ID, credential.UserID, encodePasskeyBytes(credential.CredentialID), credential.PublicKey,
		int64(credential.SignCount), transports, encodePasskeyBytes(credential.AAGUID), boolInt(credential.BackupEligible),
		credential.Name, formatTime(createdAt), lastUsedAt)
	if err != nil {
		if isSQLiteUniqueViolation(err) {
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
	result, err := s.db.ExecContext(ctx, `UPDATE passkey_credentials SET sign_count=?,last_used_at=? WHERE id=? AND (sign_count < ? OR sign_count = 0)`,
		int64(signCount), formatTime(lastUsedAt), id, int64(signCount))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM passkey_credentials WHERE id=?`, id).Scan(&one)
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
	result, err := s.db.ExecContext(ctx, `DELETE FROM passkey_credentials WHERE id=?`, id)
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkey_credentials WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE user_id=?`, userID); err != nil {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, hash := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO passkey_recovery_codes(id,user_id,code_hash,used_at,created_at) VALUES(?,?,?,'',?)`,
			uuid.NewString(), userID, encodePasskeyHash(hash), formatTime(createdAt)); err != nil {
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
	result, err := s.db.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE user_id=? AND code_hash=? AND used_at=''`, userID, encodePasskeyHash(hash))
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkey_recovery_codes WHERE user_id=?`, userID)
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
	at := event.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO passkey_audit_events(id,type,user_id,actor,reason,created_at) VALUES(?,?,?,?,?,?)`,
		uuid.NewString(), event.Type, event.UserID, event.Actor, event.Reason, formatTime(at))
	return err
}

func scanSQLitePasskeyCredential(row scanner) (*passkey.Credential, error) {
	var (
		credential     passkey.Credential
		credentialID   string
		publicKey      []byte
		signCount      int64
		transports     string
		aaguid         string
		backupEligible int
		createdAt      string
		lastUsedAt     string
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
	credential.BackupEligible = backupEligible != 0
	credential.CreatedAt = parseTime(createdAt)
	if lastUsedAt != "" {
		credential.LastUsedAt = parseTime(lastUsedAt)
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

func encodePasskeyTransports(transports []string) (string, error) {
	if len(transports) == 0 {
		return "[]", nil
	}
	encoded, err := json.Marshal(transports)
	if err != nil {
		return "", fmt.Errorf("%w: encode transports: %v", passkey.ErrInvalidCredential, err)
	}
	return string(encoded), nil
}

func decodePasskeyTransports(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 4<<10 {
		return nil, fmt.Errorf("%w: transports exceed their bound", passkey.ErrInvalidCredential)
	}
	var transports []string
	if err := json.Unmarshal([]byte(raw), &transports); err != nil {
		return nil, fmt.Errorf("%w: decode transports: %v", passkey.ErrInvalidCredential, err)
	}
	return transports, nil
}

func isSQLiteUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
