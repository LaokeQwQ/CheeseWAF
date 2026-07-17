package ai

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalApproved  ApprovalStatus = "approved"
	ApprovalExecuting ApprovalStatus = "executing"
	ApprovalRejected  ApprovalStatus = "rejected"
	ApprovalExecuted  ApprovalStatus = "executed"
	ApprovalFailed    ApprovalStatus = "failed"
)

type ApprovalRequest struct {
	ID                 string          `json:"id"`
	ToolName           string          `json:"tool_name"`
	Args               map[string]any  `json:"args"`
	ArgsSalt           string          `json:"-"`
	ArgsDigest         string          `json:"-"`
	Sensitivity        ToolSensitivity `json:"sensitivity"`
	Diff               string          `json:"diff,omitempty"`
	Status             ApprovalStatus  `json:"status"`
	RequesterSubject   string          `json:"requester_subject,omitempty"`
	RequesterSessionID string          `json:"requester_session_id,omitempty"`
	RequesterUsername  string          `json:"requester_username,omitempty"`
	ApprovedBySubject  string          `json:"approved_by_subject,omitempty"`
	ApprovedBySession  string          `json:"approved_by_session_id,omitempty"`
	ApprovedByUsername string          `json:"approved_by_username,omitempty"`
	RejectedBySubject  string          `json:"rejected_by_subject,omitempty"`
	RejectedBySession  string          `json:"rejected_by_session_id,omitempty"`
	RejectedByUsername string          `json:"rejected_by_username,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	ExpiresAt          time.Time       `json:"expires_at"`
	DecidedAt          time.Time       `json:"decided_at,omitempty"`
	ConsumedAt         time.Time       `json:"consumed_at,omitempty"`
}

type ApprovalStore struct {
	mu        sync.RWMutex
	requests  map[string]ApprovalRequest
	now       func() time.Time
	ttl       time.Duration
	path      string
	healthErr error
}

const redactedApprovalValue = "[redacted]"

var (
	approvalDiffAssignmentPattern = regexp.MustCompile(`(?i)(["']?)(password|passwd|passphrase|secret|token|api[_-]?key|authorization|private[_-]?key|cookie|client[_-]?secret|access[_-]?key)(["']?\s*[=:]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&}\]]+)`)
	approvalDiffHeaderPattern     = regexp.MustCompile(`(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$`)
	approvalPrivateKeyPattern     = regexp.MustCompile(`(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`)
	approvalBearerPattern         = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
)

type ApprovalActor struct {
	Subject   string
	SessionID string
	Username  string
}

type approvalActorContextKey struct{}

const defaultApprovalTTL = 10 * time.Minute

func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{requests: map[string]ApprovalRequest{}, now: time.Now, ttl: defaultApprovalTTL}
}

func NewPersistentApprovalStore(path string) (*ApprovalStore, error) {
	store := NewApprovalStore()
	if err := store.UseFile(path); err != nil {
		store.mu.Lock()
		store.healthErr = err
		store.mu.Unlock()
		return store, err
	}
	return store, nil
}

func (s *ApprovalStore) UseFile(path string) error {
	if s == nil {
		return fmt.Errorf("approval store is nil")
	}
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return fmt.Errorf("approval store path is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	err := s.loadLocked()
	s.healthErr = err
	return err
}

func (s *ApprovalStore) PersistenceHealth() (bool, error) {
	if s == nil {
		return false, fmt.Errorf("approval store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.path == "" {
		return s.healthErr == nil, s.healthErr
	}
	return s.healthErr == nil, s.healthErr
}

func (s *ApprovalStore) CanPersistModifications() bool {
	ok, _ := s.PersistenceHealth()
	return ok
}

func ContextWithApprovalActor(ctx context.Context, actor ApprovalActor) context.Context {
	return context.WithValue(ctx, approvalActorContextKey{}, actor)
}

func ApprovalActorFromContext(ctx context.Context) ApprovalActor {
	if ctx == nil {
		return ApprovalActor{}
	}
	actor, _ := ctx.Value(approvalActorContextKey{}).(ApprovalActor)
	return actor
}

func (s *ApprovalStore) Create(tool Tool, args map[string]any, diff string) (ApprovalRequest, error) {
	return s.CreateFor(tool, args, diff, ApprovalActor{})
}

func (s *ApprovalStore) CreateFor(tool Tool, args map[string]any, diff string, actor ApprovalActor) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	if tool == nil {
		return ApprovalRequest{}, fmt.Errorf("tool is nil")
	}
	now := s.now().UTC()
	ttl := s.ttl
	if ttl <= 0 {
		ttl = defaultApprovalTTL
	}
	salt, err := newApprovalArgsSalt()
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("generate approval argument salt: %w", err)
	}
	digest, ok := approvalArgsDigest(args, salt)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval arguments cannot be normalized")
	}
	safeDiff, err := sanitizeApprovalDiff(diff)
	if err != nil {
		return ApprovalRequest{}, err
	}
	request := ApprovalRequest{
		ID:                 uuid.NewString(),
		ToolName:           tool.Name(),
		Args:               redactApprovalArgs(args),
		ArgsSalt:           salt,
		ArgsDigest:         digest,
		Sensitivity:        tool.Sensitivity(),
		Diff:               safeDiff,
		Status:             ApprovalPending,
		RequesterSubject:   actor.Subject,
		RequesterSessionID: actor.SessionID,
		RequesterUsername:  actor.Username,
		CreatedAt:          now,
		ExpiresAt:          now.Add(ttl),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[request.ID] = request
	if err := s.persistLocked(); err != nil {
		delete(s.requests, request.ID)
		return ApprovalRequest{}, err
	}
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) Approve(id string) (ApprovalRequest, error) {
	return s.ApproveFor(id, ApprovalActor{})
}

func (s *ApprovalStore) ApproveFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if approvalExpired(request, s.now().UTC()) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is expired", id)
	}
	if request.Status == ApprovalApproved {
		return cloneApprovalRequest(request), nil
	}
	if request.Status != ApprovalPending {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	old := request
	request.Status = ApprovalApproved
	request.DecidedAt = s.now().UTC()
	request.ApprovedBySubject = actor.Subject
	request.ApprovedBySession = actor.SessionID
	request.ApprovedByUsername = actor.Username
	s.requests[id] = request
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return cloneApprovalRequest(old), err
	}
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) Reject(id string) (ApprovalRequest, error) {
	return s.RejectFor(id, ApprovalActor{})
}

func (s *ApprovalStore) RejectFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if approvalExpired(request, s.now().UTC()) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is expired", id)
	}
	if request.Status != ApprovalPending && request.Status != ApprovalApproved {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	old := request
	request.Status = ApprovalRejected
	request.DecidedAt = s.now().UTC()
	request.RejectedBySubject = actor.Subject
	request.RejectedBySession = actor.SessionID
	request.RejectedByUsername = actor.Username
	s.requests[id] = request
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return cloneApprovalRequest(old), err
	}
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) ConsumeApproved(id string, toolName string, args map[string]any) (ApprovalRequest, error) {
	return s.BeginExecution(id, toolName, args)
}

func (s *ApprovalStore) BeginExecution(id string, toolName string, args map[string]any) (ApprovalRequest, error) {
	return s.BeginExecutionFor(id, toolName, args, ApprovalActor{})
}

func (s *ApprovalStore) BeginExecutionFor(id string, toolName string, args map[string]any, actor ApprovalActor) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if approvalExpired(request, s.now().UTC()) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is expired", id)
	}
	if request.Status != ApprovalApproved {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is %s, not approved", id, request.Status)
	}
	if !requesterMatches(request, actor) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is bound to another requester", id)
	}
	if request.ToolName != toolName {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q belongs to tool %q", id, request.ToolName)
	}
	if !approvalArgsMatch(request.ArgsSalt, request.ArgsDigest, args) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q arguments do not match", id)
	}
	old := request
	request.Status = ApprovalExecuting
	request.ConsumedAt = s.now().UTC()
	s.requests[id] = request
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return cloneApprovalRequest(old), err
	}
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) MarkExecuted(id string) (ApprovalRequest, error) {
	return s.finishExecution(id, ApprovalExecuted)
}

func (s *ApprovalStore) MarkExecutionFailed(id string) (ApprovalRequest, error) {
	return s.finishExecution(id, ApprovalFailed)
}

func (s *ApprovalStore) finishExecution(id string, status ApprovalStatus) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	if status != ApprovalApproved && status != ApprovalExecuted && status != ApprovalFailed {
		return ApprovalRequest{}, fmt.Errorf("unsupported approval execution status %q", status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Status != ApprovalExecuting {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is %s, not executing", id, request.Status)
	}
	old := request
	request.Status = status
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	if err := s.persistLocked(); err != nil {
		s.requests[id] = old
		return cloneApprovalRequest(old), err
	}
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) Get(id string) (ApprovalRequest, bool) {
	if s == nil {
		return ApprovalRequest{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	request, ok := s.requests[id]
	return cloneApprovalRequest(request), ok
}

// List returns a defensive snapshot of all approval requests. Callers are
// responsible for applying authorization filters before exposing the data.
func (s *ApprovalStore) List() []ApprovalRequest {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	requests := make([]ApprovalRequest, 0, len(s.requests))
	for _, request := range s.requests {
		requests = append(requests, cloneApprovalRequest(request))
	}
	slices.SortFunc(requests, func(left, right ApprovalRequest) int {
		if left.CreatedAt.Equal(right.CreatedAt) {
			return strings.Compare(left.ID, right.ID)
		}
		if left.CreatedAt.After(right.CreatedAt) {
			return -1
		}
		return 1
	})
	return requests
}

func cloneApprovalRequest(request ApprovalRequest) ApprovalRequest {
	request.Args = cloneArgs(request.Args)
	return request
}

func cloneArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for key, value := range args {
		out[key] = cloneArgValue(value)
	}
	return out
}

func cloneArgValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneArgs(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneArgValue(item)
		}
		return out
	default:
		return value
	}
}

func approvalArgsMatch(salt, expected string, args map[string]any) bool {
	digest, ok := approvalArgsDigest(args, salt)
	return ok && expected != "" && digest == expected
}

func approvalArgsDigest(args map[string]any, salt string) (string, bool) {
	normalized, ok := canonicalArgs(args)
	if !ok || salt == "" {
		return "", false
	}
	digest := sha256.Sum256([]byte(salt + "\x00" + normalized))
	return fmt.Sprintf("sha256:%x", digest[:]), true
}

func newApprovalArgsSalt() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func redactApprovalArgs(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return map[string]any{"_redacted": redactedApprovalValue}
	}
	var normalized map[string]any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return map[string]any{"_redacted": redactedApprovalValue}
	}
	return redactApprovalMap(normalized)
}

func redactApprovalMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for key, item := range value {
		if isSensitiveApprovalKey(key) {
			out[key] = redactedApprovalValue
			continue
		}
		out[key] = redactApprovalValue(item)
	}
	return out
}

func redactApprovalValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactApprovalMap(typed)
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = redactApprovalValue(item)
		}
		return out
	default:
		return typed
	}
}

func isSensitiveApprovalKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(normalized)
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range []string{
		"password", "passwd", "passphrase", "secret", "token", "api_key", "apikey",
		"authorization", "private_key", "privatekey", "cookie", "client_secret", "access_key",
	} {
		compactMarker := strings.ReplaceAll(marker, "_", "")
		if normalized == marker || strings.Contains("_"+normalized+"_", "_"+marker+"_") || strings.Contains(compact, compactMarker) {
			return true
		}
	}
	return false
}

func sanitizeApprovalDiff(diff string) (string, error) {
	trimmed := strings.TrimSpace(diff)
	if trimmed == "" {
		return "", nil
	}

	var structured any
	if json.Unmarshal([]byte(trimmed), &structured) == nil {
		safe, err := json.MarshalIndent(redactApprovalValue(structured), "", "  ")
		if err != nil {
			return "", fmt.Errorf("sanitize approval diff: %w", err)
		}
		return string(safe), nil
	}

	safe := approvalPrivateKeyPattern.ReplaceAllString(diff, redactedApprovalValue)
	safe = approvalDiffHeaderPattern.ReplaceAllString(safe, `${1}`+redactedApprovalValue)
	safe = approvalBearerPattern.ReplaceAllString(safe, "Bearer "+redactedApprovalValue)
	safe = approvalDiffAssignmentPattern.ReplaceAllStringFunc(safe, func(match string) string {
		parts := approvalDiffAssignmentPattern.FindStringSubmatch(match)
		if len(parts) < 4 {
			return redactedApprovalValue
		}
		return parts[1] + parts[2] + parts[3] + redactedApprovalValue
	})

	// A private-key marker or assignment-like sensitive value surviving the
	// conservative scrub is safer to reject than to persist.
	if approvalPrivateKeyPattern.MatchString(safe) || approvalBearerPattern.MatchString(safe) {
		return "", fmt.Errorf("approval diff contains unsupported sensitive material")
	}
	return safe, nil
}

type approvalRequestDisk struct {
	ApprovalRequest
	ArgsSalt   string `json:"args_salt"`
	ArgsDigest string `json:"args_digest"`
}

type approvalStoreDisk struct {
	Requests []approvalRequestDisk `json:"requests"`
}

func (s *ApprovalStore) loadLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var disk approvalStoreDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return err
	}
	now := s.now().UTC()
	next := map[string]ApprovalRequest{}
	changed := false
	for _, diskRequest := range disk.Requests {
		request := diskRequest.ApprovalRequest
		request.ArgsSalt = diskRequest.ArgsSalt
		request.ArgsDigest = diskRequest.ArgsDigest
		if request.ID == "" {
			changed = true
			continue
		}
		if approvalExpired(request, now) && (request.Status == ApprovalPending || request.Status == ApprovalApproved) {
			changed = true
			continue
		}
		if request.Status == ApprovalExecuting {
			request.Status = ApprovalFailed
			request.DecidedAt = now
			changed = true
		}
		if request.ArgsSalt == "" {
			request.ArgsSalt, _ = newApprovalArgsSalt()
			changed = true
		}
		if request.ArgsDigest == "" {
			request.ArgsDigest, _ = approvalArgsDigest(request.Args, request.ArgsSalt)
			changed = true
		}
		redacted := redactApprovalArgs(request.Args)
		if normalized, ok := canonicalArgs(redacted); ok {
			current, _ := canonicalArgs(request.Args)
			if normalized != current {
				changed = true
			}
		}
		request.Args = redacted
		safeDiff, err := sanitizeApprovalDiff(request.Diff)
		if err != nil {
			return fmt.Errorf("sanitize persisted approval %q diff: %w", request.ID, err)
		}
		if safeDiff != request.Diff {
			request.Diff = safeDiff
			changed = true
		}
		next[request.ID] = cloneApprovalRequest(request)
	}
	s.requests = next
	if changed {
		return s.persistLocked()
	}
	return nil
}

func (s *ApprovalStore) persistLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		s.healthErr = err
		return err
	}
	items := make([]approvalRequestDisk, 0, len(s.requests))
	for _, request := range s.requests {
		cloned := cloneApprovalRequest(request)
		items = append(items, approvalRequestDisk{
			ApprovalRequest: cloned,
			ArgsSalt:        request.ArgsSalt,
			ArgsDigest:      request.ArgsDigest,
		})
	}
	raw, err := json.MarshalIndent(approvalStoreDisk{Requests: items}, "", "  ")
	if err != nil {
		s.healthErr = err
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		s.healthErr = err
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		s.healthErr = err
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		s.healthErr = err
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		s.healthErr = err
		return err
	}
	if err := tmp.Close(); err != nil {
		s.healthErr = err
		return err
	}
	if err := replaceFileAtomic(tmpName, s.path); err != nil {
		s.healthErr = err
		return err
	}
	if err := protectApprovalFile(s.path); err != nil {
		s.healthErr = err
		return err
	}
	s.healthErr = nil
	return nil
}

func approvalExpired(request ApprovalRequest, now time.Time) bool {
	return !request.ExpiresAt.IsZero() && !request.ExpiresAt.After(now)
}

func sameApprovalActor(subject, sessionID string, actor ApprovalActor) bool {
	if subject == "" || actor.Subject == "" || subject != actor.Subject {
		return false
	}
	if sessionID != "" && actor.SessionID != "" {
		return sessionID == actor.SessionID
	}
	return true
}

func requesterMatches(request ApprovalRequest, actor ApprovalActor) bool {
	if request.RequesterSubject == "" {
		return true
	}
	if actor.Subject == "" || actor.Subject != request.RequesterSubject {
		return false
	}
	if request.RequesterSessionID != "" {
		return actor.SessionID != "" && actor.SessionID == request.RequesterSessionID
	}
	return true
}

func canonicalArgs(args map[string]any) (string, bool) {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return "", false
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return "", false
	}
	raw, err = json.Marshal(normalized)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func (s *ApprovalStore) decide(id string, status ApprovalStatus) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Status != ApprovalPending {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	request.Status = status
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	return cloneApprovalRequest(request), nil
}
