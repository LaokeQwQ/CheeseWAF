package ai

import (
	"encoding/json"
	"fmt"
	"reflect"
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
)

type ApprovalRequest struct {
	ID          string          `json:"id"`
	ToolName    string          `json:"tool_name"`
	Args        map[string]any  `json:"args"`
	Sensitivity ToolSensitivity `json:"sensitivity"`
	Diff        string          `json:"diff,omitempty"`
	Status      ApprovalStatus  `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	DecidedAt   time.Time       `json:"decided_at,omitempty"`
}

type ApprovalStore struct {
	mu       sync.RWMutex
	requests map[string]ApprovalRequest
	now      func() time.Time
}

func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{requests: map[string]ApprovalRequest{}, now: time.Now}
}

func (s *ApprovalStore) Create(tool Tool, args map[string]any, diff string) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	if tool == nil {
		return ApprovalRequest{}, fmt.Errorf("tool is nil")
	}
	request := ApprovalRequest{
		ID:          uuid.NewString(),
		ToolName:    tool.Name(),
		Args:        cloneArgs(args),
		Sensitivity: tool.Sensitivity(),
		Diff:        diff,
		Status:      ApprovalPending,
		CreatedAt:   s.now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[request.ID] = request
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) Approve(id string) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Status == ApprovalApproved {
		return cloneApprovalRequest(request), nil
	}
	if request.Status != ApprovalPending {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	request.Status = ApprovalApproved
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) Reject(id string) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Status != ApprovalPending && request.Status != ApprovalApproved {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	request.Status = ApprovalRejected
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) ConsumeApproved(id string, toolName string, args map[string]any) (ApprovalRequest, error) {
	return s.BeginExecution(id, toolName, args)
}

func (s *ApprovalStore) BeginExecution(id string, toolName string, args map[string]any) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[id]
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("approval request %q not found", id)
	}
	if request.Status != ApprovalApproved {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q is %s, not approved", id, request.Status)
	}
	if request.ToolName != toolName {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q belongs to tool %q", id, request.ToolName)
	}
	if !sameArgs(request.Args, args) {
		return cloneApprovalRequest(request), fmt.Errorf("approval request %q arguments do not match", id)
	}
	request.Status = ApprovalExecuting
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	return cloneApprovalRequest(request), nil
}

func (s *ApprovalStore) MarkExecuted(id string) (ApprovalRequest, error) {
	return s.finishExecution(id, ApprovalExecuted)
}

func (s *ApprovalStore) MarkExecutionFailed(id string) (ApprovalRequest, error) {
	return s.finishExecution(id, ApprovalApproved)
}

func (s *ApprovalStore) finishExecution(id string, status ApprovalStatus) (ApprovalRequest, error) {
	if s == nil {
		return ApprovalRequest{}, fmt.Errorf("approval store is nil")
	}
	if status != ApprovalApproved && status != ApprovalExecuted {
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
	request.Status = status
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
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

func sameArgs(left, right map[string]any) bool {
	leftNorm, leftOK := canonicalArgs(left)
	rightNorm, rightOK := canonicalArgs(right)
	if leftOK && rightOK {
		return leftNorm == rightNorm
	}
	return reflect.DeepEqual(left, right)
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
