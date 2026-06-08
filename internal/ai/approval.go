package ai

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
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
		Args:        args,
		Sensitivity: tool.Sensitivity(),
		Diff:        diff,
		Status:      ApprovalPending,
		CreatedAt:   s.now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[request.ID] = request
	return request, nil
}

func (s *ApprovalStore) Approve(id string) (ApprovalRequest, error) {
	return s.decide(id, ApprovalApproved)
}

func (s *ApprovalStore) Reject(id string) (ApprovalRequest, error) {
	return s.decide(id, ApprovalRejected)
}

func (s *ApprovalStore) Get(id string) (ApprovalRequest, bool) {
	if s == nil {
		return ApprovalRequest{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	request, ok := s.requests[id]
	return request, ok
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
		return request, fmt.Errorf("approval request %q is already %s", id, request.Status)
	}
	request.Status = status
	request.DecidedAt = s.now().UTC()
	s.requests[id] = request
	return request, nil
}
