package netlease

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// TemporaryHTTPExecution is the complete input for one administrator-approved
// HTTPS operation. The password is consumed during ExecuteTemporaryHTTP and is
// never retained in a session, lease, audit event, or transport object.
type TemporaryHTTPExecution struct {
	Identity         AdministratorIdentity
	Password         string
	PluginID         string
	PluginVersion    string
	Target           Target
	TLSFingerprint   string
	PolicyEpoch      uint64
	TTL              time.Duration
	MaxBytes         int64
	TLSPolicy        *TLSPolicy
	Method           string
	Path             string
	Header           http.Header
	Body             []byte
	MaxResponseBytes int64
}

// TemporaryHTTPExecutor is the narrow integration seam for a future control
// plane or plugin controller. Implementations must preserve the one-call
// lifecycle contract; callers must not receive a broker, socket, or reusable
// HTTP client to manage themselves.
type TemporaryHTTPExecutor interface {
	ExecuteTemporaryHTTP(context.Context, TemporaryHTTPExecution) (HTTPResponse, error)
}

var _ TemporaryHTTPExecutor = (*Broker)(nil)

// ExecuteTemporaryHTTP owns the entire temporary-egress lifecycle in one
// call: authenticate the current administrator session, perform a fresh
// password confirmation, atomically consume one lease, execute one brokered
// HTTPS request, record its result, and revoke both handles before returning.
// It is intentionally synchronous and creates no worker or reusable client.
func (b *Broker) ExecuteTemporaryHTTP(ctx context.Context, req TemporaryHTTPExecution) (response HTTPResponse, retErr error) {
	if b == nil {
		return HTTPResponse{}, ErrBrokerDisabled
	}
	session, err := b.BeginTemporarySession(ctx, BeginTemporarySessionRequest{Identity: req.Identity, TTL: req.TTL})
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("temporary network session: %w", err)
	}
	var lease Lease
	defer func() {
		var cleanupErr error
		if lease.ID != "" {
			if err := b.Revoke(lease.ID); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("revoke temporary lease: %w", err))
			}
		}
		if err := b.sessions.Revoke(session.ID); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("revoke temporary session: %w", err))
		}
		if cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	lease, err = b.IssueTemporary(ctx, ConfirmationInput{
		SessionID:      session.ID,
		Password:       req.Password,
		PluginID:       req.PluginID,
		PluginVersion:  req.PluginVersion,
		Target:         req.Target,
		TLSFingerprint: req.TLSFingerprint,
		PolicyEpoch:    req.PolicyEpoch,
		TTL:            req.TTL,
		MaxBytes:       req.MaxBytes,
	})
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("temporary network lease: %w", err)
	}

	return b.DoHTTP(ctx, HTTPRequest{
		LeaseID:          lease.ID,
		Scope:            RequestScope{PluginID: req.PluginID, PluginVersion: req.PluginVersion, Target: req.Target, TLSFingerprint: req.TLSFingerprint, PolicyEpoch: req.PolicyEpoch, OperatorID: req.Identity.ID, TemporaryEgress: true},
		TLSPolicy:        req.TLSPolicy,
		Method:           req.Method,
		Path:             req.Path,
		Header:           req.Header,
		Body:             req.Body,
		MaxResponseBytes: req.MaxResponseBytes,
	})
}
