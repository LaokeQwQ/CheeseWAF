package netlease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

var ErrCanonicalAuditMapping = errors.New("netlease audit event cannot be mapped to canonical audit")

// CanonicalAuditSink mirrors accepted temporary-network metadata into the
// append-only audit runtime. The legacy sink remains an explicitly supplied
// compatibility copy; it is never used to substitute for the canonical sink.
type CanonicalAuditSink struct {
	appender audit.EventAppender
	legacy   AuditSink
}

func NewCanonicalAuditSink(appender audit.EventAppender, legacy AuditSink) (*CanonicalAuditSink, error) {
	if appender == nil {
		return nil, ErrAuditUnavailable
	}
	return &CanonicalAuditSink{appender: appender, legacy: legacy}, nil
}

// Durable reports whether the underlying appender promises durable storage.
// Production wiring refuses a broker whose audit sink is not durable.
func (s *CanonicalAuditSink) Durable() bool {
	if s == nil || s.appender == nil {
		return false
	}
	durable, ok := s.appender.(interface{ Durable() bool })
	return ok && durable.Durable()
}

func (s *CanonicalAuditSink) Append(ctx context.Context, event AuditEvent) error {
	if s == nil || s.appender == nil || !validAuditEvent(event) {
		return ErrAuditUnavailable
	}
	canonical, err := canonicalAuditEvent(event)
	if err != nil {
		return err
	}
	if _, err := s.appender.Append(ctx, canonical); err != nil {
		return fmt.Errorf("append canonical netlease audit: %w", err)
	}
	if s.legacy != nil {
		if err := s.legacy.Append(ctx, event); err != nil {
			return fmt.Errorf("append netlease compatibility audit: %w", err)
		}
	}
	return nil
}

var canonicalAuditActions = map[string]struct{}{
	"issued": {}, "authorized": {}, "consumed": {}, "connection_started": {},
	"result": {}, "revoked": {}, "authorization_denied": {}, "consume_denied": {},
	"result_denied": {},
}

func canonicalAuditEvent(event AuditEvent) (audit.Event, error) {
	if _, ok := canonicalAuditActions[event.Action]; !ok {
		return audit.Event{}, fmt.Errorf("%w: action %q", ErrCanonicalAuditMapping, event.Action)
	}
	actor := event.OperatorID
	if actor == "" {
		actor = "system"
	}
	outcome := audit.OutcomeFailure
	switch {
	case event.Action == "connection_started":
		outcome = audit.OutcomeStarted
	case event.Action == "authorization_denied" || event.Action == "consume_denied" || event.Action == "result_denied" || strings.HasSuffix(event.Result, "_denied"):
		outcome = audit.OutcomeDenied
	case event.Result == "issued" || event.Result == "authorized" || event.Result == "consumed" || event.Result == "revoked" || event.Result == "success" || strings.HasPrefix(event.Result, "http_"):
		outcome = audit.OutcomeSuccess
	}
	return audit.Event{
		EventID:         canonicalAuditEventID(event),
		StreamID:        "management",
		TenantID:        "system",
		Actor:           actor,
		Type:            audit.EventTypeLeaseChanged,
		Action:          "temporary_egress." + event.Action,
		Resource:        "lease:" + event.LeaseID,
		Outcome:         outcome,
		AuthorizationID: event.ConfirmationID,
		LeaseID:         event.LeaseID,
		Reason:          canonicalReason(event),
		EvidenceDigest:  canonicalEvidenceDigest(event),
		PolicyEpoch:     event.PolicyEpoch,
		Class:           audit.EventClassCritical,
		At:              event.At.UTC(),
	}, nil
}

func canonicalReason(event AuditEvent) string {
	if event.Reason != "" && safeAuditToken(event.Reason) {
		return event.Reason
	}
	if event.Result != "" && safeAuditToken(event.Result) {
		return event.Result
	}
	return "audit_event"
}

func canonicalAuditEventID(event AuditEvent) string {
	return "netlease-" + canonicalEvidenceDigest(event)[:32]
}

func canonicalEvidenceDigest(event AuditEvent) string {
	// Hash the complete validated netlease metadata, including target and pin,
	// so canonical audit stores evidence without copying sensitive target data.
	body, _ := json.Marshal(struct {
		LeaseID, Action, PluginID, PluginVersion   string
		TargetHost, TargetProtocol, ConfirmationID string
		ResourceID, OperatorID, TLSFingerprint     string
		TargetPort                                 int
		PolicyEpoch                                uint64
		TemporaryEgress                            bool
		Bytes, BytesSent, BytesReceived, Requests  int64
		Result, Reason                             string
		At                                         string
	}{event.LeaseID, event.Action, event.PluginID, event.PluginVersion, event.TargetHost, event.TargetProtocol, event.ConfirmationID, event.ResourceID, event.OperatorID, event.TLSFingerprint, event.TargetPort, event.PolicyEpoch, event.TemporaryEgress, event.Bytes, event.BytesSent, event.BytesReceived, event.Requests, event.Result, event.Reason, event.At.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
