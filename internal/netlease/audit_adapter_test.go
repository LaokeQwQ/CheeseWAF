package netlease

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

type auditAppenderFunc struct {
	event audit.Event
	err   error
}

func (f *auditAppenderFunc) Append(_ context.Context, event audit.Event) (audit.Record, error) {
	if f.err != nil {
		return audit.Record{}, f.err
	}
	f.event = event
	return audit.Record{Event: event}, nil
}

type auditSinkFunc struct {
	event AuditEvent
	err   error
}

func (f *auditSinkFunc) Append(_ context.Context, event AuditEvent) error {
	f.event = event
	return f.err
}

func validCanonicalAuditFixture() AuditEvent {
	return AuditEvent{
		LeaseID: "lease-a", Action: "result", PluginID: "plugin-a", PluginVersion: "1.2.3",
		TargetHost: "updates.example.test", TargetPort: 443, TargetProtocol: "https",
		TLSFingerprint: "sha256:" + strings.Repeat("a", 64), PolicyEpoch: 7,
		TemporaryEgress: true, ConfirmationID: "confirmation-a", ResourceID: "resource-a",
		OperatorID: "admin-a", Bytes: 12, BytesSent: 4, BytesReceived: 8, Requests: 1,
		Result: "http_200", Reason: "http_200", At: time.Unix(1700000000, 0).UTC(),
	}
}

func TestCanonicalAuditSinkMapsMetadataAndDoesNotCopyTarget(t *testing.T) {
	appender := &auditAppenderFunc{}
	legacy := &auditSinkFunc{}
	sink, err := NewCanonicalAuditSink(appender, legacy)
	if err != nil {
		t.Fatal(err)
	}
	event := validCanonicalAuditFixture()
	if err := sink.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if appender.event.EventID == "" || appender.event.Type != audit.EventTypeLeaseChanged || appender.event.Outcome != audit.OutcomeSuccess {
		t.Fatalf("canonical event=%+v", appender.event)
	}
	if appender.event.Resource != "lease:lease-a" || appender.event.LeaseID != event.LeaseID || appender.event.PolicyEpoch != event.PolicyEpoch {
		t.Fatalf("canonical binding=%+v", appender.event)
	}
	raw, err := json.Marshal(appender.event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), event.TargetHost) || strings.Contains(string(raw), event.TLSFingerprint) {
		t.Fatalf("canonical event copied sensitive target metadata: %s", raw)
	}
	if legacy.event.LeaseID != event.LeaseID {
		t.Fatalf("compatibility event=%+v", legacy.event)
	}
	firstID := appender.event.EventID
	if err := sink.Append(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if appender.event.EventID != firstID {
		t.Fatalf("event id changed across retry: %q != %q", appender.event.EventID, firstID)
	}
}

func TestCanonicalAuditSinkRejectsUnallowlistedAction(t *testing.T) {
	appender := &auditAppenderFunc{}
	sink, err := NewCanonicalAuditSink(appender, nil)
	if err != nil {
		t.Fatal(err)
	}
	event := validCanonicalAuditFixture()
	event.Action = "internal_secret"
	if err := sink.Append(context.Background(), event); !errors.Is(err, ErrCanonicalAuditMapping) {
		t.Fatalf("err=%v, want mapping rejection", err)
	}
	if appender.event.EventID != "" {
		t.Fatal("unallowlisted event reached canonical appender")
	}
}

func TestCanonicalAuditSinkPropagatesCanonicalAndCompatibilityErrors(t *testing.T) {
	canonicalErr := errors.New("canonical unavailable")
	appender := &auditAppenderFunc{err: canonicalErr}
	legacy := &auditSinkFunc{}
	sink, err := NewCanonicalAuditSink(appender, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Append(context.Background(), validCanonicalAuditFixture()); !errors.Is(err, canonicalErr) {
		t.Fatalf("canonical err=%v", err)
	}
	if legacy.event.LeaseID != "" {
		t.Fatal("legacy sink ran after canonical failure")
	}

	appender.err = nil
	legacy.err = errors.New("compatibility unavailable")
	if err := sink.Append(context.Background(), validCanonicalAuditFixture()); !errors.Is(err, legacy.err) {
		t.Fatalf("compatibility err=%v", err)
	}
}
