// Package hostapi defines the local, capability-scoped data plane between the
// CheeseWAF host and an executable plugin. It deliberately has no network,
// filesystem, database, or secret-store dependency.
package hostapi

import "encoding/json"

const (
	// ProtocolVersion is the only wire version accepted by this package.
	ProtocolVersion = "cheesewaf-plugin-host/v1"
	// MaxFrameBytes bounds one newline-delimited JSON frame.
	MaxFrameBytes = 64 << 10
	// MaxFrameDepth bounds nested JSON values before a frame is rejected.
	MaxFrameDepth = 64
)

// FrameType is the closed set of host data-plane frame types.
type FrameType string

const (
	FrameHello           FrameType = "hello"
	FrameReady           FrameType = "ready"
	FrameConfig          FrameType = "config"
	FrameConfigAck       FrameType = "config_ack"
	FrameEvent           FrameType = "event"
	FrameEventAck        FrameType = "event_ack"
	FrameJob             FrameType = "job"
	FrameJobAck          FrameType = "job_ack"
	FrameHint            FrameType = "hint"
	FrameHintReceipt     FrameType = "hint_receipt"
	FrameAnalysis        FrameType = "analysis"
	FrameAnalysisReceipt FrameType = "analysis_receipt"
	FrameHealth          FrameType = "health"
	FrameDrain           FrameType = "drain"
	FrameDrained         FrameType = "drained"
	FrameShutdown        FrameType = "shutdown"
	FrameError           FrameType = "error"
)

var validFrameTypes = map[FrameType]struct{}{
	FrameHello: {}, FrameReady: {}, FrameConfig: {}, FrameConfigAck: {},
	FrameEvent: {}, FrameEventAck: {}, FrameJob: {}, FrameJobAck: {},
	FrameHint: {}, FrameHintReceipt: {}, FrameAnalysis: {}, FrameAnalysisReceipt: {},
	FrameHealth: {}, FrameDrain: {}, FrameDrained: {}, FrameShutdown: {}, FrameError: {},
}

// Valid reports whether t is a protocol frame type.
func (t FrameType) Valid() bool {
	_, ok := validFrameTypes[t]
	return ok
}

// NeedsSequence reports whether a frame must carry a non-zero sequence.
func (t FrameType) NeedsSequence() bool {
	return t != FrameHello && t != FrameReady
}

// Capability is a host-granted data-plane capability.
type Capability string

const (
	CapabilityEventsSubscribe Capability = "events.subscribe"
	CapabilityHintsSubmit     Capability = "hints.submit"
	CapabilityAnalysisSubmit  Capability = "analysis.submit"
	CapabilityDiagnostics     Capability = "diagnostics.submit"
	CapabilityHealth          Capability = "health.report"
	CapabilityConfigRead      Capability = "config.read"
)

var validCapabilities = map[Capability]struct{}{
	CapabilityEventsSubscribe: {}, CapabilityHintsSubmit: {}, CapabilityAnalysisSubmit: {},
	CapabilityDiagnostics: {}, CapabilityHealth: {}, CapabilityConfigRead: {},
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	_, ok := validCapabilities[c]
	return ok
}

func frameCapability(frameType FrameType) Capability {
	switch frameType {
	case FrameEvent:
		return CapabilityEventsSubscribe
	case FrameJob, FrameAnalysis:
		return CapabilityAnalysisSubmit
	case FrameConfig:
		return CapabilityConfigRead
	case FrameHint:
		return CapabilityHintsSubmit
	case FrameHealth:
		return CapabilityHealth
	default:
		return ""
	}
}

// ErrorCode is a stable, non-sensitive error classification.
type ErrorCode string

const (
	ErrorInvalidFrame     ErrorCode = "invalid_frame"
	ErrorFrameTooLarge    ErrorCode = "frame_too_large"
	ErrorDuplicateField   ErrorCode = "duplicate_field"
	ErrorUnknownType      ErrorCode = "unknown_type"
	ErrorCapabilityDenied ErrorCode = "capability_denied"
	ErrorSchemaInvalid    ErrorCode = "schema_invalid"
	ErrorSequenceGap      ErrorCode = "sequence_gap"
	ErrorQueueFull        ErrorCode = "queue_full"
	ErrorAckTimeout       ErrorCode = "ack_timeout"
	ErrorPlugin           ErrorCode = "plugin_error"
	ErrorShuttingDown     ErrorCode = "shutting_down"
	ErrorInternal         ErrorCode = "internal"
)

// Identity is the immutable plugin identity bound to a session.
type Identity struct {
	PluginID         string `json:"plugin_id"`
	Namespace        string `json:"namespace"`
	Version          string `json:"version"`
	ManifestIdentity string `json:"manifest_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
}

// Frame is the outer envelope. Payload is interpreted only after Type and
// SchemaVersion have been validated and only within the negotiated capability.
type Frame struct {
	Type          FrameType       `json:"type"`
	SchemaVersion string          `json:"schema_version"`
	Sequence      uint64          `json:"sequence,omitempty"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}
