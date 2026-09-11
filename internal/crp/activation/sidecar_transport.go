package activation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

const sidecarStartPath = "/v1/crp/sidecars/start"

type SidecarStartRequest struct {
	SchemaVersion string            `json:"schema_version"`
	Authorization Authorization     `json:"authorization"`
	Descriptor    SidecarDescriptor `json:"descriptor"`
	Target        RuntimeTarget     `json:"target"`
	Mode          SidecarMode       `json:"mode"`
}

type SidecarOperationRequest struct {
	SchemaVersion string        `json:"schema_version"`
	Authorization Authorization `json:"authorization"`
	HandleID      string        `json:"handle_id"`
	Mode          SidecarMode   `json:"mode"`
}

type SidecarAcknowledgement struct {
	SchemaVersion    string      `json:"schema_version"`
	AuthorizationID  string      `json:"authorization_id"`
	RequestID        string      `json:"request_id"`
	NodeID           string      `json:"node_id"`
	HandleID         string      `json:"handle_id"`
	PluginKey        string      `json:"plugin_key"`
	ManifestIdentity string      `json:"manifest_identity"`
	Mode             SidecarMode `json:"mode"`
	Status           string      `json:"status"`
}

// HTTPSidecarManager controls an approved launcher over authenticated HTTPS.
// Every operation carries the exact control-plane authorization so the
// launcher can independently enforce node, source, permission, and fence.
type HTTPSidecarManager struct {
	endpoint  *url.URL
	transport *MTLSClient
	clock     func() time.Time
}

func NewHTTPSidecarManager(endpoint string, transport *MTLSClient, clock func() time.Time) (*HTTPSidecarManager, error) {
	base, err := parseTransportEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if transport == nil || transport.client == nil {
		return nil, fmt.Errorf("%w: mTLS client is required", ErrTransportConfig)
	}
	if clock == nil {
		clock = time.Now
	}
	return &HTTPSidecarManager{endpoint: base, transport: transport, clock: clock}, nil
}

func (m *HTTPSidecarManager) TransportIdentity() TransportIdentity {
	if m == nil || m.transport == nil {
		return TransportIdentity{}
	}
	return m.transport.TransportIdentity()
}

func (m *HTTPSidecarManager) Start(ctx context.Context, descriptor SidecarDescriptor, record crp.RuntimeRecord, opts StartOptions) (Sidecar, error) {
	if m == nil {
		return nil, ErrSidecarUnavailable
	}
	if opts.Mode != SidecarModeObserve {
		return nil, fmt.Errorf("%w: launcher must start in observe mode", ErrSidecar)
	}
	authorization := opts.Authorization
	if err := validateAuthorization(authorization, authorization.Request, m.clock().UTC()); err != nil {
		return nil, err
	}
	if !sameTransportIdentity(authorization.Request.Identity, m.TransportIdentity()) || canonicalIdentity(authorization.Request.Descriptor) != canonicalIdentity(descriptor) || authorization.Request.Target != runtimeTarget(record) {
		return nil, ErrAuthorizationBinding
	}
	request := SidecarStartRequest{
		SchemaVersion: TransportSchemaVersion, Authorization: authorization,
		Descriptor: cloneDescriptor(descriptor), Target: runtimeTarget(record), Mode: opts.Mode,
	}
	var response SidecarAcknowledgement
	if err := m.post(ctx, sidecarStartPath, request, &response); err != nil {
		return nil, mapSidecarError("start", err)
	}
	if !validSidecarHandle(response.HandleID) || validateSidecarAcknowledgement(response, authorization, record, opts.Mode, "started") != nil {
		return nil, ErrAuthorizationBinding
	}
	return &httpSidecar{manager: m, authorization: authorization, target: runtimeTarget(record), handleID: response.HandleID, mode: SidecarModeObserve}, nil
}

func (m *HTTPSidecarManager) post(ctx context.Context, endpointPath string, input, output any) error {
	return m.transport.postJSON(ctx, resolveTransportPath(m.endpoint, endpointPath), input, output)
}

type httpSidecar struct {
	manager       *HTTPSidecarManager
	authorization Authorization
	target        RuntimeTarget
	handleID      string

	mu      sync.Mutex
	mode    SidecarMode
	stopped bool
}

func (s *httpSidecar) SetMode(ctx context.Context, mode SidecarMode) error {
	if s == nil || s.manager == nil {
		return ErrSidecarUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return fmt.Errorf("%w: sidecar is stopped", ErrSidecar)
	}
	if err := validateAuthorization(s.authorization, s.authorization.Request, s.manager.clock().UTC()); err != nil {
		return err
	}
	if s.mode == SidecarModeObserve && mode != SidecarModeCanary || s.mode == SidecarModeCanary && mode != SidecarModeActive || s.mode == SidecarModeActive {
		return fmt.Errorf("%w: invalid mode transition %s to %s", ErrSidecar, s.mode, mode)
	}
	request := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: s.authorization, HandleID: s.handleID, Mode: mode}
	var response SidecarAcknowledgement
	if err := s.manager.post(ctx, sidecarOperationPath(s.handleID, "mode"), request, &response); err != nil {
		return mapSidecarError("set mode", err)
	}
	if err := validateSidecarAcknowledgementForTarget(response, s.authorization, s.target, s.handleID, mode, "mode_set"); err != nil {
		return err
	}
	s.mode = mode
	return nil
}

func (s *httpSidecar) Probe(ctx context.Context) error {
	if s == nil || s.manager == nil {
		return ErrSidecarUnavailable
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return fmt.Errorf("%w: sidecar is stopped", ErrSidecar)
	}
	mode := s.mode
	s.mu.Unlock()
	if err := validateAuthorization(s.authorization, s.authorization.Request, s.manager.clock().UTC()); err != nil {
		return err
	}
	request := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: s.authorization, HandleID: s.handleID, Mode: mode}
	var response SidecarAcknowledgement
	if err := s.manager.post(ctx, sidecarOperationPath(s.handleID, "probe"), request, &response); err != nil {
		return mapSidecarError("probe", err)
	}
	return validateSidecarAcknowledgementForTarget(response, s.authorization, s.target, s.handleID, mode, "healthy")
}

func (s *httpSidecar) Stop(ctx context.Context) error {
	if s == nil || s.manager == nil {
		return ErrSidecarUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	request := SidecarOperationRequest{SchemaVersion: TransportSchemaVersion, Authorization: s.authorization, HandleID: s.handleID, Mode: s.mode}
	var response SidecarAcknowledgement
	if err := s.manager.post(ctx, sidecarOperationPath(s.handleID, "stop"), request, &response); err != nil {
		return mapSidecarError("stop", err)
	}
	if err := validateSidecarAcknowledgementForTarget(response, s.authorization, s.target, s.handleID, s.mode, "stopped"); err != nil {
		return err
	}
	s.stopped = true
	return nil
}

func sidecarOperationPath(handleID, operation string) string {
	return "/v1/crp/sidecars/" + handleID + "/" + operation
}

func validateSidecarAcknowledgement(response SidecarAcknowledgement, authorization Authorization, record crp.RuntimeRecord, mode SidecarMode, status string) error {
	return validateSidecarAcknowledgementForTarget(response, authorization, runtimeTarget(record), "", mode, status)
}

func validateSidecarAcknowledgementForTarget(response SidecarAcknowledgement, authorization Authorization, target RuntimeTarget, handleID string, mode SidecarMode, status string) error {
	if response.SchemaVersion != TransportSchemaVersion || response.AuthorizationID != authorization.ID || response.RequestID != authorization.Request.RequestID || response.NodeID != authorization.Request.Identity.NodeID || response.PluginKey != target.Key || response.ManifestIdentity != target.ManifestIdentity || response.Mode != mode || response.Status != status || !validSidecarHandle(response.HandleID) || handleID != "" && response.HandleID != handleID {
		return ErrAuthorizationBinding
	}
	return nil
}

func validSidecarHandle(value string) bool {
	if !validTransportField(value, 128) {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func mapSidecarError(operation string, err error) error {
	var status httpStatusError
	if errors.As(err, &status) {
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusConflict || status == http.StatusGone {
			return fmt.Errorf("%w: %s", ErrAuthorizationDenied, operation)
		}
	}
	if errors.Is(err, ErrTransportProtocol) || errors.Is(err, ErrTransportConfig) {
		return err
	}
	return fmt.Errorf("%w: %s transport", ErrSidecarUnavailable, operation)
}
