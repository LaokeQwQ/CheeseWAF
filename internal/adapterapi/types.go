// Package adapterapi implements the core-side HTTP contract used by
// CheeseWAF-Adapters. The JSON shape intentionally mirrors
// contracts/inspection/v1 in the adapter repository.
package adapterapi

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

const Version = "v1"

type Action string

const (
	ActionAllow     Action = "allow"
	ActionLog       Action = "log"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
)

type BodyState string

const (
	BodyStateAbsent      BodyState = "absent"
	BodyStateWithheld    BodyState = "withheld"
	BodyStateForwarded   BodyState = "forwarded"
	BodyStateTruncated   BodyState = "truncated"
	BodyStateUnsupported BodyState = "unsupported"
)

type Source string

const (
	SourceGeneric      Source = "generic"
	SourceNginxAuth    Source = "nginx-auth-request"
	SourceEnvoyAuth    Source = "envoy-ext-authz"
	SourceEnvoyExtProc Source = "envoy-ext-proc"
	SourceOOBMirror    Source = "oob-mirror"
)

const (
	maxRequestIDBytes      = 256
	maxAuthorityBytes      = 4 * 1024
	maxPathBytes           = 16 * 1024
	maxQueryBytes          = 64 * 1024
	maxHeaderCount         = 256
	maxHeaderValueBytes    = 16 * 1024
	maxHeadersBytes        = 64 * 1024
	maxBodyEncodingBytes   = 64
	maxInspectBodyBytes    = 32 << 20
	maxDecisionBodyBytes   = 64 * 1024
	maxDecisionContentType = 256
	maxDecisionHeaders     = 64
	maxDecisionHeaderBytes = 64 * 1024
	maxSetCookies          = 8
	maxSetCookieBytes      = 4 * 1024
)

type Request struct {
	ContractVersion string              `json:"contract_version"`
	RequestID       string              `json:"request_id,omitempty"`
	Source          Source              `json:"source"`
	Method          string              `json:"method"`
	Scheme          string              `json:"scheme,omitempty"`
	Authority       string              `json:"authority,omitempty"`
	Path            string              `json:"path"`
	Query           string              `json:"query,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	BodyState       BodyState           `json:"body_state,omitempty"`
	BodyForwarded   bool                `json:"body_forwarded,omitempty"`
	Body            []byte              `json:"body,omitempty"`
	BodyTruncated   bool                `json:"body_truncated,omitempty"`
	BodyEncoding    string              `json:"body_encoding,omitempty"`
	Client          ClientContext       `json:"client,omitempty"`
	TLS             TLSContext          `json:"tls,omitempty"`
	Response        *ResponseContext    `json:"response,omitempty"`
	ObservedAt      time.Time           `json:"observed_at,omitempty"`
}

type ClientContext struct {
	IP        string `json:"ip,omitempty"`
	Port      string `json:"port,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type TLSContext struct {
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
}

type ResponseContext struct {
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Latency    time.Duration       `json:"latency_ns,omitempty"`
}

type Decision struct {
	ContractVersion string            `json:"contract_version"`
	Action          Action            `json:"action"`
	StatusCode      int               `json:"status_code,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	RuleID          string            `json:"rule_id,omitempty"`
	PolicyVersion   string            `json:"policy_version,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	SetCookies      []string          `json:"set_cookies,omitempty"`
	Body            []byte            `json:"body,omitempty"`
	BodyContentType string            `json:"body_content_type,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type TelemetryEvent struct {
	ContractVersion string `json:"contract_version"`
	RequestID       string `json:"request_id,omitempty"`
	Source          Source `json:"source"`
	Action          Action `json:"action"`
	Path            string `json:"path,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	LatencyNanos    int64  `json:"latency_ns,omitempty"`
	PolicyVersion   string `json:"policy_version,omitempty"`
}

func (r Request) Validate() error {
	if r.ContractVersion != "" && r.ContractVersion != Version {
		return fmt.Errorf("unsupported contract version %q", r.ContractVersion)
	}
	if !validToken(r.Method) {
		return fmt.Errorf("invalid method")
	}
	if r.Source != "" && !validSource(r.Source) {
		return fmt.Errorf("unsupported source %q", r.Source)
	}
	if r.Path == "" || !strings.HasPrefix(r.Path, "/") || !validText(r.Path, maxPathBytes) {
		return fmt.Errorf("invalid path")
	}
	if strings.ContainsAny(r.Path, "?#\\ ") {
		return fmt.Errorf("path contains an unencoded delimiter")
	}
	if !validText(r.Query, maxQueryBytes) || strings.ContainsAny(r.Query, "\r\n#") {
		return fmt.Errorf("invalid query")
	}
	if r.Authority != "" && (!validText(r.Authority, maxAuthorityBytes) || strings.ContainsAny(r.Authority, "\r\n/?#\\@, ")) {
		return fmt.Errorf("invalid authority")
	}
	if r.RequestID != "" && !validText(r.RequestID, maxRequestIDBytes) {
		return fmt.Errorf("invalid request id")
	}
	if r.Client.IP != "" {
		if _, err := netip.ParseAddr(r.Client.IP); err != nil {
			return fmt.Errorf("invalid client ip")
		}
	}
	if r.Client.UserAgent != "" && !validText(r.Client.UserAgent, maxHeaderValueBytes) {
		return fmt.Errorf("invalid user agent")
	}
	if err := validateHeaders(r.Headers); err != nil {
		return err
	}
	if len(r.Body) > maxInspectBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxInspectBodyBytes)
	}
	if r.BodyEncoding != "" && (!validToken(r.BodyEncoding) || len(r.BodyEncoding) > maxBodyEncodingBytes) {
		return fmt.Errorf("invalid body encoding")
	}
	return validateBodyState(r)
}

func validateBodyState(r Request) error {
	switch r.BodyState {
	case "":
		if len(r.Body) > 0 && !r.BodyForwarded {
			return fmt.Errorf("body is present but not marked as forwarded")
		}
		if r.BodyTruncated && !r.BodyForwarded {
			return fmt.Errorf("truncated body must be marked as forwarded")
		}
	case BodyStateAbsent, BodyStateWithheld, BodyStateUnsupported:
		if r.BodyForwarded || r.BodyTruncated || len(r.Body) > 0 {
			return fmt.Errorf("%s body must not be forwarded", r.BodyState)
		}
	case BodyStateForwarded:
		if !r.BodyForwarded || r.BodyTruncated {
			return fmt.Errorf("forwarded body state requires body_forwarded and no truncation")
		}
	case BodyStateTruncated:
		if !r.BodyForwarded || !r.BodyTruncated {
			return fmt.Errorf("truncated body state requires body_forwarded and body_truncated")
		}
	default:
		return fmt.Errorf("unsupported body state %q", r.BodyState)
	}
	return nil
}

func (d Decision) Validate() error {
	if d.ContractVersion != "" && d.ContractVersion != Version {
		return fmt.Errorf("unsupported contract version %q", d.ContractVersion)
	}
	switch d.Action {
	case ActionAllow, ActionLog, ActionBlock, ActionChallenge:
	default:
		return fmt.Errorf("unsupported action %q", d.Action)
	}
	if d.StatusCode != 0 {
		if d.Action == ActionAllow || d.Action == ActionLog {
			if d.StatusCode < 200 || d.StatusCode >= 300 {
				return fmt.Errorf("allow/log status must be 2xx")
			}
		} else if d.StatusCode < 400 || d.StatusCode >= 500 {
			return fmt.Errorf("block/challenge status must be 4xx")
		}
	}
	if len(d.Headers) > maxDecisionHeaders {
		return fmt.Errorf("too many decision headers")
	}
	for key, value := range d.Headers {
		if !validHeaderName(key) || !validText(value, maxHeaderValueBytes) {
			return fmt.Errorf("invalid decision header")
		}
	}
	if len(d.SetCookies) > maxSetCookies {
		return fmt.Errorf("too many set-cookie values")
	}
	for _, cookie := range d.SetCookies {
		if cookie == "" || len(cookie) > maxSetCookieBytes || !validText(cookie, maxSetCookieBytes) {
			return fmt.Errorf("invalid set-cookie value")
		}
	}
	if len(d.Body) > maxDecisionBodyBytes {
		return fmt.Errorf("decision body exceeds %d bytes", maxDecisionBodyBytes)
	}
	if d.BodyContentType != "" && (!validText(d.BodyContentType, maxDecisionContentType) || len(d.BodyContentType) > maxDecisionContentType) {
		return fmt.Errorf("invalid body content type")
	}
	return nil
}

func (d Decision) Normalized() Decision {
	if d.ContractVersion == "" {
		d.ContractVersion = Version
	}
	if d.Action == ActionBlock && d.StatusCode == 0 {
		d.StatusCode = 403
	}
	if d.Action == ActionChallenge && d.StatusCode == 0 {
		d.StatusCode = 401
	}
	if len(d.Body) > 0 && d.BodyContentType == "" {
		d.BodyContentType = "text/plain; charset=utf-8"
	}
	return d
}

func (e TelemetryEvent) Validate() error {
	if e.ContractVersion != Version {
		return fmt.Errorf("unsupported contract version %q", e.ContractVersion)
	}
	if !validSource(e.Source) {
		return fmt.Errorf("unsupported source %q", e.Source)
	}
	switch e.Action {
	case ActionAllow, ActionLog, ActionBlock, ActionChallenge:
	default:
		return fmt.Errorf("unsupported action %q", e.Action)
	}
	if e.StatusCode != 0 && (e.StatusCode < 200 || e.StatusCode > 599) {
		return fmt.Errorf("invalid status code")
	}
	if e.RequestID != "" && !validText(e.RequestID, maxRequestIDBytes) {
		return fmt.Errorf("invalid request id")
	}
	if e.Path != "" {
		if !strings.HasPrefix(e.Path, "/") || !validText(e.Path, maxPathBytes) {
			return fmt.Errorf("invalid path")
		}
	}
	if e.PolicyVersion != "" && !validText(e.PolicyVersion, 256) {
		return fmt.Errorf("invalid policy version")
	}
	if e.LatencyNanos < 0 {
		return fmt.Errorf("latency must be non-negative")
	}
	return nil
}

func validSource(source Source) bool {
	switch source {
	case SourceGeneric, SourceNginxAuth, SourceEnvoyAuth, SourceEnvoyExtProc, SourceOOBMirror:
		return true
	default:
		return false
	}
}

func validateHeaders(headers map[string][]string) error {
	if len(headers) > maxHeaderCount {
		return fmt.Errorf("too many request headers")
	}
	total := 0
	for name, values := range headers {
		if !validHeaderName(name) || len(values) == 0 {
			return fmt.Errorf("invalid request header")
		}
		for _, value := range values {
			if !validText(value, maxHeaderValueBytes) {
				return fmt.Errorf("invalid request header value")
			}
			total += len(name) + len(value)
			if total > maxHeadersBytes {
				return fmt.Errorf("request headers exceed %d bytes", maxHeadersBytes)
			}
		}
	}
	return nil
}

func validText(value string, maxBytes int) bool {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}

func validHeaderName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}
