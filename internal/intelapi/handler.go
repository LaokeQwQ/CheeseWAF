// Package intelapi exposes the intelligence review pipeline over HTTP.
//
// Every mutation is review-first: imported candidates are always stored
// disabled, log-only, and in the draft state, and no endpoint enables or
// activates a rule on its own. The handler is meant to be mounted behind the
// management-plane authentication middleware; an optional Authorizer is invoked
// before every request for defense in depth.
package intelapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/pipeline"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

const (
	defaultMaxRequestBytes int64 = 16 << 10
	minMaxRequestBytes     int64 = 512
	maxMaxRequestBytes     int64 = 1 << 20
	maxApproveBodyBytes    int64 = 4 << 10
	maxListLimit                 = intelstore.MaxListLimit
	defaultListLimit             = intelstore.DefaultListLimit
	maxResponseBytes             = 8 << 20
)

// ErrUnauthorized lets an Authorizer distinguish a missing credential from a
// present credential that lacks permission.
var ErrUnauthorized = errors.New("intelapi: unauthorized")

// Fetcher is the SSRF-safe fetch contract implemented by *intel.Fetcher.
type Fetcher interface {
	Fetch(ctx context.Context, request intel.FetchRequest) (intel.FetchResult, error)
}

// HandlerOptions configures the intel HTTP handler.
type HandlerOptions struct {
	// Store is required.
	Store intelstore.Store
	// Fetcher performs the SSRF-safe fetch. A default *intel.Fetcher with the
	// intel package's URL, redirect, size, and content-type policy is built
	// when nil.
	Fetcher Fetcher
	// Extractor defaults to the deterministic AdvisoryExtractor.
	Extractor intel.Extractor
	// Authorizer runs before every request. When nil the caller is responsible
	// for mounting this handler behind authentication.
	Authorizer func(*http.Request) error
	// Actor returns the authenticated reviewer identity. When nil it is read
	// from middleware.Claims; tests may inject a deterministic actor.
	Actor func(*http.Request) (string, error)
	// Profiles supplies local traffic aggregates for one candidate's impact
	// estimate. When nil no profile evidence exists, so block promotion is
	// rejected.
	Profiles func(ctx context.Context, candidate impact.Candidate) ([]impact.Profile, error)
	// Now overrides the clock in tests.
	Now func() time.Time
	// DefaultTTL bounds each candidate's lifetime. Zero uses the intel default.
	DefaultTTL time.Duration
	// MaxRequestBytes bounds request bodies. Zero uses 16 KiB.
	MaxRequestBytes int64
	// MaxFetchBytes bounds fetched advisory bodies. Zero uses the intel default.
	MaxFetchBytes int64
	// DisableURLImport removes the URL import route when the operator has
	// turned intel.url_import off. The default keeps the route available.
	DisableURLImport bool
	// ImportSourceID pins URL imports to one registered source. When empty the
	// source is resolved from registered sources by URL host.
	ImportSourceID string
	// TrustPolicy defaults to intel.DefaultTrustPolicy.
	TrustPolicy intel.TrustPolicy
	// Policy overrides the rollout thresholds (shadow window, canary bounds).
	// Zero uses impact.DefaultPolicy.
	Policy impact.Policy
}

type handler struct {
	store           intelstore.Store
	fetcher         Fetcher
	extractor       intel.Extractor
	authorizer      func(*http.Request) error
	actor           func(*http.Request) (string, error)
	profiles        func(context.Context, impact.Candidate) ([]impact.Profile, error)
	now             func() time.Time
	ttl             time.Duration
	maxRequestBytes int64
	importSourceID  string
	trustPolicy     intel.TrustPolicy
	policy          impact.Policy
	promotePipeline *pipeline.Pipeline
}

// NewHandler builds the intel API. Mount it at a private prefix:
//
//	r.Mount("/api/intel", intelapi.NewHandler(opts))
func NewHandler(opts HandlerOptions) http.Handler {
	if opts.Store == nil {
		panic("intelapi: HandlerOptions.Store is required")
	}
	ttl := opts.DefaultTTL
	if ttl == 0 {
		ttl = intel.DefaultCandidateTTL
	}
	if ttl < 0 || ttl > intel.MaxCandidateTTL {
		panic("intelapi: DefaultTTL must be within (0, intel.MaxCandidateTTL]")
	}
	maxRequest := opts.MaxRequestBytes
	if maxRequest == 0 {
		maxRequest = defaultMaxRequestBytes
	}
	if maxRequest < minMaxRequestBytes || maxRequest > maxMaxRequestBytes {
		panic(fmt.Sprintf("intelapi: MaxRequestBytes must be between %d and %d", minMaxRequestBytes, maxMaxRequestBytes))
	}
	fetcher := opts.Fetcher
	if fetcher == nil {
		created, err := intel.NewFetcher(intel.FetchOptions{MaxBodyBytes: opts.MaxFetchBytes})
		if err != nil {
			panic(fmt.Sprintf("intelapi: build fetcher: %v", err))
		}
		fetcher = created
	}
	extractor := opts.Extractor
	if extractor == nil {
		extractor = NewAdvisoryExtractor()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	trustPolicy := opts.TrustPolicy
	if trustPolicy.RequiredCorroboration == 0 {
		trustPolicy = intel.DefaultTrustPolicy()
	}
	registry, err := pipeline.NewRegistry(nil)
	if err != nil {
		panic(fmt.Sprintf("intelapi: build pipeline registry: %v", err))
	}
	promotePipeline, err := pipeline.New(pipeline.Config{
		Registry:     registry,
		ImpactPolicy: opts.Policy,
		Extractor:    pipeline.ExtractorFunc(func(context.Context, intel.Item) ([]intel.Extraction, error) { return nil, nil }),
		TrustPolicy:  trustPolicy,
		TTL:          ttl,
		Now:          now,
	})
	if err != nil {
		panic(fmt.Sprintf("intelapi: build promotion pipeline: %v", err))
	}
	h := &handler{
		store:           opts.Store,
		fetcher:         fetcher,
		extractor:       extractor,
		authorizer:      opts.Authorizer,
		actor:           opts.Actor,
		profiles:        opts.Profiles,
		now:             now,
		ttl:             ttl,
		maxRequestBytes: maxRequest,
		importSourceID:  strings.TrimSpace(opts.ImportSourceID),
		trustPolicy:     trustPolicy,
		policy:          opts.Policy,
		promotePipeline: promotePipeline,
	}
	router := chi.NewRouter()
	router.Use(h.authorize)
	if !opts.DisableURLImport {
		router.Post("/import-url", h.handleImportURL)
	}
	router.Get("/items", h.handleListItems)
	router.Get("/candidates", h.handleListCandidates)
	router.Get("/candidates/{id}", h.handleGetCandidate)
	router.Post("/candidates/{id}/approve", h.handleApproveCandidate)
	router.Post("/candidates/{id}/reject", h.handleRejectCandidate)
	router.Get("/impact", h.handleImpact)
	router.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	})
	return router
}

func (h *handler) authorize(next http.Handler) http.Handler {
	if h.authorizer == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.authorizer(r); err != nil {
			if errors.Is(err, ErrUnauthorized) {
				writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
				return
			}
			writeError(w, http.StatusForbidden, "forbidden", "access is denied")
			return
		}
		next.ServeHTTP(w, r)
	})
}

var (
	errBadJSON       = errors.New("intelapi: invalid json body")
	errBodyTooLarge  = errors.New("intelapi: request body too large")
	errUnsupportedCT = errors.New("intelapi: unsupported content type")
)

func decodeBody(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return errUnsupportedCT
	}
	body := http.MaxBytesReader(w, r.Body, max)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errBodyTooLarge
		}
		return errBadJSON
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errBadJSON
	}
	return nil
}

func decodeOptionalBody(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	if r.ContentLength == 0 && r.Header.Get("Content-Type") == "" {
		return nil
	}
	return decodeBody(w, r, max, dst)
}

func writeDecodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnsupportedCT):
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_content_type", "Content-Type must be application/json")
	case errors.Is(err, errBodyTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the size limit")
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid_json", "request body is not a single valid JSON object with known fields")
	}
}

type errorDetail struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Reasons []string `json:"reasons,omitempty"`
}

type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorReasons(w, status, code, message, nil)
}

func writeErrorReasons(w http.ResponseWriter, status int, code, message string, reasons []string) {
	writeJSON(w, status, errorEnvelope{Error: errorDetail{Code: code, Message: message, Reasons: reasons}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxResponseBytes {
		status = http.StatusInternalServerError
		encoded = []byte(`{"error":{"code":"response_too_large","message":"response exceeds the size limit"}}`)
	}
	encoded = append(encoded, '\n')
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func parseLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return defaultListLimit, nil
	}
	value := 0
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("limit must be a positive integer")
		}
		value = value*10 + int(digit-'0')
		if value > maxListLimit {
			return maxListLimit, nil
		}
	}
	if value == 0 {
		return defaultListLimit, nil
	}
	return value, nil
}

func parseState(r *http.Request) (intel.CandidateState, error) {
	raw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if raw == "" {
		return "", nil
	}
	state := intel.CandidateState(raw)
	if !state.Valid() {
		return "", fmt.Errorf("unknown candidate state")
	}
	return state, nil
}
