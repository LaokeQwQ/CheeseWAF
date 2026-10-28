package intelapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/impact"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/pipeline"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

const maxRawExcerptBytes = 4096

var errSourceUnregistered = errors.New("intelapi: url is not registered as an intel source")

type importRequest struct {
	URL        string   `json:"url"`
	SiteID     string   `json:"site_id"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	Methods    []string `json:"methods,omitempty"`
}

type importCandidate struct {
	Candidate intel.Candidate   `json:"candidate"`
	Impact    impact.Assessment `json:"impact"`
}

type importResponse struct {
	JobID            string            `json:"job_id"`
	Item             intel.Item        `json:"item"`
	Candidate        intel.Candidate   `json:"candidate"`
	Impact           impact.Assessment `json:"impact"`
	Candidates       []importCandidate `json:"candidates"`
	ItemCreated      bool              `json:"item_created"`
	CandidateCreated bool              `json:"candidate_created"`
}

func (h *handler) handleImportURL(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var request importRequest
	if err := decodeBody(w, r, h.maxRequestBytes, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	rawURL := strings.TrimSpace(request.URL)
	if err := intel.ValidateFetchURL(rawURL); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "unsafe_url",
			"URL must be an absolute public HTTP(S) URL without credentials or fragments")
		return
	}
	methods, err := normalizeMethods(request.Methods)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_methods", "methods must be HTTP method names")
		return
	}
	scope := intel.Scope{SiteID: strings.TrimSpace(request.SiteID), PathPrefix: strings.TrimSpace(request.PathPrefix), Methods: methods}
	if err := scope.Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_scope", "site_id and path_prefix do not form a valid single-site scope")
		return
	}

	now := h.now().UTC()
	succeeded := false
	defer func() {
		if !succeeded {
			intel.RecordImport(false)
		}
	}()
	job := intelstore.NewImportJob(newID("job"), rawURL, now)
	if err := h.store.InsertImportJob(ctx, job); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "could not record the import job")
		return
	}
	fail := func(status int, code, message string) {
		h.failImportJob(ctx, job, code)
		writeError(w, status, code, message)
	}

	source, err := h.resolveSource(ctx, rawURL)
	if err != nil {
		if errors.Is(err, errSourceUnregistered) {
			fail(http.StatusUnprocessableEntity, "source_unregistered",
				"URL host is not covered by an enabled intel source; register the source first")
			return
		}
		fail(http.StatusInternalServerError, "storage_error", "could not resolve the intel source")
		return
	}

	result, err := h.fetcher.Fetch(ctx, intel.FetchRequest{URL: rawURL})
	if err == nil && !sourceAllowsURL(source, result.URL) {
		fail(http.StatusUnprocessableEntity, "source_mismatch", "fetched URL does not match the registered source origin")
		return
	}
	if err != nil {
		status, code, message := mapFetchError(err)
		fail(status, code, message)
		return
	}
	document, err := intel.ExtractHTML(result.Body, intel.DefaultMaxTextBytes)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "invalid_document", "fetched document is empty or exceeds the HTML size limit")
		return
	}

	item := intel.Item{
		ID:          itemIDFor(source.ID, document.SHA256),
		SourceID:    source.ID,
		Title:       document.Title,
		ContentHash: document.SHA256,
		PublishedAt: now,
		RawExcerpt:  truncateText(document.Text, maxRawExcerptBytes),
	}

	extraction, err := h.extractor.Extract(ctx, item, document)
	if err != nil {
		switch {
		case errors.Is(err, intel.ErrNoSafeRule):
			fail(http.StatusUnprocessableEntity, "no_safe_rule", "advisory has no PHP2Shell-shaped evidence that maps to a narrow rule")
		case errors.Is(err, intel.ErrInvalid):
			fail(http.StatusUnprocessableEntity, "extraction_invalid", "extracted advisory data failed validation")
		default:
			fail(http.StatusInternalServerError, "extraction_failed", "advisory extraction failed")
		}
		return
	}
	item.ExternalIDs = append([]string(nil), extraction.CVEIDs...)
	item.Products = append([]string(nil), extraction.Products...)
	item.AffectedVersions = append([]string(nil), extraction.AffectedVersions...)
	item.References = append([]string(nil), extraction.References...)

	ingest, err := h.importPipeline(source)
	if err != nil {
		fail(http.StatusInternalServerError, "pipeline_error", "could not assemble the import pipeline")
		return
	}
	candidates, pipelineErr := ingest.IngestItem(ctx, item, []intel.Extraction{extraction}, scope)
	if len(candidates) == 0 {
		status, code, message := mapPipelineError(pipelineErr)
		fail(status, code, message)
		return
	}

	storedItem, itemCreated, err := h.store.InsertItem(ctx, item)
	if err != nil {
		fail(http.StatusInternalServerError, "storage_error", "could not persist the intelligence item")
		return
	}
	if storedItem.ID != item.ID {
		fail(http.StatusConflict, "item_conflict", "an item with this source and content hash already exists")
		return
	}

	previews := make([]importCandidate, 0, len(candidates))
	primary := intel.Candidate{}
	primaryImpact := impact.Assessment{}
	candidateCreated := false
	for _, candidate := range candidates {
		stored, created, err := h.store.InsertCandidate(ctx, candidate.Candidate)
		if err != nil {
			fail(http.StatusInternalServerError, "storage_error", "could not persist a rule candidate")
			return
		}
		if len(previews) == 0 {
			primary = stored
			primaryImpact = candidate.Impact
			candidateCreated = created
		}
		if created {
			candidateCreated = true
		}
		previews = append(previews, importCandidate{Candidate: stored, Impact: candidate.Impact})
	}

	encodedExtractions, err := json.Marshal([]intel.Extraction{extraction})
	if err != nil {
		encodedExtractions = []byte("{}")
	}
	job.ContentHash = document.SHA256
	job.Status = intelstore.ImportStatusCompleted
	job.ExtractionJSON = string(encodedExtractions)
	job.UpdatedAt = h.now().UTC()
	if err := h.store.UpdateImportJob(ctx, job); err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "could not finalize the import job")
		return
	}

	status := http.StatusOK
	if candidateCreated {
		status = http.StatusCreated
	}
	succeeded = true
	intel.RecordImport(true)
	writeJSON(w, status, importResponse{
		JobID:            job.ID,
		Item:             storedItem,
		Candidate:        primary,
		Impact:           primaryImpact,
		Candidates:       previews,
		ItemCreated:      itemCreated,
		CandidateCreated: candidateCreated,
	})
}

func sourceAllowsURL(source intel.Source, rawURL string) bool {
	registered, err := url.Parse(strings.TrimSpace(source.URL))
	if err != nil || registered.Host == "" {
		return false
	}
	target, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || target.Host == "" {
		return false
	}
	if !strings.EqualFold(hostKey(registered), hostKey(target)) {
		return false
	}
	if strings.EqualFold(registered.Scheme, "https") && !strings.EqualFold(target.Scheme, "https") {
		return false
	}
	return true
}

func (h *handler) resolveSource(ctx context.Context, rawURL string) (intel.Source, error) {
	if h.importSourceID != "" {
		source, err := h.store.GetSource(ctx, h.importSourceID)
		if err != nil {
			if errors.Is(err, intelstore.ErrNotFound) {
				return intel.Source{}, errSourceUnregistered
			}
			return intel.Source{}, err
		}
		if !source.Enabled || strings.TrimSpace(source.URL) == "" || !sourceAllowsURL(source, rawURL) {
			return intel.Source{}, errSourceUnregistered
		}
		return source, nil
	}
	sources, err := h.store.ListSources(ctx)
	if err != nil {
		return intel.Source{}, err
	}
	target, err := url.Parse(rawURL)
	if err != nil {
		return intel.Source{}, errSourceUnregistered
	}
	targetHost := hostKey(target)
	var (
		best      intel.Source
		bestScore int
	)
	for _, source := range sources {
		if !source.Enabled || strings.TrimSpace(source.URL) == "" {
			continue
		}
		registered, err := url.Parse(strings.TrimSpace(source.URL))
		if err != nil || registered.Host == "" {
			continue
		}
		scheme := strings.ToLower(registered.Scheme)
		if scheme != "http" && scheme != "https" {
			continue
		}
		sourceHost := hostKey(registered)
		if sourceHost != targetHost || !sourceAllowsURL(source, rawURL) {
			continue
		}
		score := 1
		if strings.TrimSpace(source.URL) == rawURL {
			score = 2
		}
		if score > bestScore || (score == bestScore && source.Trust.Rank() > best.Trust.Rank()) ||
			(score == bestScore && source.Trust.Rank() == best.Trust.Rank() && source.ID < best.ID) {
			best = source
			bestScore = score
		}
	}
	if bestScore == 0 {
		return intel.Source{}, errSourceUnregistered
	}
	return best, nil
}

func (h *handler) importPipeline(primary intel.Source) (*pipeline.Pipeline, error) {
	registry, err := pipeline.NewRegistry([]pipeline.SourceConfig{{
		ID:      primary.ID,
		URL:     primary.URL,
		Format:  feedFormatForType(primary.Type),
		Trust:   string(primary.Trust),
		Enabled: primary.Enabled,
	}})
	if err != nil {
		return nil, err
	}
	return pipeline.New(pipeline.Config{
		Registry:      registry,
		ImpactPolicy:  h.policy,
		Extractor:     pipeline.ExcerptExtractor{Next: h.extractor},
		Profiles:      h.profileProvider(),
		TrustPolicy:   h.trustPolicy,
		TTL:           h.ttl,
		Now:           h.now,
		ExtractorName: "deterministic-advisory",
	})
}

func (h *handler) profileProvider() pipeline.ProfileProvider {
	if h.profiles == nil {
		return nil
	}
	return pipeline.ProfileProviderFunc(func(ctx context.Context, candidate impact.Candidate) []impact.Profile {
		profiles, err := h.profiles(ctx, candidate)
		if err != nil {
			return nil
		}
		return profiles
	})
}

func (h *handler) failImportJob(ctx context.Context, job intelstore.ImportJob, code string) {
	job.Status = intelstore.ImportStatusFailed
	job.Error = code
	job.UpdatedAt = h.now().UTC()
	_ = h.store.UpdateImportJob(ctx, job)
}

func mapFetchError(err error) (int, string, string) {
	switch {
	case errors.Is(err, intel.ErrUnsafeURL):
		return http.StatusUnprocessableEntity, "unsafe_url", "fetch target was rejected by the URL policy"
	case errors.Is(err, intel.ErrResponseTooLarge):
		return http.StatusRequestEntityTooLarge, "response_too_large", "fetched document exceeds the response size limit"
	case errors.Is(err, intel.ErrUnsupportedContentType):
		return http.StatusUnprocessableEntity, "unsupported_content_type", "fetched document has an unsupported content type"
	case errors.Is(err, intel.ErrTooManyRedirects):
		return http.StatusUnprocessableEntity, "too_many_redirects", "fetch exceeded the redirect budget"
	default:
		return http.StatusBadGateway, "fetch_failed", "upstream fetch failed"
	}
}

func mapPipelineError(err error) (int, string, string) {
	switch {
	case errors.Is(err, pipeline.ErrQuarantined):
		return http.StatusUnprocessableEntity, "quarantined", "source trust policy did not allow this item"
	case errors.Is(err, pipeline.ErrNoSafeRule):
		return http.StatusUnprocessableEntity, "no_safe_rule", "advisory has no shape that maps to a narrow rule"
	case errors.Is(err, pipeline.ErrLimitExceeded):
		return http.StatusUnprocessableEntity, "limit_exceeded", "advisory exceeds a processing limit"
	case errors.Is(err, pipeline.ErrInvalid):
		return http.StatusUnprocessableEntity, "invalid_input", "advisory could not be compiled into a valid candidate"
	default:
		return http.StatusUnprocessableEntity, "processing_failed", "advisory processing failed"
	}
}

func normalizeMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 8 {
		return nil, fmt.Errorf("too many methods")
	}
	seen := make(map[string]struct{}, len(values))
	methods := make([]string, 0, len(values))
	for _, value := range values {
		method := strings.ToUpper(strings.TrimSpace(value))
		if method == "" {
			return nil, fmt.Errorf("empty method")
		}
		if _, exists := seen[method]; exists {
			continue
		}
		seen[method] = struct{}{}
		methods = append(methods, method)
	}
	return methods, nil
}

func hostKey(parsed *url.URL) string {
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	return scheme + "://" + host
}

func feedFormatForType(sourceType string) string {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "rss":
		return "rss"
	case "atom":
		return "atom"
	case "api":
		return "json"
	default:
		return ""
	}
}

func itemIDFor(sourceID, contentHash string) string {
	sum := sha256.Sum256([]byte(sourceID + "\n" + contentHash))
	return "item-" + hex.EncodeToString(sum[:])[:16]
}

func newID(prefix string) string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(buffer)
}

func truncateText(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return strings.TrimSpace(value[:cut])
}
