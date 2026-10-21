package feed

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const maxSourceNameBytes = 128

var sourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,128}$`)

// SourceRegistry is an allowlist of feed sources keyed by ID and normalized
// URL. Unknown IDs or URLs are rejected, and disabled sources cannot be used
// until an operator enables them. SourceRegistry performs no network I/O.
type SourceRegistry struct {
	mu    sync.RWMutex
	byID  map[string]Source
	byURL map[string]string
}

// NewSourceRegistry validates and registers every source. A duplicate ID or
// URL is rejected rather than silently overwriting an allowlist entry.
func NewSourceRegistry(sources []Source) (*SourceRegistry, error) {
	registry := &SourceRegistry{
		byID:  make(map[string]Source, len(sources)),
		byURL: make(map[string]string, len(sources)),
	}
	for _, source := range sources {
		if err := registry.Register(source); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// Register validates and adds a source. Disabled sources remain registered so
// an operator can enable them later.
func (r *SourceRegistry) Register(source Source) error {
	normalized, err := validateSource(source)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = make(map[string]Source)
	}
	if r.byURL == nil {
		r.byURL = make(map[string]string)
	}
	if _, exists := r.byID[normalized.ID]; exists {
		return fmt.Errorf("%w: id %q", ErrDuplicateSource, normalized.ID)
	}
	if existing, exists := r.byURL[normalized.URL]; exists {
		return fmt.Errorf("%w: url %q already belongs to %q", ErrDuplicateSource, normalized.URL, existing)
	}
	r.byID[normalized.ID] = normalized
	r.byURL[normalized.URL] = normalized.ID
	return nil
}

// Resolve returns an enabled source by ID.
func (r *SourceRegistry) Resolve(id string) (Source, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	source, exists := r.byID[strings.TrimSpace(id)]
	if !exists {
		return Source{}, fmt.Errorf("%w: id %q", ErrUnknownSource, strings.TrimSpace(id))
	}
	if !source.Enabled {
		return Source{}, fmt.Errorf("%w: id %q", ErrSourceDisabled, source.ID)
	}
	return source, nil
}

// Lookup returns a source by ID regardless of enabled state.
func (r *SourceRegistry) Lookup(id string) (Source, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	source, exists := r.byID[strings.TrimSpace(id)]
	return source, exists
}

// ResolveURL returns an enabled source by allowlisted URL.
func (r *SourceRegistry) ResolveURL(raw string) (Source, error) {
	normalized, err := normalizeSourceURL(raw)
	if err != nil {
		return Source{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, exists := r.byURL[normalized]
	if !exists {
		return Source{}, fmt.Errorf("%w: url %q", ErrUnknownSource, normalized)
	}
	source := r.byID[id]
	if !source.Enabled {
		return Source{}, fmt.Errorf("%w: id %q", ErrSourceDisabled, source.ID)
	}
	return source, nil
}

// SetEnabled changes the enabled state of a registered source.
func (r *SourceRegistry) SetEnabled(id string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	source, exists := r.byID[strings.TrimSpace(id)]
	if !exists {
		return fmt.Errorf("%w: id %q", ErrUnknownSource, strings.TrimSpace(id))
	}
	source.Enabled = enabled
	r.byID[source.ID] = source
	return nil
}

// Sources returns a copy of the registry sorted by source ID.
func (r *SourceRegistry) Sources() []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Source, 0, len(r.byID))
	for _, source := range r.byID {
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Parse resolves the source and parses its body. Unknown or disabled sources
// are rejected before the body is inspected.
func (r *SourceRegistry) Parse(sourceID string, body []byte) ([]FeedItem, error) {
	source, err := r.Resolve(sourceID)
	if err != nil {
		return nil, err
	}
	return Parse(source, body)
}

func validateSource(source Source) (Source, error) {
	source.ID = strings.TrimSpace(source.ID)
	if !sourceIDPattern.MatchString(source.ID) {
		return Source{}, fmt.Errorf("%w: source id must match %s", ErrInvalidSource, sourceIDPattern)
	}
	name, err := cleanText("source name", source.Name, maxSourceNameBytes)
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrInvalidSource, err)
	}
	source.Name = name
	normalizedURL, err := normalizeSourceURL(source.URL)
	if err != nil {
		return Source{}, fmt.Errorf("%w: %v", ErrInvalidSource, err)
	}
	source.URL = normalizedURL
	if source.Format != "" {
		format := ParseFormat(string(source.Format))
		if format == "" {
			return Source{}, fmt.Errorf("%w: format %q", ErrInvalidSource, source.Format)
		}
		source.Format = format
	}
	trust := TrustLevel(strings.ToLower(strings.TrimSpace(string(source.Trust))))
	if trust == "" {
		trust = TrustUnknown
	}
	if !trust.Valid() {
		return Source{}, fmt.Errorf("%w: trust %q", ErrInvalidSource, source.Trust)
	}
	source.Trust = trust
	return source, nil
}

// normalizeSourceURL canonicalizes the URL used as the allowlist key. Scheme
// and host are lowercased, default ports and fragments are dropped, and an
// empty path becomes "/". Query strings remain significant.
func normalizeSourceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%w: source url is required", ErrInvalidSource)
	}
	if len(raw) > MaxLinkBytes {
		return "", fmt.Errorf("%w: source url exceeds %d bytes", ErrInvalidSource, MaxLinkBytes)
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", fmt.Errorf("%w: source url %q is not absolute", ErrInvalidSource, raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: source url must use http or https", ErrInvalidSource)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: source url must not contain credentials", ErrInvalidSource)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: source url has no host", ErrInvalidSource)
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	switch {
	case port != "":
		parsed.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		parsed.Host = "[" + host + "]"
	default:
		parsed.Host = host
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}
