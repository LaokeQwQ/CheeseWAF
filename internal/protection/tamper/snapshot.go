package tamper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	macSize       = sha256.Size
	minimumKeyLen = 32
)

var (
	ErrKeyRequired        = errors.New("tamper MAC key must be at least 32 bytes")
	ErrInvalidSnapshot    = errors.New("invalid tamper snapshot")
	ErrInvalidResourceURL = errors.New("invalid tamper resource URL")
)

// Snapshot is an authenticated baseline for one exact resource URL.
// MAC covers the version, canonical URL, body size, and body bytes.
type Snapshot struct {
	URL        string    `json:"url" yaml:"url"`
	MAC        string    `json:"mac" yaml:"mac"`
	Size       int       `json:"size" yaml:"size"`
	CapturedAt time.Time `json:"captured_at" yaml:"captured_at"`
}

type Drift struct {
	URL      string `json:"url"`
	Changed  bool   `json:"changed"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Reason   string `json:"reason,omitempty"`
}

// CanonicalURL normalizes the URL representation used by snapshot MACs.
// Fragments are never sent to an HTTP server and are deliberately excluded.
func CanonicalURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return "", ErrInvalidResourceURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidResourceURL, raw)
	}
	u.Fragment = ""
	if u.IsAbs() {
		if (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.Host == "" || u.User != nil {
			return "", fmt.Errorf("%w: absolute URL requires HTTP(S) scheme and host without userinfo", ErrInvalidResourceURL)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String(), nil
	}
	if u.Path == "" {
		return "", fmt.Errorf("%w: relative URL requires a path", ErrInvalidResourceURL)
	}
	if u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return "", fmt.Errorf("%w: relative URL must start with /", ErrInvalidResourceURL)
	}
	return u.RequestURI(), nil
}

func validateKey(key []byte) error {
	if len(key) < minimumKeyLen {
		return ErrKeyRequired
	}
	return nil
}

func macFor(key []byte, resourceURL string, body []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	canonical, err := CanonicalURL(resourceURL)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("cheesewaf/tamper/v1"))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(canonical)))
	_, _ = h.Write(length[:])
	_, _ = h.Write([]byte(canonical))
	binary.BigEndian.PutUint64(length[:], uint64(len(body)))
	_, _ = h.Write(length[:])
	_, _ = h.Write(body)
	return h.Sum(nil), nil
}

// Capture creates an authenticated snapshot. The key is never stored in the
// returned value and must be supplied again when comparing the response.
func Capture(key []byte, resourceURL string, body []byte, now time.Time) (Snapshot, error) {
	canonical, err := CanonicalURL(resourceURL)
	if err != nil {
		return Snapshot{}, err
	}
	sum, err := macFor(key, canonical, body)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		URL:        canonical,
		MAC:        hex.EncodeToString(sum),
		Size:       len(body),
		CapturedAt: now.UTC(),
	}, nil
}

// Compare authenticates the supplied response against a snapshot and binds
// the comparison to the URL actually being served. A URL mismatch is a drift
// even when the body happens to be identical.
func Compare(key []byte, snapshot Snapshot, resourceURL string, body []byte) (Drift, error) {
	if err := validateKey(key); err != nil {
		return Drift{}, err
	}
	canonicalSnapshotURL, err := CanonicalURL(snapshot.URL)
	if err != nil {
		return Drift{}, fmt.Errorf("%w: snapshot URL: %v", ErrInvalidSnapshot, err)
	}
	canonicalURL, err := CanonicalURL(resourceURL)
	if err != nil {
		return Drift{}, err
	}
	if snapshot.Size < 0 {
		return Drift{}, fmt.Errorf("%w: negative snapshot size", ErrInvalidSnapshot)
	}
	expected, err := hex.DecodeString(strings.TrimSpace(snapshot.MAC))
	if err != nil || len(expected) != macSize {
		return Drift{}, fmt.Errorf("%w: MAC must be %d bytes", ErrInvalidSnapshot, macSize)
	}
	actual, err := macFor(key, canonicalURL, body)
	if err != nil {
		return Drift{}, err
	}
	macMatches := hmac.Equal(expected, actual)
	changed := canonicalSnapshotURL != canonicalURL || snapshot.Size != len(body) || !macMatches
	reason := ""
	switch {
	case canonicalSnapshotURL != canonicalURL:
		reason = "url_mismatch"
	case snapshot.Size != len(body):
		reason = "size_mismatch"
	case !macMatches:
		reason = "body_mismatch"
	}
	return Drift{
		URL:      canonicalURL,
		Changed:  changed,
		Expected: strings.ToLower(strings.TrimSpace(snapshot.MAC)),
		Actual:   hex.EncodeToString(actual),
		Reason:   reason,
	}, nil
}

// Verifier is an immutable URL-indexed snapshot set suitable for concurrent
// response inspection.
type Verifier struct {
	key       []byte
	snapshots map[string]Snapshot
}

func NewVerifier(key []byte, snapshots []Snapshot) (*Verifier, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	verifier := &Verifier{key: append([]byte(nil), key...), snapshots: make(map[string]Snapshot, len(snapshots))}
	for _, snapshot := range snapshots {
		canonical, err := CanonicalURL(snapshot.URL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
		}
		if _, exists := verifier.snapshots[canonical]; exists {
			return nil, fmt.Errorf("%w: duplicate URL %q", ErrInvalidSnapshot, canonical)
		}
		mac, err := hex.DecodeString(strings.TrimSpace(snapshot.MAC))
		if err != nil || len(mac) != macSize || snapshot.Size < 0 {
			return nil, fmt.Errorf("%w: URL %q has invalid MAC or size", ErrInvalidSnapshot, canonical)
		}
		snapshot.URL = canonical
		verifier.snapshots[canonical] = snapshot
	}
	return verifier, nil
}

func (v *Verifier) Enabled() bool {
	return v != nil && len(v.snapshots) > 0
}

func (v *Verifier) HasSnapshot(resourceURL string) bool {
	if v == nil {
		return false
	}
	canonical, err := CanonicalURL(resourceURL)
	if err != nil {
		return false
	}
	_, ok := v.snapshots[canonical]
	return ok
}

func (v *Verifier) Compare(resourceURL string, body []byte) (Drift, error) {
	if v == nil {
		return Drift{}, nil
	}
	canonical, err := CanonicalURL(resourceURL)
	if err != nil {
		return Drift{}, err
	}
	snapshot, ok := v.snapshots[canonical]
	if !ok {
		return Drift{}, nil
	}
	return Compare(v.key, snapshot, canonical, body)
}
