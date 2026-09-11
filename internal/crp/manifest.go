// Package crp defines the content-addressed contract for a CheeseWAF
// Resource Package (CRP). It deliberately has no network, filesystem, or
// signature dependencies; those concerns are layered on top of this package.
package crp

import (
	"crypto/md5"  // #nosec G501 -- MD5 is required as a legacy transport-integrity check; SHA-256 remains authoritative.
	"crypto/sha1" // #nosec G505 -- SHA-1 is required as a legacy transport-integrity check; it is not a signature.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	// APIVersion is the first stable CRP manifest schema.
	APIVersion = "crp.cheesewaf.io/v1"
	Kind       = "CheeseWAFResourcePackage"
)

var (
	ErrInvalidManifest   = errors.New("invalid CRP manifest")
	ErrDigestMismatch    = errors.New("CRP artifact digest mismatch")
	ErrNamespace         = errors.New("CRP namespace is not allowed")
	ErrSource            = errors.New("CRP source root is not allowed")
	ErrDowngrade         = errors.New("CRP release would downgrade the installed version")
	ErrArtifactSize      = errors.New("CRP artifact size does not match manifest")
	ErrMissingDigest     = errors.New("CRP manifest must contain MD5, SHA-1, and SHA-256 digests")
	ErrUnsupportedSchema = errors.New("unsupported CRP manifest schema")
)

// Digests contains the three transport-integrity digests required by the CRP
// contract. Values are lowercase hexadecimal strings without an algorithm
// prefix. MD5 and SHA-1 are compatibility checks only; SHA-256 is the
// authoritative content identity.
type Digests struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// Artifact describes the bytes represented by a manifest. Digest fields on
// Artifact are preferred; the top-level Manifest.Digests field is retained as
// a compact compatibility form for producers that do not need a path.
type Artifact struct {
	Name    string  `json:"name,omitempty"`
	Size    int64   `json:"size,omitempty"`
	Digests Digests `json:"digests"`
}

// Manifest is the signed-content envelope consumed by later CRP trust-chain
// layers. Signature and transparency evidence are intentionally not modelled
// here: this package only establishes the bytes and release binding those
// layers must sign.
type Manifest struct {
	APIVersion      string   `json:"api_version,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Name            string   `json:"name"`
	PluginID        string   `json:"plugin_id,omitempty"`
	Version         string   `json:"version"`
	Namespace       string   `json:"namespace"`
	Publisher       string   `json:"publisher,omitempty"`
	Source          string   `json:"source,omitempty"`
	SourceRoot      string   `json:"source_root"`
	ReleaseSequence uint64   `json:"release_sequence"`
	Digests         Digests  `json:"digests,omitempty"`
	Artifact        Artifact `json:"artifact,omitempty"`
}

// ValidationOptions controls the deployment-context checks that cannot be
// decided from a manifest alone. Empty expected values mean "use the
// manifest's declared value" and still require the manifest field itself to
// be syntactically valid.
type ValidationOptions struct {
	ExpectedNamespace  string
	ExpectedSource     string
	ExpectedSourceRoot string
	CurrentVersion     string
	CurrentSequence    uint64
}

// Release identifies the currently installed release for downgrade checks.
type Release struct {
	Version  string
	Sequence uint64
}

// SourceRootRegistration binds a logical source root to the namespaces and
// transport sources it is permitted to serve. A URL is not a trust root: the
// registry compares these stable identifiers before any downloader is called.
type SourceRootRegistration struct {
	ID                string   `json:"id"`
	NamespacePrefixes []string `json:"namespace_prefixes"`
	Sources           []string `json:"sources"`
}

// SourceRegistry is an immutable in-memory registry of approved source roots.
// It has no network or persistence behavior; a control-plane adapter can load
// and replace it from its durable registry snapshot.
type SourceRegistry struct {
	roots map[string]SourceRootRegistration
}

// NewSourceRegistry validates and constructs a source-root registry. Duplicate
// IDs, empty namespace bindings, and empty source allowlists are rejected so
// an incomplete registration cannot accidentally become a wildcard.
func NewSourceRegistry(registrations []SourceRootRegistration) (SourceRegistry, error) {
	roots := make(map[string]SourceRootRegistration, len(registrations))
	for _, registration := range registrations {
		registration.ID = strings.TrimSpace(registration.ID)
		if err := validateSourceRoot(registration.ID); err != nil {
			return SourceRegistry{}, err
		}
		if _, exists := roots[registration.ID]; exists {
			return SourceRegistry{}, fmt.Errorf("%w: duplicate source root %q", ErrSource, registration.ID)
		}
		if len(registration.NamespacePrefixes) == 0 {
			return SourceRegistry{}, fmt.Errorf("%w: source root %q has no namespace binding", ErrNamespace, registration.ID)
		}
		if len(registration.Sources) == 0 {
			return SourceRegistry{}, fmt.Errorf("%w: source root %q has no source allowlist", ErrSource, registration.ID)
		}
		registration.NamespacePrefixes = normalizeUnique(registration.NamespacePrefixes)
		for _, prefix := range registration.NamespacePrefixes {
			if err := validateNamespacePrefix(prefix); err != nil {
				return SourceRegistry{}, err
			}
		}
		registration.Sources = normalizeUnique(registration.Sources)
		for _, source := range registration.Sources {
			if err := validateSource(source); err != nil {
				return SourceRegistry{}, err
			}
		}
		roots[registration.ID] = SourceRootRegistration{
			ID:                registration.ID,
			NamespacePrefixes: append([]string(nil), registration.NamespacePrefixes...),
			Sources:           append([]string(nil), registration.Sources...),
		}
	}
	return SourceRegistry{roots: roots}, nil
}

// Validate checks that a manifest's declared root, namespace, and transport
// source are all present in the same registration. An unknown root or source,
// and a namespace outside the root's allowlist, are hard failures.
func (r SourceRegistry) Validate(m Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	root, ok := r.roots[m.SourceRoot]
	if !ok {
		return fmt.Errorf("%w: unknown source root %q", ErrSource, m.SourceRoot)
	}
	if m.Source == "" {
		return fmt.Errorf("%w: manifest source is required for registry validation", ErrSource)
	}
	if !contains(root.Sources, m.Source) {
		return fmt.Errorf("%w: source %q is not registered for root %q", ErrSource, m.Source, m.SourceRoot)
	}
	for _, prefix := range root.NamespacePrefixes {
		if namespaceMatches(m.Namespace, prefix) {
			return nil
		}
	}
	return fmt.Errorf("%w: namespace %q is not bound to source root %q", ErrNamespace, m.Namespace, m.SourceRoot)
}

// SourceRoot returns a defensive copy of one registration for diagnostics.
func (r SourceRegistry) SourceRoot(id string) (SourceRootRegistration, bool) {
	registration, ok := r.roots[strings.TrimSpace(id)]
	if !ok {
		return SourceRootRegistration{}, false
	}
	registration.NamespacePrefixes = append([]string(nil), registration.NamespacePrefixes...)
	registration.Sources = append([]string(nil), registration.Sources...)
	return registration, true
}

var (
	identifierPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	versionPart    = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
)

// ParseManifest decodes one JSON manifest and validates its intrinsic
// contract. Trailing JSON values and unknown fields are rejected so a typo
// cannot silently weaken a security gate.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, fmt.Errorf("%w: trailing JSON data", ErrInvalidManifest)
		}
		return Manifest{}, fmt.Errorf("%w: invalid trailing JSON: %v", ErrInvalidManifest, err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate checks fields that must be true regardless of deployment context.
func (m Manifest) Validate() error {
	if m.APIVersion != "" && m.APIVersion != APIVersion {
		return fmt.Errorf("%w: %v %q", ErrInvalidManifest, ErrUnsupportedSchema, m.APIVersion)
	}
	if m.Kind != "" && m.Kind != Kind {
		return fmt.Errorf("%w: kind must be %q", ErrInvalidManifest, Kind)
	}
	if strings.TrimSpace(m.Name) == "" && strings.TrimSpace(m.PluginID) == "" {
		return fmt.Errorf("%w: name or plugin_id is required", ErrInvalidManifest)
	}
	if !versionPart.MatchString(strings.TrimSpace(m.Version)) {
		return fmt.Errorf("%w: version must be semantic version text", ErrInvalidManifest)
	}
	if err := validateNamespace(m.Namespace); err != nil {
		return err
	}
	if err := validateSourceRoot(m.SourceRoot); err != nil {
		return err
	}
	if m.Source != "" {
		if err := validateSource(m.Source); err != nil {
			return err
		}
	}
	if m.Artifact.Size < 0 {
		return fmt.Errorf("%w: artifact size cannot be negative", ErrInvalidManifest)
	}
	if _, err := m.contentDigests(); err != nil {
		return err
	}
	return nil
}

// ValidateWith combines intrinsic validation with namespace, source-root,
// and no-downgrade checks for a particular cluster.
func (m Manifest) ValidateWith(opts ValidationOptions) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if expected := strings.TrimSpace(opts.ExpectedNamespace); expected != "" && m.Namespace != expected {
		return fmt.Errorf("%w: got %q, want %q", ErrNamespace, m.Namespace, expected)
	}
	if expected := strings.TrimSpace(opts.ExpectedSource); expected != "" && m.Source != expected {
		return fmt.Errorf("%w: got %q, want %q", ErrSource, m.Source, expected)
	}
	if expected := strings.TrimSpace(opts.ExpectedSourceRoot); expected != "" && m.SourceRoot != expected {
		return fmt.Errorf("%w: got %q, want %q", ErrSource, m.SourceRoot, expected)
	}
	if opts.CurrentVersion != "" || opts.CurrentSequence != 0 {
		if err := m.ValidateUpgrade(Release{Version: opts.CurrentVersion, Sequence: opts.CurrentSequence}); err != nil {
			return err
		}
	}
	return nil
}

// ValidateManifest is the function form of Manifest.ValidateWith.
func ValidateManifest(m Manifest, opts ValidationOptions) error { return m.ValidateWith(opts) }

// ValidateBinding verifies the deployment namespace and trust-root binding.
func (m Manifest) ValidateBinding(namespace, sourceRoot string) error {
	return m.ValidateWith(ValidationOptions{ExpectedNamespace: namespace, ExpectedSourceRoot: sourceRoot})
}

// ValidateNamespace exposes the namespace grammar for source registries and
// control-plane admission code without requiring a complete manifest.
func ValidateNamespace(value string) error { return validateNamespace(value) }

// ValidateSourceRoot exposes source-root validation for registry setup code.
func ValidateSourceRoot(value string) error { return validateSourceRoot(value) }

// ValidateSource exposes transport-source validation for admission code.
func ValidateSource(value string) error { return validateSource(value) }

// ValidateUpgrade rejects a candidate whose semantic version or release
// sequence moves backwards. A zero sequence means the producer has no
// sequence authority yet; version comparison remains mandatory.
func (m Manifest) ValidateUpgrade(current Release) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if current.Version != "" {
		cmp, err := compareVersions(m.Version, current.Version)
		if err != nil {
			return fmt.Errorf("%w: current version: %v", ErrDowngrade, err)
		}
		if cmp < 0 {
			return fmt.Errorf("%w: candidate %q is older than %q", ErrDowngrade, m.Version, current.Version)
		}
	}
	if current.Sequence != 0 && (m.ReleaseSequence == 0 || m.ReleaseSequence < current.Sequence) {
		return fmt.Errorf("%w: candidate sequence %d is older than %d", ErrDowngrade, m.ReleaseSequence, current.Sequence)
	}
	return nil
}

// ValidateNoDowngrade is a standalone form useful to control-plane adapters.
func ValidateNoDowngrade(current, candidate Release) error {
	if candidate.Version == "" {
		return fmt.Errorf("%w: candidate version is required", ErrDowngrade)
	}
	if current.Version != "" {
		cmp, err := compareVersions(candidate.Version, current.Version)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrDowngrade, err)
		}
		if cmp < 0 {
			return fmt.Errorf("%w: candidate %q is older than %q", ErrDowngrade, candidate.Version, current.Version)
		}
	}
	if current.Sequence != 0 && (candidate.Sequence == 0 || candidate.Sequence < current.Sequence) {
		return fmt.Errorf("%w: candidate sequence %d is older than %d", ErrDowngrade, candidate.Sequence, current.Sequence)
	}
	return nil
}

// ComputeDigests computes all required transport-integrity digests.
func ComputeDigests(data []byte) Digests {
	md5sum := md5.Sum(data)   // #nosec G401 -- see Digests documentation.
	sha1sum := sha1.Sum(data) // #nosec G401 -- see Digests documentation.
	sha256sum := sha256.Sum256(data)
	return Digests{MD5: hex.EncodeToString(md5sum[:]), SHA1: hex.EncodeToString(sha1sum[:]), SHA256: hex.EncodeToString(sha256sum[:])}
}

// VerifyDigests verifies all three digest values in constant time.
func VerifyDigests(data []byte, expected Digests) error {
	if err := validateDigestShape(expected); err != nil {
		return err
	}
	got := ComputeDigests(data)
	if subtle.ConstantTimeCompare([]byte(got.MD5), []byte(expected.MD5)) != 1 ||
		subtle.ConstantTimeCompare([]byte(got.SHA1), []byte(expected.SHA1)) != 1 ||
		subtle.ConstantTimeCompare([]byte(got.SHA256), []byte(expected.SHA256)) != 1 {
		return ErrDigestMismatch
	}
	return nil
}

// Verify checks the artifact bytes against this manifest's declared digests
// and, when present, its declared byte size.
func (m Manifest) Verify(data []byte) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Artifact.Size != 0 && int64(len(data)) != m.Artifact.Size {
		return fmt.Errorf("%w: got %d, want %d", ErrArtifactSize, len(data), m.Artifact.Size)
	}
	digests, _ := m.contentDigests()
	return VerifyDigests(data, digests)
}

func (m Manifest) contentDigests() (Digests, error) {
	d := m.Digests
	if m.Artifact.Digests != (Digests{}) {
		if d != (Digests{}) && d != m.Artifact.Digests {
			return Digests{}, fmt.Errorf("%w: top-level and artifact digests disagree", ErrInvalidManifest)
		}
		d = m.Artifact.Digests
	}
	if err := validateDigestShape(d); err != nil {
		return Digests{}, err
	}
	return d, nil
}

func validateDigestShape(d Digests) error {
	if !isHex(d.MD5, md5.Size*2) || !isHex(d.SHA1, sha1.Size*2) || !isHex(d.SHA256, sha256.Size*2) {
		return ErrMissingDigest
	}
	return nil
}

func isHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateNamespace(value string) error {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, "/")
	if len(parts) < 1 || len(parts) > 3 || value == "" {
		return fmt.Errorf("%w: %q", ErrNamespace, value)
	}
	for _, part := range parts {
		if !identifierPart.MatchString(part) {
			return fmt.Errorf("%w: invalid component %q", ErrNamespace, part)
		}
	}
	switch parts[0] {
	case "official":
		if len(parts) != 2 {
			return fmt.Errorf("%w: official namespace must be official/<plugin>", ErrNamespace)
		}
	case "enterprise":
		if len(parts) != 3 {
			return fmt.Errorf("%w: enterprise namespace must be enterprise/<org-id>/<plugin>", ErrNamespace)
		}
	case "community", "personal", "test", "development":
		if len(parts) != 3 {
			return fmt.Errorf("%w: %s namespace must be %s/<publisher>/<plugin>", ErrNamespace, parts[0], parts[0])
		}
	default:
		return fmt.Errorf("%w: unknown trust namespace %q", ErrNamespace, parts[0])
	}
	return nil
}

func validateNamespacePrefix(value string) error {
	value = strings.TrimSuffix(strings.TrimSpace(value), "/")
	if value == "" {
		return fmt.Errorf("%w: namespace prefix is required", ErrNamespace)
	}
	parts := strings.Split(value, "/")
	if len(parts) > 3 {
		return fmt.Errorf("%w: namespace prefix %q has too many components", ErrNamespace, value)
	}
	for _, part := range parts {
		if !identifierPart.MatchString(part) {
			return fmt.Errorf("%w: invalid prefix component %q", ErrNamespace, part)
		}
	}
	switch parts[0] {
	case "official":
		if len(parts) > 2 {
			return fmt.Errorf("%w: official namespace prefix must be official[/<plugin>]", ErrNamespace)
		}
	case "enterprise":
		if len(parts) < 2 {
			return fmt.Errorf("%w: enterprise namespace prefix must include org-id", ErrNamespace)
		}
	case "community", "personal", "test", "development":
		if len(parts) < 2 {
			return fmt.Errorf("%w: %s namespace prefix must include publisher", ErrNamespace, parts[0])
		}
	default:
		return fmt.Errorf("%w: unknown trust namespace %q", ErrNamespace, parts[0])
	}
	return nil
}

func namespaceMatches(namespace, prefix string) bool {
	namespace = strings.TrimSuffix(strings.TrimSpace(namespace), "/")
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	return namespace == prefix || strings.HasPrefix(namespace, prefix+"/")
}

func normalizeUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validateSourceRoot(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\t ") {
		return fmt.Errorf("%w: source_root must be a non-empty stable identifier", ErrSource)
	}
	if strings.Contains(value, "..") || strings.ContainsAny(value, "\\") {
		return fmt.Errorf("%w: source_root contains a path traversal", ErrSource)
	}
	return nil
}

func validateSource(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n\t ") {
		return fmt.Errorf("%w: source must be a non-empty stable identifier", ErrSource)
	}
	if strings.Contains(value, "..") || strings.Contains(value, "\\") {
		return fmt.Errorf("%w: source contains a path traversal", ErrSource)
	}
	for _, r := range value {
		if !(r == ':' || r == '/' || r == '.' || r == '-' || r == '_' || r == '@' || r == '+' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("%w: source contains unsupported character", ErrSource)
		}
	}
	return nil
}

func compareVersions(a, b string) (int, error) {
	type parsedVersion struct {
		base []int
		pre  []string
	}
	parse := func(value string) (parsedVersion, error) {
		value = strings.TrimPrefix(strings.TrimSpace(value), "v")
		if !versionPart.MatchString(value) {
			return parsedVersion{}, fmt.Errorf("invalid version %q", value)
		}
		baseAndPre := value
		if i := strings.IndexByte(baseAndPre, '+'); i >= 0 {
			baseAndPre = baseAndPre[:i]
		}
		pre := ""
		if i := strings.IndexByte(baseAndPre, '-'); i >= 0 {
			pre = baseAndPre[i+1:]
			baseAndPre = baseAndPre[:i]
		}
		parts := strings.Split(baseAndPre, ".")
		out := make([]int, 3)
		for i := range parts {
			n, err := strconv.Atoi(parts[i])
			if err != nil {
				return parsedVersion{}, err
			}
			out[i] = n
		}
		var identifiers []string
		if pre != "" {
			identifiers = strings.Split(pre, ".")
			for _, identifier := range identifiers {
				if identifier == "" || (len(identifier) > 1 && identifier[0] == '0' && allDigits(identifier)) {
					return parsedVersion{}, fmt.Errorf("invalid prerelease identifier %q", identifier)
				}
			}
		}
		return parsedVersion{base: out, pre: identifiers}, nil
	}
	aa, err := parse(a)
	if err != nil {
		return 0, err
	}
	bb, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range aa.base {
		if aa.base[i] < bb.base[i] {
			return -1, nil
		}
		if aa.base[i] > bb.base[i] {
			return 1, nil
		}
	}
	if len(aa.pre) == 0 && len(bb.pre) == 0 {
		return 0, nil
	}
	if len(aa.pre) == 0 {
		return 1, nil
	}
	if len(bb.pre) == 0 {
		return -1, nil
	}
	for i := 0; i < len(aa.pre) && i < len(bb.pre); i++ {
		left, right := aa.pre[i], bb.pre[i]
		leftNumeric, rightNumeric := allDigits(left), allDigits(right)
		switch {
		case leftNumeric && rightNumeric:
			ln, _ := strconv.Atoi(left)
			rn, _ := strconv.Atoi(right)
			if ln < rn {
				return -1, nil
			}
			if ln > rn {
				return 1, nil
			}
		case leftNumeric:
			return -1, nil
		case rightNumeric:
			return 1, nil
		case left < right:
			return -1, nil
		case left > right:
			return 1, nil
		}
	}
	if len(aa.pre) < len(bb.pre) {
		return -1, nil
	}
	if len(aa.pre) > len(bb.pre) {
		return 1, nil
	}
	return 0, nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
