package crp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testManifest(data []byte) Manifest {
	digests := ComputeDigests(data)
	return Manifest{
		APIVersion:      APIVersion,
		Kind:            Kind,
		Name:            "rate-limit",
		PluginID:        "rate-limit",
		Version:         "1.2.3",
		Namespace:       "official/rate-limit",
		Publisher:       "cheesesec",
		Source:          "ota",
		SourceRoot:      "vendor-root-v1",
		ReleaseSequence: 42,
		Artifact: Artifact{
			Name:    "rate-limit.crp",
			Size:    int64(len(data)),
			Digests: digests,
		},
	}
}

func TestComputeAndVerifyAllDigests(t *testing.T) {
	data := []byte("cheesewaf-crp")
	digests := ComputeDigests(data)
	if err := VerifyDigests(data, digests); err != nil {
		t.Fatalf("valid digest set rejected: %v", err)
	}
	for _, name := range []string{"md5", "sha1", "sha256"} {
		bad := digests
		switch name {
		case "md5":
			bad.MD5 = strings.Repeat("0", len(bad.MD5))
		case "sha1":
			bad.SHA1 = strings.Repeat("0", len(bad.SHA1))
		case "sha256":
			bad.SHA256 = strings.Repeat("0", len(bad.SHA256))
		}
		if err := VerifyDigests(data, bad); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("%s mismatch error=%v, want ErrDigestMismatch", name, err)
		}
	}
	uppercase := digests
	uppercase.SHA256 = strings.ToUpper(uppercase.SHA256)
	if err := VerifyDigests(data, uppercase); !errors.Is(err, ErrMissingDigest) {
		t.Fatalf("uppercase digest error=%v, want ErrMissingDigest", err)
	}
}

func TestManifestValidateAndVerify(t *testing.T) {
	data := []byte("package bytes")
	m := testManifest(data)
	if err := m.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if err := m.Verify(data); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	if err := m.Verify([]byte("tampered")); !errors.Is(err, ErrArtifactSize) {
		t.Fatalf("size mismatch error=%v, want ErrArtifactSize", err)
	}
	m.Artifact.Size = int64(len(data))
	m.Artifact.Digests.SHA256 = strings.Repeat("0", 64)
	if err := m.Verify(data); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch error=%v, want ErrDigestMismatch", err)
	}
	m.Artifact.Digests = ComputeDigests(data)
	m.Digests = Digests{MD5: strings.Repeat("0", 32), SHA1: strings.Repeat("0", 40), SHA256: strings.Repeat("0", 64)}
	if err := m.Validate(); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("conflicting digest sets error=%v, want ErrInvalidManifest", err)
	}
}

func TestParseManifestRejectsUnknownAndTrailingData(t *testing.T) {
	data := []byte("bytes")
	m := testManifest(data)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseManifest(b); err != nil || parsed.Version != m.Version {
		t.Fatalf("valid JSON parse=(%+v, %v)", parsed, err)
	}
	for _, input := range []string{
		string(b) + " {}",
		string(b) + " nope",
		strings.Replace(string(b), `"version":"1.2.3"`, `"version":"1.2.3","unexpected":true`, 1),
	} {
		if _, err := ParseManifest([]byte(input)); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("input was accepted: err=%v", err)
		}
	}
}

func TestNamespaceAndSourceBinding(t *testing.T) {
	for _, namespace := range []string{"official/rate-limit", "enterprise/acme/rate-limit", "community/alice/rate-limit", "personal/alice/rate-limit", "test/nightly/rate-limit", "development/local/rate-limit"} {
		if err := ValidateNamespace(namespace); err != nil {
			t.Errorf("namespace %q rejected: %v", namespace, err)
		}
	}
	for _, namespace := range []string{"", "unknown/plugin", "enterprise", "enterprise/acme", "official", "official/a/b", "official/../plugin", "official/a b"} {
		if err := ValidateNamespace(namespace); !errors.Is(err, ErrNamespace) {
			t.Errorf("namespace %q error=%v, want ErrNamespace", namespace, err)
		}
	}
	for _, source := range []string{"vendor-root-v1", "enterprise/acme/root-2", "offline:bundle-v1", "https://ota.cheesesec.com/root-v1"} {
		if err := ValidateSourceRoot(source); err != nil {
			t.Errorf("source root %q rejected: %v", source, err)
		}
	}
	for _, source := range []string{"", "../root", "root\\v1", "root v1", "root\nnext"} {
		if err := ValidateSourceRoot(source); !errors.Is(err, ErrSource) {
			t.Errorf("source root %q error=%v, want ErrSource", source, err)
		}
	}
	m := testManifest([]byte("bytes"))
	if err := m.ValidateBinding("official/rate-limit", "vendor-root-v1"); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	if err := m.ValidateWith(ValidationOptions{ExpectedNamespace: "enterprise/acme/rate-limit"}); !errors.Is(err, ErrNamespace) {
		t.Fatalf("wrong namespace error=%v, want ErrNamespace", err)
	}
	if err := m.ValidateWith(ValidationOptions{ExpectedSourceRoot: "other-root"}); !errors.Is(err, ErrSource) {
		t.Fatalf("wrong source root error=%v, want ErrSource", err)
	}
	if err := m.ValidateWith(ValidationOptions{ExpectedSource: "peer"}); !errors.Is(err, ErrSource) {
		t.Fatalf("wrong source error=%v, want ErrSource", err)
	}
}

func TestManifestNoDowngradeChecksVersionAndSequence(t *testing.T) {
	m := testManifest([]byte("bytes"))
	for _, current := range []Release{{Version: "1.2.2", Sequence: 41}, {Version: "1.2.3", Sequence: 42}, {Version: "1.2.3", Sequence: 0}} {
		if err := m.ValidateUpgrade(current); err != nil {
			t.Errorf("candidate should be accepted against %+v: %v", current, err)
		}
	}
	for _, current := range []Release{{Version: "1.3.0", Sequence: 42}, {Version: "1.2.3", Sequence: 43}} {
		if err := m.ValidateUpgrade(current); !errors.Is(err, ErrDowngrade) {
			t.Errorf("candidate against %+v error=%v, want ErrDowngrade", current, err)
		}
	}
	for _, pair := range []struct {
		current   Release
		candidate Release
	}{
		{Release{Version: "1.0.0", Sequence: 1}, Release{Version: "1.0.1", Sequence: 2}},
		{Release{Version: "1.0.0-alpha.1", Sequence: 1}, Release{Version: "1.0.0", Sequence: 2}},
		{Release{Version: "1.0.0-alpha.2", Sequence: 1}, Release{Version: "1.0.0-alpha.10", Sequence: 2}},
		{Release{Version: "1.0.0+build.1", Sequence: 1}, Release{Version: "1.0.0+build.2", Sequence: 2}},
	} {
		if err := ValidateNoDowngrade(pair.current, pair.candidate); err != nil {
			t.Errorf("upgrade %+v -> %+v rejected: %v", pair.current, pair.candidate, err)
		}
	}
	for _, pair := range []struct {
		current   Release
		candidate Release
	}{
		{Release{Version: "1.0.1", Sequence: 2}, Release{Version: "1.0.0", Sequence: 3}},
		{Release{Version: "1.0.0", Sequence: 2}, Release{Version: "1.0.1", Sequence: 1}},
		{Release{Version: "1.0.0", Sequence: 2}, Release{Version: "1.0.1", Sequence: 0}},
	} {
		if err := ValidateNoDowngrade(pair.current, pair.candidate); !errors.Is(err, ErrDowngrade) {
			t.Errorf("downgrade %+v -> %+v error=%v, want ErrDowngrade", pair.current, pair.candidate, err)
		}
	}
}

func TestManifestRequiresAllDigests(t *testing.T) {
	m := testManifest([]byte("bytes"))
	m.Artifact.Digests.SHA1 = ""
	if err := m.Validate(); !errors.Is(err, ErrMissingDigest) {
		t.Fatalf("missing digest error=%v, want ErrMissingDigest", err)
	}
	m = testManifest([]byte("bytes"))
	m.Source = "bad source\n"
	if err := m.Validate(); !errors.Is(err, ErrSource) {
		t.Fatalf("invalid source error=%v, want ErrSource", err)
	}
}

func TestSourceRegistryBindsRootsNamespacesAndSources(t *testing.T) {
	registry, err := NewSourceRegistry([]SourceRootRegistration{
		{ID: "vendor-root-v1", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota", "peer", "offline"}},
		{ID: "enterprise-acme-v1", NamespacePrefixes: []string{"enterprise/acme/"}, Sources: []string{"ota", "offline"}},
		{ID: "community-root-v1", NamespacePrefixes: []string{"community/alice/"}, Sources: []string{"peer"}},
	})
	if err != nil {
		t.Fatalf("registry construction failed: %v", err)
	}
	valid := testManifest([]byte("bytes"))
	if err := registry.Validate(valid); err != nil {
		t.Fatalf("registered official manifest rejected: %v", err)
	}

	wrongSource := valid
	wrongSource.Source = "unknown-peer"
	if err := registry.Validate(wrongSource); !errors.Is(err, ErrSource) {
		t.Fatalf("unknown source error=%v, want ErrSource", err)
	}
	wrongRoot := valid
	wrongRoot.SourceRoot = "missing-root"
	if err := registry.Validate(wrongRoot); !errors.Is(err, ErrSource) {
		t.Fatalf("unknown root error=%v, want ErrSource", err)
	}
	crossNamespace := valid
	crossNamespace.Namespace = "enterprise/acme/rate-limit"
	if err := registry.Validate(crossNamespace); !errors.Is(err, ErrNamespace) {
		t.Fatalf("cross-namespace error=%v, want ErrNamespace", err)
	}
	missingSource := valid
	missingSource.Source = ""
	if err := registry.Validate(missingSource); !errors.Is(err, ErrSource) {
		t.Fatalf("missing source error=%v, want ErrSource", err)
	}

	got, ok := registry.SourceRoot("vendor-root-v1")
	if !ok || len(got.Sources) != 3 || len(got.NamespacePrefixes) != 1 {
		t.Fatalf("source root lookup=%+v, found=%v", got, ok)
	}
	got.Sources[0] = "mutated"
	again, _ := registry.SourceRoot("vendor-root-v1")
	if again.Sources[0] == "mutated" {
		t.Fatal("source root lookup returned mutable registry state")
	}
}

func TestSourceRegistryRejectsIncompleteOrDuplicateRegistrations(t *testing.T) {
	tests := []struct {
		name  string
		roots []SourceRootRegistration
		want  error
	}{
		{"duplicate root", []SourceRootRegistration{
			{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota"}},
			{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota"}},
		}, ErrSource},
		{"missing namespace", []SourceRootRegistration{{ID: "root", Sources: []string{"ota"}}}, ErrNamespace},
		{"missing source allowlist", []SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"official/"}}}, ErrSource},
		{"unknown namespace prefix", []SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"unknown/"}, Sources: []string{"ota"}}}, ErrNamespace},
		{"unsafe source", []SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"ota\npeer"}}}, ErrSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSourceRegistry(tt.roots); !errors.Is(err, tt.want) {
				t.Fatalf("error=%v, want %v", err, tt.want)
			}
		})
	}
}

func ExampleComputeDigests() {
	d := ComputeDigests([]byte("hello"))
	fmt.Println(d.MD5, d.SHA1, d.SHA256)
	// Output:
	// 5d41402abc4b2a76b9719d911017c592 aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
}
