package crp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestHostCompatibilityCheck(t *testing.T) {
	cases := []struct {
		name    string
		compat  HostCompatibility
		host    string
		wantErr bool
		// hostError marks the case where the host version itself is invalid,
		// which is a caller error rather than a manifest problem.
		hostError bool
	}{
		{name: "open range accepts anything", compat: HostCompatibility{}, host: "0.4.5-beta"},
		{name: "min inclusive", compat: HostCompatibility{Min: "0.4.5"}, host: "0.4.5"},
		{name: "min rejects older", compat: HostCompatibility{Min: "0.4.5"}, host: "0.4.4", wantErr: true},
		{name: "prerelease satisfies min", compat: HostCompatibility{Min: "0.4.5"}, host: "0.4.5-beta"},
		{name: "v prefix accepted", compat: HostCompatibility{Min: "v0.4.0", Max: "v0.5.0"}, host: "0.4.9"},
		{name: "max inclusive", compat: HostCompatibility{Max: "0.5.0"}, host: "0.5.0"},
		{name: "max rejects newer", compat: HostCompatibility{Max: "0.5.0"}, host: "0.5.1", wantErr: true},
		{name: "three components compared numerically", compat: HostCompatibility{Min: "0.4.10"}, host: "0.4.9", wantErr: true},
		{name: "unparsable bound is rejected", compat: HostCompatibility{Min: "latest"}, host: "0.4.5", wantErr: true},
		{name: "unparsable host is rejected", compat: HostCompatibility{Min: "0.4.0"}, host: "dev", wantErr: true, hostError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.compat.Check(tc.host)
			if tc.wantErr && err == nil {
				t.Fatal("expected an incompatibility error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && !tc.hostError && !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestManifestValidateRejectsMalformedCompatibility(t *testing.T) {
	manifest := Manifest{Version: "1.0.0", Name: "demo", Namespace: "official/demo", SourceRoot: "root", Source: "offline", ReleaseSequence: 1}
	// Validate reaches the compatibility bounds after the digest check, so the
	// digests are satisfied here to isolate the bound validation.
	manifest.Digests = Digests{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64)}
	manifest.HostCompatibility = HostCompatibility{Min: "0.4.x"}
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "host_compatibility") {
		t.Fatalf("expected a malformed bound to be rejected, got %v", err)
	}
	manifest.HostCompatibility = HostCompatibility{Min: "0.4.0", Max: "0.5.0"}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("valid range rejected: %v", err)
	}
}

// Manifests signed before host_compatibility existed must keep identical bytes:
// the field is omitted entirely when no bound is declared.
func TestEmptyHostCompatibilityIsOmittedFromSigningBytes(t *testing.T) {
	manifest := Manifest{
		APIVersion: APIVersion, Kind: Kind, Name: "demo", Version: "1.0.0",
		Namespace: "official/demo", SourceRoot: "root", Source: "offline", ReleaseSequence: 1,
		Digests: Digests{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64)},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "host_compatibility") {
		t.Fatalf("empty range leaked into the signed bytes: %s", raw)
	}
	manifest.HostCompatibility = HostCompatibility{Min: "0.4.5"}
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal with range: %v", err)
	}
	if !strings.Contains(string(raw), `"host_compatibility":{"min":"0.4.5"}`) {
		t.Fatalf("declared range missing from the signed bytes: %s", raw)
	}
}
