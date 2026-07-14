package version

import (
	"runtime"
	"testing"
)

func TestCurrentReturnsBuildMetadataAndRuntimeIdentity(t *testing.T) {
	original := []string{Version, Commit, BuildTime, Channel, Edition}
	t.Cleanup(func() {
		Version, Commit, BuildTime, Channel, Edition = original[0], original[1], original[2], original[3], original[4]
	})
	Version, Commit, BuildTime, Channel, Edition = "1.2.3", "abc123", "2026-07-11T00:00:00Z", "stable", "enterprise"
	got := Current()
	if got.Version != Version || got.Commit != Commit || got.BuildTime != BuildTime || got.Channel != Channel || got.Edition != Edition {
		t.Fatalf("metadata = %#v", got)
	}
	if got.GoVersion != runtime.Version() || got.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("runtime = %#v", got)
	}
}
