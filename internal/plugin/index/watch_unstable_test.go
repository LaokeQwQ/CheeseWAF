package index

import "testing"

// An exhausted retry loop must never return a fingerprint that a later tick
// could consider current; otherwise the change that settles the directory is
// never reloaded.
func TestUnstableFingerprintNeverMatches(t *testing.T) {
	dir := t.TempDir()
	unstable := dirFingerprint{err: "directory kept changing during scan"}
	if unstable.equal(fingerprintDir(dir)) {
		t.Fatal("unstable fingerprint matched a real directory")
	}
	if unstable.equal(dirFingerprint{}) {
		t.Fatal("unstable fingerprint matched an empty fingerprint")
	}
}
