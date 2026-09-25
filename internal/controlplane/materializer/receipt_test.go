package materializer

import (
	"errors"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

func testCommit(t *testing.T, epoch controlplane.Epoch, revision controlplane.Revision, nonce string) controlplane.Commit {
	t.Helper()
	payload, digest, err := desiredstate.EncodeProtectionPolicy(config.ProtectionPolicyConfig{
		WebAttack: config.ProtectionLevelSmart, APISecurity: config.ProtectionLevelHigh,
		BotCC: config.ProtectionLevelLow, ThreatIntel: config.ProtectionLevelOff,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controlplane.Commit{
		State: controlplane.State{
			ClusterID: "cluster-a", LeaderID: "leader-a", Term: uint64(epoch), Epoch: epoch,
			Revision: revision, Desired: controlplane.DesiredState{Version: desiredstate.Version, Digest: digest, Payload: payload},
			NonceLedger: map[string]controlplane.Revision{nonce: revision},
		},
		Fence: controlplane.FenceToken{ClusterID: "cluster-a", LeaderID: "leader-a", Epoch: epoch, Revision: revision, Digest: digest, Nonce: nonce},
	}
}

func TestReceiptRejectsSensitiveOrUntypedPayload(t *testing.T) {
	commit := testCommit(t, 1, 1, "nonce-1")
	commit.State.Desired.Payload = []byte(`{"dsn":"postgres://secret"}`)
	commit.State.Desired.Digest = controlplane.Digest(commit.State.Desired.Payload)
	commit.Fence.Digest = commit.State.Desired.Digest
	if _, err := FromCommit(commit, PhasePrepared); err == nil || !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("sensitive payload err=%v, want ErrReceiptCorrupt", err)
	}
}

func TestTransitionRejectsHistoricalRevisionDespiteStateMachineHistory(t *testing.T) {
	current, err := NewReceipt(testCommit(t, 2, 9, "nonce-9"), PhaseApplied)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := NewReceipt(testCommit(t, 2, 8, "nonce-8"), PhasePrepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTransition(&current, historical); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("historical revision err=%v, want ErrStaleRevision", err)
	}
}

func TestTransitionIdempotenceAndConflicts(t *testing.T) {
	prepared, err := NewReceipt(testCommit(t, 1, 1, "nonce-1"), PhasePrepared)
	if err != nil {
		t.Fatal(err)
	}
	copyReceipt := prepared.Clone()
	idempotent, err := Compare(&prepared, copyReceipt)
	if err != nil || !idempotent {
		t.Fatalf("same receipt idempotence=%v err=%v", idempotent, err)
	}
	baselineReceipt := prepared.Clone()
	baselineReceipt.Phase = PhaseBaselinePersisted
	if idempotent, err := Compare(&prepared, baselineReceipt); err != nil || idempotent {
		t.Fatalf("phase advance idempotence=%v err=%v", idempotent, err)
	}
	conflict := prepared.Clone()
	conflict.Commit.Nonce = "nonce-other"
	if err := ValidateTransition(&prepared, conflict); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("nonce conflict err=%v, want ErrCommitConflict", err)
	}
	conflict = prepared.Clone()
	conflict.Payload, conflict.Commit.Digest, _ = desiredstate.EncodeProtectionPolicy(config.ProtectionPolicyConfig{
		WebAttack: config.ProtectionLevelStrict, APISecurity: config.ProtectionLevelHigh,
		BotCC: config.ProtectionLevelLow, ThreatIntel: config.ProtectionLevelOff,
	})
	if err := ValidateTransition(&prepared, conflict); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("payload conflict err=%v, want ErrCommitConflict", err)
	}
	skip := prepared.Clone()
	skip.Phase = PhaseApplied
	if err := ValidateTransition(&prepared, skip); !errors.Is(err, ErrPhaseRegression) {
		t.Fatalf("phase skip err=%v, want ErrPhaseRegression", err)
	}

	newLeader := prepared.Clone()
	newLeader.Commit.Epoch = 2
	newLeader.Commit.Revision = 1
	newLeader.Commit.LeaderID = "leader-b"
	newLeader.Phase = PhasePrepared
	if err := ValidateTransition(&prepared, newLeader); err != nil {
		t.Fatalf("new epoch leader change err=%v", err)
	}
}

func TestTransitionEpochAndPhaseRules(t *testing.T) {
	base, err := NewReceipt(testCommit(t, 3, 4, "nonce-4"), PhaseApplied)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch, _ := NewReceipt(testCommit(t, 2, 99, "nonce-old"), PhasePrepared)
	if err := ValidateTransition(&base, oldEpoch); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old epoch err=%v, want ErrStaleEpoch", err)
	}
	newEpoch, _ := NewReceipt(testCommit(t, 4, 1, "nonce-new"), PhasePrepared)
	if err := ValidateTransition(&base, newEpoch); err != nil {
		t.Fatalf("new epoch prepared err=%v", err)
	}
	regression := base.Clone()
	regression.Phase = PhaseYAMLPersisted
	if err := ValidateTransition(&base, regression); !errors.Is(err, ErrPhaseRegression) {
		t.Fatalf("applied phase regression err=%v, want ErrPhaseRegression", err)
	}
	if _, err := NewReceipt(testCommit(t, 1, 1, "nonce"), Phase("unknown")); !errors.Is(err, ErrInvalidPhase) {
		t.Fatalf("unknown phase err=%v, want ErrInvalidPhase", err)
	}
}

func TestReceiptJSONStrictDecode(t *testing.T) {
	r, err := NewReceipt(testCommit(t, 1, 1, "nonce-1"), PhasePrepared)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{" {}", "\n{}"} {
		if _, err := decodeReceipt(append(append([]byte(nil), encoded...), suffix...)); err == nil {
			t.Fatalf("trailing JSON %q unexpectedly accepted", suffix)
		}
	}
	unknown := strings.TrimSuffix(string(encoded), "}") + `,"unexpected":true}`
	if _, err := decodeReceipt([]byte(unknown)); err == nil {
		t.Fatal("unknown receipt field unexpectedly accepted")
	}
}
