package desiredstate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

func validPolicy() config.ProtectionPolicyConfig {
	return config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelSmart,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelLow,
		ThreatIntel: config.ProtectionLevelOff,
	}
}

func TestEncodeProtectionPolicyIsCanonicalAndDigestBound(t *testing.T) {
	payload, digest, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"management.v1","kind":"protection.policy","spec":{"web_attack":"smart","api_security":"high","bot_cc":"low","threat_intel":"off"}}`
	if string(payload) != want {
		t.Fatalf("payload = %s, want %s", payload, want)
	}
	if digest != controlplane.Digest(payload) {
		t.Fatalf("digest = %s, want digest of exact payload", digest)
	}
	if strings.Contains(strings.ToLower(string(payload)), "secret") || strings.Contains(strings.ToLower(string(payload)), "token") || strings.Contains(strings.ToLower(string(payload)), "dsn") || strings.Contains(strings.ToLower(string(payload)), "cert") || strings.Contains(strings.ToLower(string(payload)), "key") {
		t.Fatalf("payload contains a forbidden sensitive field: %s", payload)
	}

	decoded, err := DecodeProtectionPolicy(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decoded.Config()
	if err != nil {
		t.Fatal(err)
	}
	if got != validPolicy() {
		t.Fatalf("decoded policy = %+v, want %+v", got, validPolicy())
	}
}

func TestDecodeProtectionPolicyRejectsNonCanonicalOrAmbiguousJSON(t *testing.T) {
	payload, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"leading whitespace": append([]byte(" \n"), payload...),
		"trailing document":  append(append([]byte(nil), payload...), []byte(`{"version":"management.v1"}`)...),
		"duplicate field":    bytes.Replace(payload, []byte(`"kind":"protection.policy"`), []byte(`"kind":"protection.policy","kind":"protection.policy"`), 1),
		"unknown top-level":  bytes.Replace(payload, []byte(`,"kind"`), []byte(`,"unexpected":true,"kind"`), 1),
		"unknown spec":       bytes.Replace(payload, []byte(`,"threat_intel"`), []byte(`,"unexpected":true,"threat_intel"`), 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProtectionPolicy(input); err == nil {
				t.Fatalf("DecodeProtectionPolicy(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func TestDecodeProtectionPolicyRejectsInvalidIdentityAndFields(t *testing.T) {
	payload, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"wrong version": bytes.Replace(payload, []byte(`management.v1`), []byte(`management.v0`), 1),
		"wrong kind":    bytes.Replace(payload, []byte(`protection.policy`), []byte(`edge.policy`), 1),
		"missing field": bytes.Replace(payload, []byte(`,"threat_intel":"off"`), nil, 1),
		"empty field":   bytes.Replace(payload, []byte(`"bot_cc":"low"`), []byte(`"bot_cc":""`), 1),
		"invalid level": bytes.Replace(payload, []byte(`"bot_cc":"low"`), []byte(`"bot_cc":"unsafe"`), 1),
		"null spec":     []byte(`{"version":"management.v1","kind":"protection.policy","spec":null}`),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProtectionPolicy(input); err == nil {
				t.Fatalf("DecodeProtectionPolicy(%s) unexpectedly succeeded", name)
			}
		})
	}
}

func TestProtectionPolicyPayloadSizeAndUTF8Boundaries(t *testing.T) {
	for _, size := range []int{MaxPayloadBytes - 1, MaxPayloadBytes} {
		input := bytes.Repeat([]byte("x"), size)
		if _, err := DecodeProtectionPolicy(input); err == nil || strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("payload at %d bytes was rejected by the size boundary: %v", size, err)
		}
	}
	oversized := bytes.Repeat([]byte("x"), MaxPayloadBytes+1)
	if _, err := DecodeProtectionPolicy(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal("oversized payload unexpectedly succeeded")
	}
	invalid := append([]byte(`{"version":"management.v1","kind":"protection.policy","spec":{"web_attack":"smart","api_security":"high","bot_cc":"low","threat_intel":"`), 0xff)
	invalid = append(invalid, []byte(`"}}`)...)
	if _, err := DecodeProtectionPolicy(invalid); err == nil {
		t.Fatal("invalid UTF-8 payload unexpectedly succeeded")
	}
}

func TestProtectionPolicyAcceptsEachAllowedLevelOnEveryAxis(t *testing.T) {
	levels := []string{
		config.ProtectionLevelOff,
		config.ProtectionLevelLow,
		config.ProtectionLevelSmart,
		config.ProtectionLevelHigh,
		config.ProtectionLevelStrict,
	}
	for _, axis := range []string{"web_attack", "api_security", "bot_cc", "threat_intel"} {
		for _, level := range levels {
			t.Run(axis+"/"+level, func(t *testing.T) {
				policy := validPolicy()
				switch axis {
				case "web_attack":
					policy.WebAttack = level
				case "api_security":
					policy.APISecurity = level
				case "bot_cc":
					policy.BotCC = level
				case "threat_intel":
					policy.ThreatIntel = level
				}
				payload, _, err := EncodeProtectionPolicy(policy)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := DecodeProtectionPolicyConfig(payload)
				if err != nil {
					t.Fatal(err)
				}
				if decoded != policy {
					t.Fatalf("decoded policy = %+v, want %+v", decoded, policy)
				}
			})
		}
	}
}

func TestProtectionPolicyDocumentConfigRevalidatesExportedValues(t *testing.T) {
	doc, err := NewProtectionPolicyDocument(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	doc.Spec.BotCC = "unsafe"
	if _, err := doc.Config(); err == nil {
		t.Fatal("Config unexpectedly accepted an invalid exported document")
	}
}

func TestProtectionPolicyProposalBindsOuterVersionAndDigest(t *testing.T) {
	proposal, err := NewProtectionPolicyProposal(validPolicy(), "node-a", 3, 7, "nonce-7")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProtectionPolicyProposal(proposal); err != nil {
		t.Fatal(err)
	}

	wrongVersion := proposal
	wrongVersion.Version = "management.v2"
	if err := ValidateProtectionPolicyProposal(wrongVersion); err == nil {
		t.Fatal("proposal with wrong outer version unexpectedly succeeded")
	}

	wrongDigest := proposal
	wrongDigest.Digest = strings.Repeat("0", 64)
	if err := ValidateProtectionPolicyProposal(wrongDigest); err == nil {
		t.Fatal("proposal with wrong digest unexpectedly succeeded")
	}

	innerVersion := bytes.Replace(proposal.Payload, []byte(`management.v1`), []byte(`management.v2`), 1)
	wrongInner := proposal
	wrongInner.Payload = innerVersion
	wrongInner.Digest = controlplane.Digest(innerVersion)
	if err := ValidateProtectionPolicyProposal(wrongInner); err == nil {
		t.Fatal("proposal with wrong inner version unexpectedly succeeded")
	}
}

func TestMaterializeProtectionPolicyPreservesNodeLocalConfiguration(t *testing.T) {
	local := config.Default()
	local.Setup.DataDir = "/var/lib/cheesewaf"
	local.TLS.CertFile = "/etc/cheesewaf/cert.pem"
	local.Storage.ManagementPostgreSQL.DSN = "postgres://user:password@example.invalid/management"
	local.Protection.Bot.Secret = "node-local-bot-secret"
	localPolicy := local.Protection.Policy

	payload, _, err := EncodeProtectionPolicy(config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelStrict,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelSmart,
		ThreatIntel: config.ProtectionLevelLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := MaterializeProtectionPolicy(&local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Protection.Policy.WebAttack != config.ProtectionLevelStrict || candidate.Protection.Policy == localPolicy {
		t.Fatalf("candidate policy was not replaced: %+v", candidate.Protection.Policy)
	}
	if candidate.Setup.DataDir != local.Setup.DataDir || candidate.TLS.CertFile != local.TLS.CertFile || candidate.Storage.ManagementPostgreSQL.DSN != local.Storage.ManagementPostgreSQL.DSN || candidate.Protection.Bot.Secret != local.Protection.Bot.Secret {
		t.Fatal("materialization changed node-local configuration")
	}
	if local.Protection.Policy != localPolicy {
		t.Fatal("materialization mutated the source configuration")
	}
}

func TestMaterializeProtectionPolicyRejectsInvalidLocalCandidate(t *testing.T) {
	local := config.Default()
	local.Server.Listen = ""
	payload, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeProtectionPolicy(&local, payload); err == nil {
		t.Fatal("materialization unexpectedly accepted an invalid local candidate")
	}
}

func TestMaterializeProtectionPolicyRejectsNilLocalConfig(t *testing.T) {
	payload, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MaterializeProtectionPolicy(nil, payload); err == nil {
		t.Fatal("materialization unexpectedly accepted a nil local config")
	}
}

func TestEncodeProtectionPolicyRejectsPartialState(t *testing.T) {
	if _, _, err := EncodeProtectionPolicy(config.ProtectionPolicyConfig{WebAttack: config.ProtectionLevelSmart}); err == nil {
		t.Fatal("partial policy unexpectedly encoded")
	}
	if _, _, err := EncodeProtectionPolicy(config.ProtectionPolicyConfig{WebAttack: "invalid", APISecurity: "smart", BotCC: "smart", ThreatIntel: "smart"}); err == nil {
		t.Fatal("invalid policy unexpectedly encoded")
	}
}

func TestEncodeProtectionPolicyDoesNotAliasReturnedBytes(t *testing.T) {
	first, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	second, _, err := EncodeProtectionPolicy(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if second[0] != '{' {
		t.Fatalf("second encode reused mutated bytes: %q", second)
	}
}
