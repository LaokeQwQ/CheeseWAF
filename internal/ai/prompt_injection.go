package ai

import (
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

// PromptInjectionFinding is a conservative signal, not a verdict. It is used
// only to keep untrusted log text away from the model and to stop automatic
// write actions; the deterministic WAF evidence remains authoritative.
type PromptInjectionFinding struct {
	Suspected bool
	Signals   []string
}

var (
	promptRoleMarkerPatterns = []struct {
		label string
		re    *regexp.Regexp
	}{
		{"chat-role-token", regexp.MustCompile(`(?i)<\|(?:im_start|im_end|system|user|assistant|developer|tool)\|>`)},
		{"instruction-token", regexp.MustCompile(`(?i)\[/?INST\]|<<?/?SYS>>?`)},
		{"chat-heading", regexp.MustCompile(`(?im)^\s*#{2,}\s*(?:system|assistant|developer|tool)\b`)},
		{"role-prefix", regexp.MustCompile(`(?im)^\s*(?:system|assistant|developer|tool)\s*:`)},
	}
	promptOverridePatterns = []struct {
		label string
		re    *regexp.Regexp
	}{
		{"ignore-previous-instructions", regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directions?)\b`)},
		{"reveal-hidden-prompt", regexp.MustCompile(`(?i)\b(?:reveal|show|print|repeat|leak|dump)\b[\s\S]{0,80}\b(?:system prompt|hidden prompt|developer message|instructions?|api key|secret)\b`)},
		{"role-override", regexp.MustCompile(`(?i)\b(?:you are now|act as|developer mode|jailbreak|do anything now|\bDAN\b)\b`)},
		{"tool-or-command-request", regexp.MustCompile(`(?i)\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|command|shell|bash|powershell)\b`)},
		{"disable-security", regexp.MustCompile(`(?i)\b(?:disable|bypass|turn off|ignore)\s+(?:the\s+)?(?:waf|protection|approval|security|guardrail)\b`)},
	}
)

// ScanPromptInjection inspects attacker-controlled log fields before they are
// serialized into a model prompt. It intentionally does not inspect trusted
// configuration or operator identity fields.
func ScanPromptInjection(entry storage.LogEntry) PromptInjectionFinding {
	texts := []string{entry.URI, entry.Payload, entry.Message, entry.UserAgent}
	seen := map[string]struct{}{}
	finding := PromptInjectionFinding{}
	add := func(label string) {
		if _, ok := seen[label]; ok {
			return
		}
		seen[label] = struct{}{}
		finding.Signals = append(finding.Signals, label)
	}
	for _, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		for _, marker := range promptRoleMarkerPatterns {
			if marker.re.MatchString(text) {
				add(marker.label)
			}
		}
		for _, pattern := range promptOverridePatterns {
			if pattern.re.MatchString(text) {
				add(pattern.label)
			}
		}
	}
	finding.Suspected = len(finding.Signals) > 0
	return finding
}

// NeutralizePromptRoleMarkers keeps evidence readable but removes the exact
// chat-control tokens an untrusted value could use to impersonate a role.
func NeutralizePromptRoleMarkers(value string) string {
	for _, marker := range promptRoleMarkerPatterns {
		value = marker.re.ReplaceAllString(value, "[prompt-role-marker]")
	}
	return value
}
