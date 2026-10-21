package intel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

const (
	// MultipartProgressMarker is the PHP upload progress form field.
	MultipartProgressMarker = "PHP_SESSION_UPLOAD_PROGRESS"
	// DefaultSessionParameter is the PHP session cookie/field name.
	DefaultSessionParameter = "PHPSESSID"
	// OversizedSessionCookieValueBytes is the cookie value length that marks
	// a response-side session leak as anomalous.
	OversizedSessionCookieValueBytes = 200
)

// RuleClass identifies the deterministic rule shape chosen for an extraction.
type RuleClass string

const (
	RuleClassMultipartProgress RuleClass = "multipart_session_progress"
	RuleClassNestedArrays      RuleClass = "nested_arrays"
	RuleClassPHPMarker         RuleClass = "php_marker"
	RuleClassSessionCookieLeak RuleClass = "response_cookie_leak"
)

// RuleCompiler deterministically maps an extraction onto a minimal rule. It
// never emits wildcard-only patterns and never enables a rule.
type RuleCompiler struct{}

// NewRuleCompiler returns the deterministic compiler.
func NewRuleCompiler() RuleCompiler {
	return RuleCompiler{}
}

// Compile converts an extraction into a disabled, log-only custom rule scoped
// to a single site. When the extraction lacks a shape that can be expressed
// safely and narrowly, it returns ErrNoSafeRule.
func (RuleCompiler) Compile(extraction Extraction, scope Scope) (CompiledRule, error) {
	if err := ValidateExtraction(extraction); err != nil {
		return CompiledRule{}, err
	}
	if scope.IsGlobal() {
		return CompiledRule{}, fmt.Errorf("%w: rule scope must name a single site", ErrInvalid)
	}
	if scope.PathPrefix == "" && extraction.Request.Path != "" && strings.TrimSpace(extraction.Request.Path) != "/" {
		scope.PathPrefix = extraction.Request.Path
	}
	if len(scope.Methods) == 0 {
		if method := strings.ToUpper(strings.TrimSpace(extraction.Request.Method)); method != "" {
			scope.Methods = []string{method}
		}
	}
	if err := scope.Validate(); err != nil {
		return CompiledRule{}, err
	}
	class, location, pattern, ok := selectRuleShape(extraction)
	if !ok {
		return CompiledRule{}, fmt.Errorf("%w: extraction has no request or response shape that maps to a narrow rule", ErrNoSafeRule)
	}
	rule := config.CustomRuleConfig{
		ID:          compiledRuleID(class, scope, extraction, pattern),
		Name:        compiledRuleName(class, extraction),
		Description: compiledRuleDescription(class, extraction),
		Pattern:     pattern,
		Location:    location,
		Action:      ActionLog,
		Severity:    "medium",
		Enabled:     false,
		Priority:    200,
	}
	compiled := CompiledRule{Rule: rule, Scope: scope}
	if err := ValidateCompiledRule(compiled); err != nil {
		return CompiledRule{}, err
	}
	return compiled, nil
}

type ruleShape func(Extraction) (RuleClass, string, string, bool)

var ruleShapes = []ruleShape{
	compileMultipartProgress,
	compileNestedArrays,
	compilePHPMarker,
	compileOversizedSessionCookie,
}

func selectRuleShape(extraction Extraction) (RuleClass, string, string, bool) {
	for _, shape := range ruleShapes {
		if class, location, pattern, ok := shape(extraction); ok {
			return class, location, pattern, true
		}
	}
	return "", "", "", false
}

func compileMultipartProgress(extraction Extraction) (RuleClass, string, string, bool) {
	shape := extraction.Request
	if !shape.UploadProgress && shape.SessionParameter == "" {
		return "", "", "", false
	}
	multipart := strings.Contains(strings.ToLower(shape.ContentType), "multipart/form-data")
	session := shape.SessionParameter
	if session == "" {
		session = MultipartProgressMarker
	}
	quoted := regexp.QuoteMeta(session)
	if multipart {
		pattern := `(?i)content-disposition:[^\r\n]{0,256}\bname="` + quoted + `"`
		return RuleClassMultipartProgress, "body", pattern, true
	}
	if shape.UploadProgress {
		pattern := `(?i)(?:^|&)` + quoted + `=`
		return RuleClassMultipartProgress, "body", pattern, true
	}
	return "", "", "", false
}

func compileNestedArrays(extraction Extraction) (RuleClass, string, string, bool) {
	if !extraction.Request.NestedArrays {
		return "", "", "", false
	}
	if len(extraction.Request.ParameterNames) > 0 {
		name := regexp.QuoteMeta(extraction.Request.ParameterNames[0])
		pattern := `(?i)(?:^|[&;]|name=")` + name + `(?:\[[^\]\r\n]{0,32}\]){3,}`
		return RuleClassNestedArrays, "body", pattern, true
	}
	pattern := `(?i)(?:^|[&;]|name=")[a-z0-9_]{1,64}(?:\[[^\]\r\n]{0,32}\]){4,}(?:=|")`
	return RuleClassNestedArrays, "body", pattern, true
}

func compilePHPMarker(extraction Extraction) (RuleClass, string, string, bool) {
	// Current rule locations are request-only. Response body markers cannot be
	// enforced by the request pipeline, so never compile them into a body rule.
	markers := extraction.Request.Markers
	fragments := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	for _, marker := range markers {
		fragment, ok := markerFragment(marker)
		if !ok {
			continue
		}
		if _, exists := seen[fragment]; exists {
			continue
		}
		seen[fragment] = struct{}{}
		fragments = append(fragments, fragment)
		if len(fragments) == 4 {
			break
		}
	}
	if len(fragments) == 0 {
		return "", "", "", false
	}
	pattern := `(?i)(?:` + strings.Join(fragments, "|") + `)`
	return RuleClassPHPMarker, "body", pattern, true
}

func compileOversizedSessionCookie(Extraction) (RuleClass, string, string, bool) {
	// Response Set-Cookie evidence needs a response inspection location. The
	// rule engine only evaluates request headers/body today, so compiling it as
	// a request cookie rule would silently never match the evidence.
	return "", "", "", false
}

func markerFragment(marker string) (string, bool) {
	normalized := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(marker)), " "))
	switch normalized {
	case "<?php", "php tag", "php open tag", "php-open-tag":
		return `<\?php`, true
	case "<?=", "php echo tag", "php short echo tag":
		return `<\?=`, true
	case "serialized", "serialized marker", "php serialized", "php serialized marker", "o:", "o:marker":
		return `O:[0-9]{1,4}:"[A-Za-z_\\][A-Za-z0-9_\\]{0,64}"`, true
	}
	if len(normalized) < 4 || len(normalized) > 128 {
		return "", false
	}
	for _, r := range normalized {
		if r < 0x20 || r > 0x7e {
			return "", false
		}
	}
	return regexp.QuoteMeta(normalized), true
}

func compiledRuleID(class RuleClass, scope Scope, extraction Extraction, pattern string) string {
	hasher := sha256.New()
	for _, part := range []string{
		string(class),
		strings.TrimSpace(scope.SiteID),
		strings.TrimSpace(scope.PathPrefix),
		strings.Join(scope.Methods, ","),
		strings.Join(extraction.CVEIDs, ","),
		pattern,
	} {
		_, _ = io.WriteString(hasher, part)
		_, _ = hasher.Write([]byte{'\n'})
	}
	return "intel-" + classSlug(class) + "-" + hex.EncodeToString(hasher.Sum(nil))[:12]
}

func compiledRuleName(class RuleClass, extraction Extraction) string {
	subject := "advisory"
	if len(extraction.CVEIDs) > 0 {
		subject = extraction.CVEIDs[0]
	}
	return fmt.Sprintf("Intel %s %s", subject, classSlug(class))
}

func compiledRuleDescription(class RuleClass, extraction Extraction) string {
	cves := "none"
	if len(extraction.CVEIDs) > 0 {
		cves = strings.Join(extraction.CVEIDs, ",")
	}
	return fmt.Sprintf("Generated by the deterministic intel compiler; class=%s; cves=%s; review before enabling.", class, cves)
}

func classSlug(class RuleClass) string {
	switch class {
	case RuleClassMultipartProgress:
		return "multipart-progress"
	case RuleClassNestedArrays:
		return "nested-arrays"
	case RuleClassPHPMarker:
		return "php-marker"
	case RuleClassSessionCookieLeak:
		return "cookie-leak"
	default:
		return strings.ReplaceAll(string(class), "_", "-")
	}
}
