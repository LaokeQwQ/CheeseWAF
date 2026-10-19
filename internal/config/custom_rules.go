package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CustomRulesDocument is the YAML/JSON envelope for batch import and export.
// It is the existing CustomRuleConfig slice, not a second rule format.
type CustomRulesDocument struct {
	CustomRules []CustomRuleConfig `yaml:"custom_rules" json:"custom_rules"`
}

const (
	CustomRulesFormatYAML      = "yaml"
	CustomRulesFormatJSON      = "json"
	maxCustomRulesBytes        = 1 << 20
	maxCustomRulesCount        = 256
	maxCustomRulesPatternBytes = 256 << 10
)

// ParseCustomRules reads a YAML or JSON document of CustomRuleConfig values.
// Accepted shapes are a `custom_rules` mapping or a bare array of rules.
func ParseCustomRules(data []byte) ([]CustomRuleConfig, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("custom rules document is empty")
	}
	if len(trimmed) > maxCustomRulesBytes {
		return nil, fmt.Errorf("custom rules document exceeds %d bytes", maxCustomRulesBytes)
	}
	if looksLikeModSecurity(trimmed) {
		return parseModSecurityRules(trimmed)
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		rules, err := parseCustomRulesJSON(trimmed)
		if err == nil {
			return rules, nil
		}
		yamlRules, yamlErr := parseCustomRulesYAML(trimmed)
		if yamlErr == nil {
			return yamlRules, nil
		}
		return nil, fmt.Errorf("parse custom rules: %w", err)
	}
	return parseCustomRulesYAML(trimmed)
}

var modSecurityRulePattern = regexp.MustCompile(`(?m)^\s*SecRule\s+([^\s]+)\s+"@([^\s]+)\s+([^\"]*)"\s+"([^\"]*)"\s*$`)

func looksLikeModSecurity(data []byte) bool {
	return regexp.MustCompile(`(?m)^\s*SecRule\b`).Match(data)
}

// parseModSecurityRules intentionally implements a small, explicit subset.
// Unsupported operators/actions are rejected so an import cannot silently lose
// detection semantics.
func parseModSecurityRules(data []byte) ([]CustomRuleConfig, error) {
	lines := strings.Split(string(data), "\n")
	var out []CustomRuleConfig
	for lineNo, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		matches := modSecurityRulePattern.FindStringSubmatch(trimmed)
		if matches == nil {
			if strings.HasPrefix(trimmed, "SecRule") {
				return nil, fmt.Errorf("modsecurity line %d: unsupported SecRule syntax", lineNo+1)
			}
			return nil, fmt.Errorf("modsecurity line %d: unsupported directive", lineNo+1)
		}
		variable, operator, pattern, actionText := matches[1], strings.ToLower(matches[2]), matches[3], matches[4]
		location, ok := modSecurityLocation(variable)
		if !ok {
			return nil, fmt.Errorf("modsecurity line %d: unsupported variable %q", lineNo+1, variable)
		}
		if operator != "rx" && operator != "contains" && operator != "streq" {
			return nil, fmt.Errorf("modsecurity line %d: unsupported operator %q", lineNo+1, operator)
		}
		if operator == "streq" {
			pattern = `\A` + regexp.QuoteMeta(pattern) + `\z`
		} else if operator == "contains" {
			pattern = regexp.QuoteMeta(pattern)
		}
		rule := CustomRuleConfig{Pattern: pattern, Location: location, Action: "block", Severity: "medium", Enabled: true}
		blockAction, logAction := false, false
		for _, action := range strings.Split(actionText, ",") {
			parts := strings.SplitN(strings.TrimSpace(action), ":", 2)
			name := strings.ToLower(strings.TrimSpace(parts[0]))
			value := ""
			if len(parts) == 2 {
				value = strings.Trim(strings.TrimSpace(parts[1]), "'\"")
			}
			switch name {
			case "id":
				rule.ID = value
			case "msg":
				rule.Name = value
			case "severity":
				rule.Severity = modSecuritySeverity(value)
			case "deny", "drop", "block":
				blockAction = true
			case "log":
				logAction = true
			case "pass", "allow":
				return nil, fmt.Errorf("modsecurity line %d: pass/allow actions are unsupported for WAF custom rules", lineNo+1)
			case "phase", "status", "tag", "capture", "nolog":
				// Metadata/control actions do not change native matching.
			case "chain":
				return nil, fmt.Errorf("modsecurity line %d: chain rules are unsupported", lineNo+1)
			default:
				return nil, fmt.Errorf("modsecurity line %d: unsupported action %q", lineNo+1, name)
			}
		}
		if blockAction {
			rule.Action = "block"
		} else if logAction {
			rule.Action = "log"
		}
		if rule.Name == "" {
			rule.Name = rule.ID
		}
		out = append(out, rule)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("modsecurity document contains no SecRule directives")
	}
	return out, nil
}

func modSecurityLocation(variable string) (string, bool) {
	variable = strings.ToUpper(strings.TrimSpace(variable))
	switch {
	case variable == "REQUEST_URI" || variable == "REQUEST_URL":
		return "request_uri", true
	case variable == "ARGS":
		return "args", true
	case variable == "ARGS_NAMES" || strings.HasPrefix(variable, "ARGS:"):
		return "", false
	case variable == "REQUEST_BODY":
		return "body", true
	case variable == "REQUEST_COOKIES":
		return "cookie", true
	case strings.HasPrefix(variable, "REQUEST_COOKIES:"):
		return "", false
	case variable == "REQUEST_HEADERS":
		return "header", true
	case strings.HasPrefix(variable, "REQUEST_HEADERS:"):
		return "", false
	default:
		return "", false
	}
}

func modSecuritySeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "emergency", "1", "alert", "2", "critical":
		return "critical"
	case "3", "error", "high":
		return "high"
	case "4", "warning", "medium":
		return "medium"
	case "5", "notice", "6", "info", "7", "debug", "8", "disabled", "low":
		return "low"
	default:
		return "medium"
	}
}

// MergeCustomRules merges imported rules by ID or location+pattern. Existing
// order is retained and imported entries replace matching entries.
func MergeCustomRules(existing, imported []CustomRuleConfig) ([]CustomRuleConfig, error) {
	base, err := prepareCustomRules(existing, false)
	if err != nil {
		return nil, err
	}
	next, err := prepareCustomRules(imported, false)
	if err != nil {
		return nil, err
	}
	merged := append([]CustomRuleConfig(nil), base...)
	byID := make(map[string]int, len(merged))
	byMatch := make(map[string]int, len(merged))
	for i, rule := range merged {
		if rule.ID != "" {
			byID[rule.ID] = i
		}
		byMatch[rule.Location+"\n"+rule.Pattern] = i
	}
	for _, rule := range next {
		idx, ok := -1, false
		if rule.ID != "" {
			idx, ok = byID[rule.ID]
		}
		if !ok {
			idx, ok = byMatch[rule.Location+"\n"+rule.Pattern]
		}
		if ok {
			old := merged[idx]
			// An ID-less import matched by location and pattern is an update to
			// the existing rule. Preserve its identity so audit/event references
			// remain stable across re-imports.
			if rule.ID == "" {
				rule.ID = old.ID
			}
			if old.ID != "" && byID[old.ID] == idx {
				delete(byID, old.ID)
			}
			oldMatch := old.Location + "\n" + old.Pattern
			if byMatch[oldMatch] == idx {
				delete(byMatch, oldMatch)
			}
			merged[idx] = rule
			if rule.ID != "" {
				byID[rule.ID] = idx
			}
			byMatch[rule.Location+"\n"+rule.Pattern] = idx
			continue
		}
		if rule.ID != "" {
			byID[rule.ID] = len(merged)
		}
		byMatch[rule.Location+"\n"+rule.Pattern] = len(merged)
		merged = append(merged, rule)
	}
	return PrepareCustomRules(merged)
}

func parseCustomRulesJSON(data []byte) ([]CustomRuleConfig, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var rules []CustomRuleConfig
		if err := decodeCustomRulesJSON(trimmed, &rules); err != nil {
			return nil, err
		}
		return rules, nil
	}
	var doc CustomRulesDocument
	if err := decodeCustomRulesJSON(trimmed, &doc); err != nil {
		return nil, err
	}
	if doc.CustomRules == nil {
		return nil, fmt.Errorf("custom_rules is required")
	}
	return doc.CustomRules, nil
}

func decodeCustomRulesJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("custom rules JSON contains more than one value")
		}
		return err
	}
	return nil
}

func parseCustomRulesYAML(data []byte) ([]CustomRuleConfig, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	node := &root
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	switch node.Kind {
	case yaml.SequenceNode:
		var rules []CustomRuleConfig
		if err := decodeCustomRulesYAML(data, &rules); err != nil {
			return nil, err
		}
		if rules == nil {
			rules = []CustomRuleConfig{}
		}
		return rules, nil
	case yaml.MappingNode:
		if !yamlMappingHasKey(node, "custom_rules") {
			return nil, fmt.Errorf("custom_rules is required")
		}
		var doc CustomRulesDocument
		if err := decodeCustomRulesYAML(data, &doc); err != nil {
			return nil, err
		}
		if doc.CustomRules == nil {
			return nil, fmt.Errorf("custom_rules is required")
		}
		return doc.CustomRules, nil
	default:
		return nil, fmt.Errorf("custom rules document must be a mapping or a list")
	}
}

func decodeCustomRulesYAML(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("custom rules YAML contains more than one document")
		}
		return err
	}
	return nil
}

func yamlMappingHasKey(node *yaml.Node, key string) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return true
		}
	}
	return false
}

// PrepareCustomRules validates a complete replacement set before publishing it.
// On any validation error it returns no rules so callers can keep the old set.
func PrepareCustomRules(rules []CustomRuleConfig) ([]CustomRuleConfig, error) {
	return prepareCustomRules(rules, true)
}

// prepareCustomRules validates and normalizes a rule set. IDs are generated
// only for a complete published set; merge operations keep omitted IDs absent
// so a derived ID cannot replace an unrelated rule.
func prepareCustomRules(rules []CustomRuleConfig, generateIDs bool) ([]CustomRuleConfig, error) {
	if rules == nil {
		rules = []CustomRuleConfig{}
	}
	if len(rules) > maxCustomRulesCount {
		return nil, fmt.Errorf("too many custom rules: got %d, maximum is %d", len(rules), maxCustomRulesCount)
	}
	normalized := make([]CustomRuleConfig, 0, len(rules))
	var errs []string
	patternBytes := 0
	for index, rule := range rules {
		rule = normalizeCustomRule(rule)
		patternBytes += len(rule.Pattern)
		if err := ValidateCustomRule(rule); err != nil {
			errs = append(errs, fmt.Sprintf("rule %s: %v", customRuleLabel(rule, index), err))
			continue
		}
		normalized = append(normalized, rule)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("custom rules invalid: %s", strings.Join(errs, "; "))
	}
	if patternBytes > maxCustomRulesPatternBytes {
		return nil, fmt.Errorf("custom rule patterns exceed %d bytes", maxCustomRulesPatternBytes)
	}
	if err := validateCustomRuleDuplicates(normalized); err != nil {
		return nil, err
	}
	if generateIDs {
		return assignCustomRuleIDs(normalized), nil
	}
	return normalized, nil
}

func normalizeCustomRule(rule CustomRuleConfig) CustomRuleConfig {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	rule.Location = strings.ToLower(strings.TrimSpace(rule.Location))
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	rule.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	if rule.Location == "" {
		rule.Location = "uri"
	}
	if rule.Action == "" {
		rule.Action = "block"
	}
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	return rule
}

func customRuleLabel(rule CustomRuleConfig, index int) string {
	if rule.ID != "" {
		return rule.ID
	}
	if rule.Name != "" {
		return rule.Name
	}
	return fmt.Sprintf("#%d", index+1)
}

func validateCustomRuleDuplicates(rules []CustomRuleConfig) error {
	seenID := make(map[string]struct{}, len(rules))
	seenMatch := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID != "" {
			if _, exists := seenID[rule.ID]; exists {
				return fmt.Errorf("duplicate custom rule id %q", rule.ID)
			}
			seenID[rule.ID] = struct{}{}
		}
		matchKey := rule.Location + "\n" + rule.Pattern
		if _, exists := seenMatch[matchKey]; exists {
			return fmt.Errorf("duplicate custom rule match for location %q", rule.Location)
		}
		seenMatch[matchKey] = struct{}{}
	}
	return nil
}

func assignCustomRuleIDs(rules []CustomRuleConfig) []CustomRuleConfig {
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID != "" {
			seen[rule.ID] = struct{}{}
		}
	}
	out := append([]CustomRuleConfig(nil), rules...)
	for index := range out {
		if out[index].ID != "" {
			continue
		}
		base := customRuleIDBase(out[index].Name, index)
		id := base
		suffix := 2
		for {
			if _, exists := seen[id]; !exists {
				break
			}
			id = fmt.Sprintf("%s-%d", base, suffix)
			suffix++
		}
		out[index].ID = id
		seen[id] = struct{}{}
	}
	return out
}

func customRuleIDBase(name string, index int) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Sprintf("custom-rule-%d", index+1)
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		return fmt.Sprintf("custom-rule-%d", index+1)
	}
	return id
}

// EncodeCustomRules writes the existing CustomRuleConfig slice as YAML or JSON.
func EncodeCustomRules(rules []CustomRuleConfig, format string) ([]byte, error) {
	if rules == nil {
		rules = []CustomRuleConfig{}
	}
	doc := CustomRulesDocument{CustomRules: rules}
	switch NormalizeCustomRulesFormat(format) {
	case CustomRulesFormatJSON:
		body, err := json.MarshalIndent(&doc, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode custom rules json: %w", err)
		}
		return append(body, '\n'), nil
	case CustomRulesFormatYAML:
		body, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, fmt.Errorf("encode custom rules yaml: %w", err)
		}
		return body, nil
	default:
		return nil, fmt.Errorf("format must be yaml or json")
	}
}

// NormalizeCustomRulesFormat maps yml/yaml/json aliases. Unknown values stay as-is.
func NormalizeCustomRulesFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "yaml", "yml":
		return CustomRulesFormatYAML
	case "json":
		return CustomRulesFormatJSON
	default:
		return strings.ToLower(strings.TrimSpace(format))
	}
}

// ExampleCustomRules is the downloadable import template. It uses the same
// fields as site custom_rules / CustomRuleConfig.
func ExampleCustomRules() []CustomRuleConfig {
	return []CustomRuleConfig{
		{
			ID:       "block-admin-probe",
			Name:     "Admin path probe",
			Pattern:  `(?i)/(wp-admin|phpmyadmin|\.git)`,
			Location: "uri",
			Action:   "block",
			Severity: "medium",
			Enabled:  true,
			Priority: 180,
		},
		{
			ID:       "block-scanner-ua",
			Name:     "Scanner user-agent",
			Pattern:  `(?i)(sqlmap|nikto|nuclei|masscan|zgrab)`,
			Location: "header",
			Action:   "block",
			Severity: "high",
			Enabled:  true,
			Priority: 160,
		},
	}
}

// ExampleCustomRulesDocument returns the template in yaml or json.
func ExampleCustomRulesDocument(format string) ([]byte, error) {
	prepared, err := PrepareCustomRules(ExampleCustomRules())
	if err != nil {
		return nil, err
	}
	return EncodeCustomRules(prepared, format)
}

// CustomRuleFilename is a download name for exported or example documents.
func CustomRuleFilename(kind, format string) string {
	base := strings.TrimSpace(kind)
	if base == "" {
		base = "custom_rules"
	}
	// This value is emitted in Content-Disposition. Restrict it to a safe
	// filename alphabet so caller-controlled site IDs cannot inject headers or
	// path separators. Invalid runes become underscores to keep the name useful.
	var safe strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			safe.WriteRune(r)
		} else {
			safe.WriteByte('_')
		}
	}
	base = strings.Trim(safe.String(), "._-")
	if base == "" {
		base = "custom_rules"
	}
	switch NormalizeCustomRulesFormat(format) {
	case CustomRulesFormatJSON:
		return base + ".json"
	default:
		return base + ".yaml"
	}
}
