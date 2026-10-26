package ip

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/google/uuid"
)

type ImportOptions struct {
	Source     string
	Severity   string
	Action     string
	Confidence float64
	Labels     []string
	ExpiresAt  time.Time
	Enabled    bool
}

func ParseThreatIntel(format string, contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	requestedSource := strings.TrimSpace(opts.Source)
	requestedAction := strings.TrimSpace(opts.Action)
	if opts.Source == "" {
		opts.Source = "manual"
	}
	if opts.Severity == "" {
		opts.Severity = "medium"
	}
	if opts.Action == "" {
		opts.Action = "challenge"
	}
	if !opts.Enabled {
		opts.Enabled = true
	}
	if len(contents) > 16<<20 {
		return nil, fmt.Errorf("threat intelligence feed exceeds 16 MiB")
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "plain"
	}
	var (
		items []config.ThreatIntelConfig
		err   error
	)
	switch format {
	case "plain", "txt", "text", "ip", "cidr", "feed":
		items, err = parsePlain(contents, opts)
	case "csv":
		items, err = parseCSV(contents, opts)
	case "json", "misp", "threatbook":
		items, err = parseJSON(contents, opts)
	case "stix", "stix2", "stix2.1":
		items, err = parseSTIX(contents, opts)
	default:
		return nil, fmt.Errorf("unsupported threat intelligence format %q", format)
	}
	if err != nil {
		return nil, err
	}
	if len(items) > 100000 {
		return nil, fmt.Errorf("threat intelligence feed exceeds 100000 indicators")
	}
	for idx := range items {
		if strings.TrimSpace(items[idx].Source) == "" && requestedSource != "" {
			items[idx].Source = opts.Source
		}
		// A caller-supplied action is an upper bound. Feed metadata remains
		// authoritative when no explicit bound was requested.
		if requestedAction != "" && actionPriority(items[idx].Action) > actionPriority(opts.Action) {
			items[idx].Action = opts.Action
		}
	}
	return dedupeThreatIntel(items), nil
}

func intelDedupeKey(item config.ThreatIntelConfig) string {
	typ := strings.ToLower(strings.TrimSpace(item.Type))
	if typ == "" {
		typ = "ip"
	}
	return typ + ":" + strings.ToLower(strings.TrimSpace(item.Value))
}

func MergeThreatIntel(existing, imported []config.ThreatIntelConfig) []config.ThreatIntelConfig {
	merged := make([]config.ThreatIntelConfig, 0, len(existing)+len(imported))
	now := time.Now()
	seen := map[string]int{}
	for _, item := range existing {
		if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(now) {
			continue
		}
		canonical, ok := canonicalizeThreatIntel(item)
		if !ok {
			continue
		}
		key := intelDedupeKey(canonical)
		if idx, exists := seen[key]; exists {
			if sourceTrust(canonical.Source) > sourceTrust(merged[idx].Source) {
				merged[idx] = canonical
			}
			continue
		}
		seen[key] = len(merged)
		merged = append(merged, canonical)
	}
	for _, item := range imported {
		if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(now) {
			continue
		}
		item, ok := canonicalizeThreatIntel(item)
		if !ok {
			continue
		}
		key := intelDedupeKey(item)
		if idx, ok := seen[key]; ok {
			existing := merged[idx]
			// Untrusted feeds may not replace a trusted indicator. Even a
			// trusted refresh cannot silently escalate an existing action.
			if sourceTrust(item.Source) < sourceTrust(existing.Source) {
				continue
			}
			if actionPriority(item.Action) > actionPriority(existing.Action) {
				item.Action = existing.Action
			}
			merged[idx] = item
			continue
		}
		seen[key] = len(merged)
		merged = append(merged, item)
	}
	return merged
}

func AdoptableIndicators(items []config.ThreatIntelConfig) []config.ThreatIntelConfig {
	out := make([]config.ThreatIntelConfig, 0, len(items))
	for _, item := range items {
		indicator, ok := indicatorFromValue(item.Value, ImportOptions{
			Source:     emptyFallback(item.Source, "lookup"),
			Severity:   item.Severity,
			Action:     item.Action,
			Confidence: item.Confidence,
			Labels:     item.Labels,
			ExpiresAt:  item.ExpiresAt,
			Enabled:    true,
		})
		if !ok {
			continue
		}
		if strings.TrimSpace(item.ID) != "" {
			indicator.ID = item.ID
		}
		out = append(out, indicator)
	}
	return dedupeThreatIntel(out)
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func dedupeThreatIntel(items []config.ThreatIntelConfig) []config.ThreatIntelConfig {
	out := make([]config.ThreatIntelConfig, 0, len(items))
	seen := map[string]int{}
	for _, item := range items {
		canonical, ok := canonicalizeThreatIntel(item)
		if !ok {
			continue
		}
		item = canonical
		key := intelDedupeKey(item)
		if idx, ok := seen[key]; ok {
			existing := out[idx]
			if sourceTrust(item.Source) < sourceTrust(existing.Source) {
				continue
			}
			if actionPriority(item.Action) > actionPriority(existing.Action) {
				item.Action = existing.Action
			}
			out[idx] = item
			continue
		}
		seen[key] = len(out)
		out = append(out, item)
	}
	return out
}

func canonicalizeThreatIntel(item config.ThreatIntelConfig) (config.ThreatIntelConfig, bool) {
	typ, value, ok := CanonicalIndicator(item.Type, item.Value)
	if !ok {
		return config.ThreatIntelConfig{}, false
	}
	item.Type = typ
	item.Value = value
	return item, true
}

func parsePlain(contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	var out []config.ThreatIntelConfig
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(strings.Split(line, "#")[0])
		if len(fields) == 0 {
			continue
		}
		if indicator, ok := indicatorFromValue(fields[0], opts); ok {
			out = append(out, indicator)
		}
	}
	return out, nil
}

func parseCSV(contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	reader := csv.NewReader(bytes.NewReader(contents))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := map[string]int{}
	start := 0
	for idx, col := range records[0] {
		header[strings.ToLower(strings.TrimSpace(col))] = idx
	}
	if hasAny(header, "ip", "cidr", "value", "indicator", "ioc") {
		start = 1
	}
	var out []config.ThreatIntelConfig
	for _, row := range records[start:] {
		value := firstCSV(row, header, "ip", "cidr", "value", "indicator", "ioc")
		if value == "" && len(row) > 0 {
			value = row[0]
		}
		rowOpts := opts
		if severity := firstCSV(row, header, "severity", "risk", "level"); severity != "" {
			rowOpts.Severity = severity
		}
		if source := firstCSV(row, header, "source", "provider"); source != "" {
			rowOpts.Source = source
		}
		if action := firstCSV(row, header, "action"); action != "" {
			rowOpts.Action = action
		}
		if confidence := firstCSV(row, header, "confidence", "score", "confidence_score"); confidence != "" {
			rowOpts.Confidence = parseConfidence(confidence)
		}
		if labels := firstCSV(row, header, "labels", "tags", "type"); labels != "" {
			rowOpts.Labels = splitLabels(labels)
		}
		if indicator, ok := indicatorFromValue(value, rowOpts); ok {
			out = append(out, indicator)
		}
	}
	return out, nil
}

const maxJSONWalkDepth = 64

func parseJSON(contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	var raw any
	if err := json.Unmarshal(contents, &raw); err != nil {
		return nil, err
	}
	var out []config.ThreatIntelConfig
	walkJSON(raw, opts, &out, 0)
	return out, nil
}

func parseSTIX(contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	indicators, err := parseJSON(contents, opts)
	if err != nil {
		return nil, err
	}
	if len(indicators) > 0 {
		return indicators, nil
	}
	return parseSTIXPatterns(string(contents), opts), nil
}

func walkJSON(raw any, opts ImportOptions, out *[]config.ThreatIntelConfig, depth int) {
	if depth > maxJSONWalkDepth {
		return
	}
	switch value := raw.(type) {
	case []any:
		for _, item := range value {
			walkJSON(item, opts, out, depth+1)
		}
	case map[string]any:
		rowOpts := optionsFromMap(value, opts)
		for key, child := range value {
			keyOpts := rowOpts
			if childMap, ok := child.(map[string]any); ok {
				keyOpts = optionsFromMap(childMap, keyOpts)
			}
			if indicator, ok := indicatorFromValue(key, keyOpts); ok && shouldImportJSONKeyIndicator(child) {
				*out = append(*out, indicator)
			}
		}
		for _, key := range []string{"value", "ip", "ip_address", "ipAddress", "ip_addr", "ipAddr", "ipAddressV4", "ipAddressV6", "address", "cidr", "indicator", "ioc", "resource"} {
			if rawValue := stringField(value, key); rawValue != "" {
				if indicator, ok := indicatorFromValue(rawValue, rowOpts); ok && shouldImportJSONObjectIndicator(value) {
					if typ := stringField(value, "type"); typ != "" {
						if t, v, valid := CanonicalIndicator(typ, rawValue); valid {
							indicator.Type = t
							indicator.Value = v
						}
					}
					*out = append(*out, indicator)
				}
			}
		}
		if pattern := stringField(value, "pattern"); pattern != "" {
			*out = append(*out, parseSTIXPatterns(pattern, rowOpts)...)
		}
		for _, key := range []string{"objects", "Objects", "object", "Object", "indicators", "Indicators", "items", "Items", "data", "Data", "response", "Response", "threat_intel", "threatIntel", "attributes", "Attributes", "attribute", "Attribute", "Event", "event", "observable", "observables", "Observable", "Observables", "pulse_info", "pulseInfo", "pulses", "Pulses", "Tag", "tags"} {
			if child, ok := value[key]; ok {
				walkJSON(child, rowOpts, out, depth+1)
			}
		}
	case string:
		if indicator, ok := indicatorFromValue(value, opts); ok {
			*out = append(*out, indicator)
		}
	}
}

var stixAddrPattern = regexp.MustCompile(`(?i)(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes[.'"A-Za-z0-9-]*|autonomous-system:number|network-traffic:extensions[.'"A-Za-z0-9_-]*)\s+(?:=|ISSUBSET|ISSUPERSET)\s+'?([^'\]\s]+)'?`)

func parseSTIXPatterns(raw string, opts ImportOptions) []config.ThreatIntelConfig {
	var out []config.ThreatIntelConfig
	for _, match := range stixAddrPattern.FindAllStringSubmatch(raw, -1) {
		if len(match) < 3 {
			continue
		}
		typ := ""
		field := strings.ToLower(match[1])
		switch {
		case strings.Contains(field, "ipv4-addr"), strings.Contains(field, "ipv6-addr"):
			typ = "ip"
		case strings.Contains(field, "domain-name"):
			typ = "domain"
		case strings.Contains(field, "url"):
			typ = "url"
		case strings.Contains(field, "autonomous-system"):
			typ = "asn"
		case strings.Contains(field, "md5"):
			typ = "md5"
		case strings.Contains(field, "sha-256"), strings.Contains(field, "sha256"):
			typ = "sha256"
		case strings.Contains(field, "ja3"):
			typ = "ja3"
		case strings.Contains(field, "ja4"):
			typ = "ja4"
		}
		if indicator, ok := indicatorFromTypedValue(typ, match[2], opts); ok {
			out = append(out, indicator)
		}
	}
	return out
}

func indicatorFromTypedValue(typ, value string, opts ImportOptions) (config.ThreatIntelConfig, bool) {
	if typ == "" {
		return indicatorFromValue(value, opts)
	}
	canonicalType, canonical, ok := CanonicalIndicator(typ, value)
	if !ok {
		return config.ThreatIntelConfig{}, false
	}
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(opts.Source+":"+canonicalType+":"+canonical)).String()
	return config.ThreatIntelConfig{
		ID:         "intel-" + id,
		Value:      canonical,
		Type:       canonicalType,
		Severity:   normalizeSeverity(opts.Severity),
		Source:     opts.Source,
		Labels:     append([]string(nil), opts.Labels...),
		Action:     normalizeAction(opts.Action),
		Confidence: normalizeConfidenceValue(opts.Confidence),
		ExpiresAt:  opts.ExpiresAt,
		Enabled:    opts.Enabled,
	}, true
}

func indicatorFromValue(value string, opts ImportOptions) (config.ThreatIntelConfig, bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return config.ThreatIntelConfig{}, false
	}
	typ, canonical, ok := CanonicalIndicator("", value)
	if !ok {
		return config.ThreatIntelConfig{}, false
	}
	value = canonical

	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(opts.Source+":"+value)).String()
	return config.ThreatIntelConfig{
		ID:         "intel-" + id,
		Value:      value,
		Type:       typ,
		Severity:   normalizeSeverity(opts.Severity),
		Source:     opts.Source,
		Labels:     append([]string(nil), opts.Labels...),
		Action:     normalizeAction(opts.Action),
		Confidence: normalizeConfidenceValue(opts.Confidence),
		ExpiresAt:  opts.ExpiresAt,
		Enabled:    opts.Enabled,
	}, true
}

func firstCSV(row []string, header map[string]int, keys ...string) string {
	for _, key := range keys {
		if idx, ok := header[key]; ok && idx >= 0 && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
	}
	return ""
}

func hasAny(header map[string]int, keys ...string) bool {
	for _, key := range keys {
		if _, ok := header[key]; ok {
			return true
		}
	}
	return false
}

func stringField(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := value[key]; ok {
			switch typed := raw.(type) {
			case string:
				return strings.TrimSpace(typed)
			case fmt.Stringer:
				return strings.TrimSpace(typed.String())
			}
		}
	}
	return ""
}

func labelsField(value map[string]any) []string {
	for _, key := range []string{"labels", "tags", "Tag", "judgments", "threat_types", "threatTypes", "intel_types", "intelTypes", "malware_families", "malwareFamilies"} {
		raw, ok := value[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case string:
			if labels := splitLabels(typed); len(labels) > 0 {
				return labels
			}
		case []any:
			var out []string
			for _, item := range typed {
				if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
					out = append(out, strings.TrimSpace(text))
					continue
				}
				if child, ok := item.(map[string]any); ok {
					if name := stringField(child, "name", "value", "tag"); name != "" {
						out = append(out, name)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func nestedLabels(value any) []string {
	switch typed := value.(type) {
	case []any:
		var out []string
		for _, item := range typed {
			out = append(out, nestedLabels(item)...)
		}
		return out
	case map[string]any:
		if labels := labelsField(typed); len(labels) > 0 {
			return labels
		}
		var out []string
		for _, child := range typed {
			out = append(out, nestedLabels(child)...)
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	default:
		return nil
	}
}

func shouldImportJSONObjectIndicator(value map[string]any) bool {
	if mapHasThreatSignal(value) {
		return true
	}
	if mapHasExplicitNonThreatSignal(value) || mapHasThreatTelemetry(value) {
		return false
	}
	return true
}

func shouldImportJSONKeyIndicator(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return textLooksThreatening(typed)
	case float64:
		return typed > 0
	case int:
		return typed > 0
	case json.Number:
		number, err := typed.Float64()
		return err == nil && number > 0
	case []any:
		for _, item := range typed {
			if shouldImportJSONKeyIndicator(item) {
				return true
			}
		}
		return false
	case map[string]any:
		return mapHasThreatSignal(typed)
	default:
		return true
	}
}

func mapHasThreatSignal(value map[string]any) bool {
	if labels := labelsField(value); len(labels) > 0 {
		return true
	}
	if confidence := numericField(value, "confidence", "score", "confidence_score", "risk_score", "riskScore", "threat_score", "threatScore", "abuseConfidenceScore", "abuse_confidence_score"); confidence > 0 {
		return true
	}
	if countField(value, "totalReports", "total_reports", "pulse_count", "pulseCount", "count") > 0 {
		return true
	}
	for _, key := range []string{"severity", "risk", "level", "verdict", "status", "category", "action"} {
		if textLooksThreatening(stringField(value, key)) {
			return true
		}
	}
	if nested, ok := value["intelligences"]; ok && nestedIntelHasThreatSignal(nested) {
		return true
	}
	for _, key := range []string{"pulse_info", "pulseInfo"} {
		if nested, ok := value[key]; ok && nestedIntelHasThreatSignal(nested) {
			return true
		}
	}
	for _, key := range []string{"malicious", "suspicious", "is_malicious", "blacklisted", "listed"} {
		if raw, ok := value[key]; ok && shouldImportJSONKeyIndicator(raw) {
			return true
		}
	}
	return false
}

func nestedIntelHasThreatSignal(value any) bool {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if nestedIntelHasThreatSignal(item) {
				return true
			}
		}
		return false
	case map[string]any:
		if labels := labelsField(typed); len(labels) > 0 {
			return true
		}
		if confidence := numericField(typed, "confidence", "score", "confidence_score", "risk_score", "riskScore", "threat_score", "threatScore", "abuseConfidenceScore", "abuse_confidence_score"); confidence > 0 {
			return true
		}
		if countField(typed, "totalReports", "total_reports", "pulse_count", "pulseCount", "count") > 0 {
			return true
		}
		for _, key := range []string{"severity", "risk", "level", "verdict", "status", "category", "action", "type"} {
			if textLooksThreatening(stringField(typed, key)) {
				return true
			}
		}
		for _, child := range typed {
			if nestedIntelHasThreatSignal(child) {
				return true
			}
		}
		return false
	case string:
		return textLooksThreatening(typed)
	case float64:
		return typed > 0
	case int:
		return typed > 0
	case bool:
		return typed
	default:
		return false
	}
}

func mapHasExplicitNonThreatSignal(value map[string]any) bool {
	for _, key := range []string{"severity", "risk", "level", "verdict", "status", "action"} {
		if raw := stringField(value, key); raw != "" && !textLooksThreatening(raw) {
			return true
		}
	}
	for _, key := range []string{"malicious", "suspicious", "is_malicious", "blacklisted", "listed", "isWhitelisted", "is_whitelisted"} {
		if raw, ok := value[key]; ok {
			if boolValue, ok := raw.(bool); ok && !boolValue {
				return true
			}
		}
	}
	return false
}

func mapHasThreatTelemetry(value map[string]any) bool {
	for _, key := range []string{"confidence", "score", "confidence_score", "risk_score", "riskScore", "threat_score", "threatScore", "abuseConfidenceScore", "abuse_confidence_score", "totalReports", "total_reports", "pulse_count", "pulseCount", "reputation"} {
		if _, ok := value[key]; ok {
			return true
		}
	}
	for _, key := range []string{"pulse_info", "pulseInfo", "intelligences"} {
		if _, ok := value[key]; ok {
			return true
		}
	}
	return false
}

func textLooksThreatening(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	switch value {
	case "0", "false", "no", "none", "null", "unknown", "clean", "benign", "safe", "normal", "whitelisted", "allow", "allowed":
		return false
	default:
		return true
	}
}

func optionsFromMap(value map[string]any, opts ImportOptions) ImportOptions {
	rowOpts := opts
	if source := stringField(value, "source", "provider", "feed", "feed_name"); source != "" {
		rowOpts.Source = source
	}
	if severity := stringField(value, "severity", "risk", "level", "verdict"); severity != "" {
		rowOpts.Severity = normalizeSeverity(severity)
	}
	if action := stringField(value, "action"); action != "" {
		rowOpts.Action = action
	}
	if confidence := numericField(value, "confidence", "score", "confidence_score", "risk_score", "riskScore", "threat_score", "threatScore", "abuseConfidenceScore", "abuse_confidence_score"); confidence > 0 {
		rowOpts.Confidence = confidence
	}
	if labels := labelsField(value); len(labels) > 0 {
		rowOpts.Labels = labels
	}
	if nested, ok := value["intelligences"].(map[string]any); ok {
		applyNestedIntelOptions(nested, &rowOpts)
	}
	if nested, ok := value["pulse_info"].(map[string]any); ok {
		applyNestedIntelOptions(map[string]any{"AlienVault OTX": []any{nested}}, &rowOpts)
	}
	if nested, ok := value["pulseInfo"].(map[string]any); ok {
		applyNestedIntelOptions(map[string]any{"AlienVault OTX": []any{nested}}, &rowOpts)
	}
	return rowOpts
}

func applyNestedIntelOptions(value map[string]any, opts *ImportOptions) {
	for source, raw := range value {
		switch typed := raw.(type) {
		case []any:
			for _, item := range typed {
				if child, ok := item.(map[string]any); ok {
					if childSource := stringField(child, "source", "provider"); childSource != "" {
						opts.Source = childSource
					} else if strings.TrimSpace(source) != "" {
						opts.Source = source
					}
					if confidence := numericField(child, "confidence", "score", "confidence_score", "risk_score", "riskScore", "threat_score", "threatScore", "abuseConfidenceScore", "abuse_confidence_score"); confidence > opts.Confidence {
						opts.Confidence = confidence
					}
					if labels := labelsField(child); len(labels) > 0 {
						opts.Labels = labels
					} else if labels := nestedLabels(child); len(labels) > 0 {
						opts.Labels = labels
					}
				}
			}
		case map[string]any:
			applyNestedIntelOptions(map[string]any{source: []any{typed}}, opts)
		}
	}
}

func numericField(value map[string]any, keys ...string) float64 {
	for _, key := range keys {
		raw, ok := value[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case float64:
			return normalizeConfidenceValue(typed)
		case int:
			return normalizeConfidenceValue(float64(typed))
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				return normalizeConfidenceValue(parsed)
			}
		case string:
			return parseConfidence(typed)
		}
	}
	return 0
}

func countField(value map[string]any, keys ...string) float64 {
	for _, key := range keys {
		raw, ok := value[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case float64:
			return typed
		case int:
			return float64(typed)
		case json.Number:
			if parsed, err := typed.Float64(); err == nil {
				return parsed
			}
		case string:
			var parsed float64
			if _, err := fmt.Sscanf(strings.TrimSpace(typed), "%f", &parsed); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func parseConfidence(value string) float64 {
	value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	if value == "" {
		return 0
	}
	var parsed float64
	if _, err := fmt.Sscanf(value, "%f", &parsed); err != nil {
		return 0
	}
	return normalizeConfidenceValue(parsed)
}

func splitLabels(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '|' || r == ';'
	})
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "malicious", "dangerous":
		return "critical"
	case "high", "suspicious":
		return "high"
	case "low", "benign", "whitelist":
		return "low"
	default:
		return "medium"
	}
}

func normalizeAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "block", "challenge", "log":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "challenge"
	}
}

func normalizeConfidenceValue(confidence float64) float64 {
	if confidence > 1 {
		confidence = confidence / 100
	}
	if confidence < 0 {
		return 0
	}
	if confidence > 1 {
		return 1
	}
	return confidence
}

func actionPriority(value string) int {
	switch normalizeAction(value) {
	case "block":
		return 3
	case "challenge":
		return 2
	case "allow":
		return 4
	default:
		return 1
	}
}
func sourceTrust(source string) int {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "manual" {
		return 3
	}
	if strings.HasPrefix(source, "verified:") {
		return 2
	}
	return 1
}

// CanonicalIndicator validates the supported IOC matrix. Unsupported values
// cannot become active indicators merely because a feed labels them trusted.
func CanonicalIndicator(typ, value string) (string, string, bool) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	value = strings.TrimSpace(value)
	switch typ {
	case "ipv4-addr", "ipv6-addr", "ip-src", "ip-dst", "cidr":
		typ = "ip"
	case "domain-name", "hostname":
		typ = "domain"
	case "sha-256", "sha256", "file:hashes.sha-256", "file:hashes.'sha-256'", "file:hashes.sha256", "file:hashes.'sha256'":
		typ = "sha256"
	case "md5", "file:hashes.md5", "file:hashes.'md5'":
		typ = "md5"
	case "autonomous-system":
		typ = "asn"
	}
	for _, name := range []string{"domain", "url", "sha256", "md5", "asn", "ja3", "ja4"} {
		if strings.HasPrefix(strings.ToLower(value), name+":") {
			typ = name
			value = value[len(name)+1:]
			break
		}
	}
	if typ == "" {
		switch {
		case net.ParseIP(value) != nil:
			typ = "ip"
		case strings.Contains(value, "/") && !strings.Contains(value, "://"):
			typ = "ip"
		case strings.Contains(value, "://"):
			typ = "url"
		case strings.HasPrefix(strings.ToUpper(value), "AS"):
			typ = "asn"
		case len(value) == 64:
			typ = "sha256"
		case len(value) == 32:
			typ = "md5"
		case strings.Contains(value, "."):
			typ = "domain"
		default:
			return "", "", false
		}
	}
	switch typ {
	case "ip":
		if ip := net.ParseIP(value); ip != nil {
			if ip.IsUnspecified() || ip.IsMulticast() {
				return "", "", false
			}
			return typ, ip.String(), true
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return "", "", false
		}
		ones, bits := network.Mask.Size()
		if (bits == 32 && ones < 8) || (bits == 128 && ones < 16) {
			return "", "", false
		}
		// Threat feeds are public-source indicators. Never let an import turn
		// RFC1918, loopback, or link-local space into a site-wide deny rule.
		if network.IP.IsPrivate() || network.IP.IsLoopback() || network.IP.IsLinkLocalUnicast() || network.IP.IsUnspecified() || network.IP.IsMulticast() {
			return "", "", false
		}
		return typ, network.String(), true
	case "domain":
		domain, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(value, ".")))
		if err != nil || len(domain) > 253 || !strings.Contains(domain, ".") {
			return "", "", false
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", "", false
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", "", false
				}
			}
		}
		return typ, domain, true
	case "url":
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			return "", "", false
		}
		_, host, ok := CanonicalIndicator("domain", u.Hostname())
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			host = ip.String()
			ok = true
		}
		if !ok {
			return "", "", false
		}
		if u.Port() != "" {
			host = net.JoinHostPort(host, u.Port())
		}
		u.Host = host
		u.Fragment = ""
		return typ, u.String(), true
	case "sha256", "md5", "ja3":
		want := 32
		if typ == "sha256" {
			want = 64
		}
		if len(value) != want {
			return "", "", false
		}
		if _, err := hex.DecodeString(value); err != nil {
			return "", "", false
		}
		return typ, strings.ToLower(value), true
	case "asn":
		value = strings.TrimPrefix(strings.ToUpper(value), "AS")
		n, err := strconv.ParseUint(value, 10, 32)
		return typ, strconv.FormatUint(n, 10), err == nil && n > 0
	case "ja4":
		if regexp.MustCompile(`^[tq][a-z0-9]{9}_[a-f0-9]{12}_[a-f0-9]{12}$`).MatchString(value) {
			return typ, value, true
		}
	}
	return "", "", false
}
