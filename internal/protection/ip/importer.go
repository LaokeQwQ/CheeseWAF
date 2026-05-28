package ip

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/google/uuid"
)

type ImportOptions struct {
	Source    string
	Severity  string
	Action    string
	Labels    []string
	ExpiresAt time.Time
	Enabled   bool
}

func ParseThreatIntel(format string, contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
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
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "csv":
		return parseCSV(contents, opts)
	case "json", "misp", "threatbook":
		return parseJSON(contents, opts)
	case "stix", "stix2", "stix2.1":
		return parseSTIX(contents, opts)
	default:
		return parsePlain(contents, opts)
	}
}

func MergeThreatIntel(existing, imported []config.ThreatIntelConfig) []config.ThreatIntelConfig {
	merged := append([]config.ThreatIntelConfig(nil), existing...)
	seen := map[string]int{}
	for idx, item := range merged {
		seen[strings.TrimSpace(item.Value)] = idx
	}
	for _, item := range imported {
		value := strings.TrimSpace(item.Value)
		if value == "" {
			continue
		}
		if idx, ok := seen[value]; ok {
			merged[idx] = item
			continue
		}
		seen[value] = len(merged)
		merged = append(merged, item)
	}
	return merged
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
		if labels := firstCSV(row, header, "labels", "tags", "type"); labels != "" {
			rowOpts.Labels = splitLabels(labels)
		}
		if indicator, ok := indicatorFromValue(value, rowOpts); ok {
			out = append(out, indicator)
		}
	}
	return out, nil
}

func parseJSON(contents []byte, opts ImportOptions) ([]config.ThreatIntelConfig, error) {
	var raw any
	if err := json.Unmarshal(contents, &raw); err != nil {
		return nil, err
	}
	var out []config.ThreatIntelConfig
	walkJSON(raw, opts, &out)
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

func walkJSON(raw any, opts ImportOptions, out *[]config.ThreatIntelConfig) {
	switch value := raw.(type) {
	case []any:
		for _, item := range value {
			walkJSON(item, opts, out)
		}
	case map[string]any:
		rowOpts := opts
		if source := stringField(value, "source", "provider"); source != "" {
			rowOpts.Source = source
		}
		if severity := stringField(value, "severity", "risk", "level", "verdict"); severity != "" {
			rowOpts.Severity = normalizeSeverity(severity)
		}
		if action := stringField(value, "action"); action != "" {
			rowOpts.Action = action
		}
		if labels := labelsField(value); len(labels) > 0 {
			rowOpts.Labels = labels
		}
		for key := range value {
			if indicator, ok := indicatorFromValue(key, rowOpts); ok {
				*out = append(*out, indicator)
			}
		}
		for _, key := range []string{"value", "ip", "cidr", "indicator", "ioc", "resource"} {
			if rawValue := stringField(value, key); rawValue != "" {
				if indicator, ok := indicatorFromValue(rawValue, rowOpts); ok {
					*out = append(*out, indicator)
				}
			}
		}
		if pattern := stringField(value, "pattern"); pattern != "" {
			*out = append(*out, parseSTIXPatterns(pattern, rowOpts)...)
		}
		for _, key := range []string{"objects", "indicators", "items", "data", "threat_intel", "attributes"} {
			if child, ok := value[key]; ok {
				walkJSON(child, rowOpts, out)
			}
		}
	case string:
		if indicator, ok := indicatorFromValue(value, opts); ok {
			*out = append(*out, indicator)
		}
	}
}

func parseSTIXPatterns(raw string, opts ImportOptions) []config.ThreatIntelConfig {
	pattern := regexp.MustCompile(`(?i)(ipv4-addr|ipv6-addr):value\s+(?:=|ISSUBSET|ISSUPERSET)\s+'([^']+)'`)
	var out []config.ThreatIntelConfig
	for _, match := range pattern.FindAllStringSubmatch(raw, -1) {
		if len(match) < 3 {
			continue
		}
		if indicator, ok := indicatorFromValue(match[2], opts); ok {
			out = append(out, indicator)
		}
	}
	return out
}

func indicatorFromValue(value string, opts ImportOptions) (config.ThreatIntelConfig, bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return config.ThreatIntelConfig{}, false
	}
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return config.ThreatIntelConfig{}, false
		}
	} else if net.ParseIP(value) == nil {
		return config.ThreatIntelConfig{}, false
	}
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(opts.Source+":"+value)).String()
	return config.ThreatIntelConfig{
		ID:        "intel-" + id,
		Value:     value,
		Type:      "ip",
		Severity:  normalizeSeverity(opts.Severity),
		Source:    opts.Source,
		Labels:    append([]string(nil), opts.Labels...),
		Action:    normalizeAction(opts.Action),
		ExpiresAt: opts.ExpiresAt,
		Enabled:   opts.Enabled,
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
	for _, key := range []string{"labels", "tags", "judgments", "threat_types", "intel_types"} {
		raw, ok := value[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case string:
			return splitLabels(typed)
		case []any:
			var out []string
			for _, item := range typed {
				if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
					out = append(out, strings.TrimSpace(text))
				}
			}
			return out
		}
	}
	return nil
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
