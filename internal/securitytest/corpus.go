package securitytest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Case struct {
	Name         string            `json:"name"`
	SourceFamily string            `json:"source_family"`
	Label        string            `json:"label"`
	Category     string            `json:"category,omitempty"`
	Method       string            `json:"method"`
	Target       string            `json:"target"`
	ContentType  string            `json:"content_type,omitempty"`
	Body         string            `json:"body,omitempty"`
	Header       map[string]string `json:"header,omitempty"`
	Rationale    string            `json:"rationale,omitempty"`
}

func (tc *Case) UnmarshalJSON(data []byte) error {
	// Accept both snake_case and PascalCase keys used across curated corpora.
	type rawCase struct {
		Name              string            `json:"name"`
		NameCamel         string            `json:"Name"`
		SourceFamily      string            `json:"source_family"`
		SourceFamilyCamel string            `json:"SourceFamily"`
		Label             string            `json:"label"`
		LabelCamel        string            `json:"Label"`
		Category          string            `json:"category,omitempty"`
		CategoryCamel     string            `json:"Category,omitempty"`
		Method            string            `json:"method"`
		MethodCamel       string            `json:"Method"`
		Target            string            `json:"target"`
		TargetCamel       string            `json:"Target"`
		ContentType       string            `json:"content_type,omitempty"`
		ContentTypeCamel  string            `json:"ContentType,omitempty"`
		Body              string            `json:"body,omitempty"`
		BodyCamel         string            `json:"Body,omitempty"`
		Header            map[string]string `json:"header,omitempty"`
		HeaderCamel       map[string]string `json:"Header,omitempty"`
		Rationale         string            `json:"rationale,omitempty"`
		RationaleCamel    string            `json:"Rationale,omitempty"`
	}
	var raw rawCase
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	tc.Name = firstNonEmpty(raw.Name, raw.NameCamel)
	tc.SourceFamily = firstNonEmpty(raw.SourceFamily, raw.SourceFamilyCamel)
	tc.Label = strings.ToLower(firstNonEmpty(raw.Label, raw.LabelCamel))
	tc.Category = strings.ToLower(firstNonEmpty(raw.Category, raw.CategoryCamel))
	tc.Method = firstNonEmpty(raw.Method, raw.MethodCamel)
	tc.Target = firstNonEmpty(raw.Target, raw.TargetCamel)
	tc.ContentType = firstNonEmpty(raw.ContentType, raw.ContentTypeCamel)
	tc.Body = firstNonEmpty(raw.Body, raw.BodyCamel)
	tc.Header = raw.Header
	if len(tc.Header) == 0 {
		tc.Header = raw.HeaderCamel
	}
	tc.Rationale = firstNonEmpty(raw.Rationale, raw.RationaleCamel)
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// StrictCategory identifies curated corpora whose labels are expected to match the
// detector category exactly. Bulk-imported public payload collections often contain
// fused vectors or source labels that describe the repository rather than the
// dominant exploit primitive, so those samples are evaluated as detection coverage.
func StrictCategory(source string) bool {
	s := strings.ToLower(strings.TrimSpace(source))
	if strings.HasPrefix(s, "hc-xxe") {
		return false
	}
	return strings.HasPrefix(s, "hc-") ||
		strings.HasPrefix(s, "handcrafted") ||
		strings.HasPrefix(s, "classic-") ||
		strings.HasPrefix(s, "curated-") ||
		strings.HasPrefix(s, "bccc-") ||
		strings.HasPrefix(s, "crs-") ||
		strings.HasPrefix(s, "sqlmap-") ||
		strings.HasPrefix(s, "portswigger-")
}

func LoadJSONL(r io.Reader) ([]Case, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var cases []Case
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var tc Case
		if err := json.Unmarshal(line, &tc); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := ValidateCase(tc); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		cases = append(cases, tc)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cases, nil
}

func ValidateCase(tc Case) error {
	if strings.TrimSpace(tc.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if tc.Label != "attack" && tc.Label != "benign" {
		return fmt.Errorf("unsupported label %q", tc.Label)
	}
	if tc.Label == "attack" && strings.TrimSpace(tc.Category) == "" {
		return fmt.Errorf("attack case %q requires category", tc.Name)
	}
	if strings.TrimSpace(tc.Method) == "" {
		return fmt.Errorf("case %q requires method", tc.Name)
	}
	if strings.TrimSpace(tc.Target) == "" {
		return fmt.Errorf("case %q requires target", tc.Name)
	}
	return nil
}
