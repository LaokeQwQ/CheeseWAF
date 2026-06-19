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
	type rawCase struct {
		Name              string            `json:"name"`
		SourceFamily      string            `json:"source_family"`
		SourceFamilyCamel string            `json:"SourceFamily"`
		Label             string            `json:"label"`
		Category          string            `json:"category,omitempty"`
		Method            string            `json:"method"`
		Target            string            `json:"target"`
		ContentType       string            `json:"content_type,omitempty"`
		ContentTypeCamel  string            `json:"ContentType,omitempty"`
		Body              string            `json:"body,omitempty"`
		Header            map[string]string `json:"header,omitempty"`
		Rationale         string            `json:"rationale,omitempty"`
	}
	var raw rawCase
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	tc.Name = raw.Name
	tc.SourceFamily = raw.SourceFamily
	if tc.SourceFamily == "" {
		tc.SourceFamily = raw.SourceFamilyCamel
	}
	tc.Label = raw.Label
	tc.Category = raw.Category
	tc.Method = raw.Method
	tc.Target = raw.Target
	tc.ContentType = raw.ContentType
	if tc.ContentType == "" {
		tc.ContentType = raw.ContentTypeCamel
	}
	tc.Body = raw.Body
	tc.Header = raw.Header
	tc.Rationale = raw.Rationale
	return nil
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
