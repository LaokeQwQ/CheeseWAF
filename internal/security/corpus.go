package security

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"strconv"
	"strings"
)

const defaultCorpusMaxLineBytes = 2 * 1024 * 1024

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

func LoadJSONL(r io.Reader) ([]Case, error) { return LoadJSONLFiltered(r, 1, 0) }

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

// ShardIndexFor returns a stable 0..shards-1 shard index for a corpus case
// based on its name. The same name always maps to the same shard so shards can
// be run in parallel processes and merged deterministically.
func ShardIndexFor(name string, shards int) int {
	if shards <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(name))))
	return int(h.Sum32() % uint32(shards))
}

// ShardIndexForRaw returns a stable 0..shards-1 shard index for a raw JSONL
// line. Unlike ShardIndexFor it does not require JSON parsing, so streaming
// loaders can skip non-shard lines before allocating the Case struct.
func ShardIndexForRaw(line []byte, shards int) int {
	if shards <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write(bytes.TrimSpace(line))
	return int(h.Sum32() % uint32(shards))
}

// JSONLStats describes a bounded JSONL pass. TotalCases and SelectedCases count
// validated corpus cases; overlong physical records are skipped before parsing.
type JSONLStats struct {
	NonEmptyLines   int
	TotalCases      int
	SelectedCases   int
	SkippedOverlong int
}

// ValidateShard rejects invalid shard ranges instead of quietly filtering every
// case. Callers can use the same contract in streaming and slice-backed modes.
func ValidateShard(shards, shard int) error {
	if shards < 1 {
		return fmt.Errorf("--shards must be at least 1")
	}
	if shard < 0 || shard >= shards {
		return fmt.Errorf("--shard must be between 0 and %d for --shards=%d", shards-1, shards)
	}
	return nil
}

// ForEachJSONLRaw reads bounded raw JSONL records. The callback receives every
// non-empty, non-overlong line together with its deterministic raw-line shard
// membership. This lets non-Case formats share the same limit and sharding
// contract as the primary corpus loader.
func ForEachJSONLRaw(r io.Reader, shards, shard int, fn func(line []byte, lineNo int, selected bool) error) (JSONLStats, error) {
	if err := ValidateShard(shards, shard); err != nil {
		return JSONLStats{}, err
	}
	reader := bufio.NewReaderSize(r, 64*1024)
	maxLine := corpusMaxLineBytes()
	stats := JSONLStats{}
	lineNo := 0
	for {
		rawLine, overlong, readErr := readBoundedJSONLLine(reader, maxLine)
		if len(rawLine) > 0 || readErr == nil {
			lineNo++
		}
		line := bytes.TrimSpace(rawLine)
		if len(line) > 0 {
			stats.NonEmptyLines++
			if overlong || len(line) > maxLine {
				stats.SkippedOverlong++
			} else {
				selected := shards == 1 || ShardIndexForRaw(line, shards) == shard
				if fn != nil {
					if err := fn(line, lineNo, selected); err != nil {
						return stats, err
					}
				}
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return stats, readErr
			}
			return stats, nil
		}
	}
}

// ForEachJSONLWithStats streams validated corpus cases. Every bounded record is
// parsed before shard selection so all shards agree on corpus validity, while
// only selected cases reach fn.
func ForEachJSONLWithStats(r io.Reader, shards, shard int, fn func(Case) error) (JSONLStats, error) {
	totalCases := 0
	selectedCases := 0
	stats, err := ForEachJSONLRaw(r, shards, shard, func(line []byte, lineNo int, selected bool) error {
		var tc Case
		if err := json.Unmarshal(line, &tc); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := ValidateCase(tc); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		totalCases++
		if !selected {
			return nil
		}
		selectedCases++
		if fn != nil {
			return fn(tc)
		}
		return nil
	})
	stats.TotalCases = totalCases
	stats.SelectedCases = selectedCases
	if err == nil && stats.SkippedOverlong > 0 {
		fmt.Fprintf(os.Stderr, "corpus: skipped %d over-long line(s)\n", stats.SkippedOverlong)
	}
	return stats, err
}

// ForEachJSONL streams validated corpus cases while discarding overlong records
// without materializing a complete line. Use ForEachJSONLWithStats when the
// caller needs total and selected case counts.
func ForEachJSONL(r io.Reader, shards, shard int, fn func(Case) error) error {
	_, err := ForEachJSONLWithStats(r, shards, shard, fn)
	return err
}

// LoadJSONLFiltered is a convenience wrapper over ForEachJSONL for callers that
// still need a slice (CLI, tests). It keeps shard semantics identical to the
// streaming path.
func LoadJSONLFiltered(r io.Reader, shards, shard int) ([]Case, error) {
	var cases []Case
	_, err := ForEachJSONLWithStats(r, shards, shard, func(tc Case) error {
		cases = append(cases, tc)
		return nil
	})
	return cases, err
}

func corpusMaxLineBytes() int {
	maxLine := defaultCorpusMaxLineBytes
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_CORPUS_MAX_LINE_BYTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < maxLine {
			maxLine = n
		}
	}
	return maxLine
}

// readBoundedJSONLLine reads through one physical line while retaining no more
// than maxLine bytes plus CRLF tolerance. It returns io.EOF with the final
// unterminated line, if any.
func readBoundedJSONLLine(reader *bufio.Reader, maxLine int) ([]byte, bool, error) {
	if reader == nil {
		return nil, false, io.EOF
	}
	if maxLine < 1 {
		maxLine = 1
	}
	const newlineAllowance = 2
	limit := maxLine + newlineAllowance
	line := make([]byte, 0, minJSONLBufferCapacity(limit))
	overlong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 && !overlong {
			remaining := limit - len(line)
			if remaining <= 0 {
				overlong = true
			} else if len(fragment) > remaining {
				line = append(line, fragment[:remaining]...)
				overlong = true
			} else {
				line = append(line, fragment...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) > maxLine {
			overlong = true
		}
		return trimmed, overlong, err
	}
}

func minJSONLBufferCapacity(limit int) int {
	if limit < 64*1024 {
		return limit
	}
	return 64 * 1024
}

// FilterShard returns only the cases belonging to the requested shard.
// shards<=1 returns the input unchanged for backwards compatibility.
func FilterShard(cases []Case, shards, shard int) []Case {
	if shards <= 1 {
		return cases
	}
	if shard < 0 || shard >= shards {
		return []Case{}
	}
	out := make([]Case, 0, len(cases)/shards+16)
	for _, tc := range cases {
		if ShardIndexFor(tc.Name, shards) == shard {
			out = append(out, tc)
		}
	}
	return out
}
