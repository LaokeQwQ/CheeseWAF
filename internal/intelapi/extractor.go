package intelapi

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

// AdvisoryExtractor is a deterministic, offline extractor for vulnerability
// advisories. It recognizes CVE identifiers and the PHP2Shell-shaped request
// and response evidence the rule compiler can express narrowly. It never calls
// a model, a tool, or the network.
type AdvisoryExtractor struct{}

var _ intel.Extractor = AdvisoryExtractor{}

// NewAdvisoryExtractor returns the deterministic advisory extractor.
func NewAdvisoryExtractor() AdvisoryExtractor {
	return AdvisoryExtractor{}
}

var (
	extractCVEPattern      = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)
	extractMethodPath      = regexp.MustCompile(`(?i)\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/[A-Za-z0-9._~%/\-]{1,511})`)
	extractURLPath         = regexp.MustCompile(`https?://[^/\s"'<>]+(/[A-Za-z0-9._~%/\-]{0,510})`)
	extractNestedArray     = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]{0,63})((?:\[[a-z0-9_]{0,32}\]){3,})`)
	extractSerializedPHP   = regexp.MustCompile(`O:[0-9]{1,4}:"[A-Za-z_\\][A-Za-z0-9_\\]{0,64}"`)
	extractStatusCode      = regexp.MustCompile(`(?i)\b(?:HTTP/[0-9.]+|status(?:\s+code)?)\s*:?\s*([1-5][0-9]{2})\b`)
	extractOversizedCookie = regexp.MustCompile(`(?i)\bPHPSESSID=([A-Za-z0-9._%\-]{200,})`)
)

// Extract implements intel.Extractor. When the document carries no shape that
// maps to a narrow rule it returns intel.ErrNoSafeRule.
func (AdvisoryExtractor) Extract(ctx context.Context, item intel.Item, document intel.Document) (intel.Extraction, error) {
	if err := ctx.Err(); err != nil {
		return intel.Extraction{}, err
	}
	text := document.Title + "\n" + document.Text
	for _, block := range document.CodeBlocks {
		text += "\n" + block
	}
	lower := strings.ToLower(text)

	extraction := intel.Extraction{
		CVEIDs:           extractCVEs(text),
		Products:         cleanHints(item.Products, intel.MaxExtractionProducts),
		AffectedVersions: cleanHints(item.AffectedVersions, intel.MaxExtractionVersions),
		References:       cleanReferences(item.References),
	}

	multipart := strings.Contains(lower, "multipart/form-data")
	uploadProgress := strings.Contains(lower, "php_session_upload_progress") ||
		strings.Contains(lower, "session.upload_progress")
	hasSession := strings.Contains(lower, "phpsessid")
	if uploadProgress {
		extraction.Request.UploadProgress = true
		extraction.Request.SessionParameter = intel.MultipartProgressMarker
	} else if hasSession {
		extraction.Request.SessionParameter = intel.DefaultSessionParameter
	}
	if multipart {
		extraction.Request.ContentType = "multipart/form-data"
	}

	if match := extractNestedArray.FindStringSubmatch(text); match != nil {
		extraction.Request.NestedArrays = true
		extraction.Request.ParameterNames = []string{match[1]}
	}

	markers := make([]string, 0, 3)
	if strings.Contains(lower, "<?php") {
		markers = append(markers, "<?php")
	}
	if strings.Contains(lower, "<?=") {
		markers = append(markers, "<?=")
	}
	if extractSerializedPHP.MatchString(text) {
		markers = append(markers, "serialized")
	}
	extraction.Request.Markers = markers

	if match := extractMethodPath.FindStringSubmatch(text); match != nil {
		if fields := strings.Fields(match[0]); len(fields) > 0 {
			extraction.Request.Method = strings.ToUpper(fields[0])
		}
		extraction.Request.Path = sanitizePath(match[1])
	} else if match := extractURLPath.FindStringSubmatch(text); match != nil {
		extraction.Request.Path = sanitizePath(match[1])
	}

	extraction.Response.StatusCodes = extractStatusCodes(text)
	if strings.Contains(lower, "set-cookie") {
		extraction.Response.HeaderNames = []string{"Set-Cookie"}
	}
	if extractOversizedCookie.MatchString(text) ||
		strings.Contains(lower, "oversized session cookie") ||
		strings.Contains(lower, "large session cookie") ||
		strings.Contains(lower, "session cookie leak") {
		extraction.Response.OversizedSessionCookie = true
	}

	multipartShape := uploadProgress || (multipart && extraction.Request.SessionParameter != "")
	shape := multipartShape || extraction.Request.NestedArrays || len(markers) > 0 || extraction.Response.OversizedSessionCookie
	if !shape {
		return intel.Extraction{}, fmt.Errorf("%w: advisory has no PHP2Shell-shaped request or response evidence", intel.ErrNoSafeRule)
	}

	extraction.Confidence = confidenceFor(extraction)
	if err := intel.ValidateExtraction(extraction); err != nil {
		return intel.Extraction{}, fmt.Errorf("intelapi: invalid extraction: %w", err)
	}
	return extraction, nil
}

func extractCVEs(text string) []string {
	matches := extractCVEPattern.FindAllString(text, intel.MaxExtractionCVEIDs*2)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	cves := make([]string, 0, len(matches))
	for _, match := range matches {
		cve := strings.ToUpper(strings.TrimSpace(match))
		if _, exists := seen[cve]; exists {
			continue
		}
		seen[cve] = struct{}{}
		cves = append(cves, cve)
		if len(cves) == intel.MaxExtractionCVEIDs {
			break
		}
	}
	return cves
}

func extractStatusCodes(text string) []int {
	matches := extractStatusCode.FindAllStringSubmatch(text, intel.MaxExtractionStatusCodes*2)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(matches))
	codes := make([]int, 0, len(matches))
	for _, match := range matches {
		code := 0
		for _, r := range match[1] {
			code = code*10 + int(r-'0')
		}
		if code < 100 || code > 599 {
			continue
		}
		if _, exists := seen[code]; exists {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
		if len(codes) == intel.MaxExtractionStatusCodes {
			break
		}
	}
	return codes
}

func sanitizePath(raw string) string {
	path := strings.TrimSpace(raw)
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		path = path[:cut]
	}
	if len(path) > 512 {
		path = path[:512]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path == "/" {
		return ""
	}
	return path
}

func cleanHints(values []string, max int) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cleaned = append(cleaned, value)
		if len(cleaned) == max {
			break
		}
	}
	return cleaned
}

func cleanReferences(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if err := intel.ValidateReferenceURL(value); err != nil {
			continue
		}
		cleaned = append(cleaned, value)
		if len(cleaned) == intel.MaxExtractionReferences {
			break
		}
	}
	return cleaned
}

func confidenceFor(extraction intel.Extraction) float64 {
	score := 0.40
	if len(extraction.CVEIDs) > 0 {
		score += 0.10
	}
	switch {
	case extraction.Request.UploadProgress:
		score += 0.20
	case extraction.Request.SessionParameter != "":
		score += 0.10
	}
	if extraction.Request.ContentType != "" {
		score += 0.05
	}
	if extraction.Request.NestedArrays {
		score += 0.10
	}
	if len(extraction.Request.Markers) > 0 {
		score += 0.10
	}
	if extraction.Response.OversizedSessionCookie {
		score += 0.15
	}
	if score > 0.95 {
		score = 0.95
	}
	score = math.Round(score*100) / 100
	if score <= 0 {
		score = 0.01
	}
	return score
}
