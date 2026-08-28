package apisec

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type ValidationFinding struct {
	SchemaID string `json:"schema_id"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

type Validator struct {
	enabled bool
	schemas []schema
}

type schema struct {
	cfg     config.APIEndpointSchemaConfig
	pattern *regexp.Regexp
}

func NewValidator(cfg config.APIValidationConfig) (*Validator, error) {
	validator := &Validator{enabled: cfg.Enabled}
	for _, item := range cfg.Schemas {
		if !item.Enabled {
			continue
		}
		pattern, err := regexp.Compile(item.PathPattern)
		if err != nil {
			return nil, err
		}
		validator.schemas = append(validator.schemas, schema{cfg: item, pattern: pattern})
	}
	return validator, nil
}

func (v *Validator) Validate(r *http.Request) []ValidationFinding {
	// Negative bodyBytes falls back to ContentLength for existing callers.
	return v.ValidateWithBodySize(r, -1)
}

// ValidateWithBodySize checks schemas; when bodyBytes >= 0 it is used for MaxBodyBytes,
// otherwise ContentLength is used (unknown length yields no body finding).
func (v *Validator) ValidateWithBodySize(r *http.Request, bodyBytes int64) []ValidationFinding {
	if v == nil || !v.enabled || r == nil {
		return nil
	}
	var findings []ValidationFinding
	path := r.URL.Path
	measuredBodyBytes := int64(-1)
	bodyMeasured := false
	for _, item := range v.schemas {
		if item.cfg.Method != "" && !strings.EqualFold(item.cfg.Method, r.Method) {
			continue
		}
		if !item.pattern.MatchString(path) {
			continue
		}
		query := r.URL.Query()
		for _, name := range item.cfg.RequiredParams {
			if query.Get(name) == "" {
				findings = append(findings, finding(item.cfg.ID, name, "required query parameter is missing"))
			}
		}
		for _, name := range item.cfg.RequiredHeaders {
			if r.Header.Get(name) == "" {
				findings = append(findings, finding(item.cfg.ID, name, "required header is missing"))
			}
		}
		if item.cfg.MaxBodyBytes > 0 {
			size := bodyBytes
			if size < 0 {
				if r.Body == nil {
					continue
				}
				if r.ContentLength >= 0 {
					size = r.ContentLength
				} else if !bodyMeasured {
					probeLimit := item.cfg.MaxBodyBytes + 1
					body, err := io.ReadAll(io.LimitReader(r.Body, probeLimit))
					if err != nil {
						measuredBodyBytes = probeLimit
					} else {
						measuredBodyBytes = int64(len(body))
					}
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
					bodyMeasured = true
					size = measuredBodyBytes
				} else {
					size = measuredBodyBytes
				}
			}
			if size > item.cfg.MaxBodyBytes {
				findings = append(findings, finding(item.cfg.ID, "body", fmt.Sprintf("body exceeds %d bytes", item.cfg.MaxBodyBytes)))
			}
		}
	}
	return findings
}

func finding(schemaID, field, message string) ValidationFinding {
	return ValidationFinding{SchemaID: schemaID, Field: field, Message: message, Severity: "medium"}
}
