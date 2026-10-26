// Package duckdb implements the host-owned, read-only DuckDB analysis job
// boundary. It never executes arbitrary SQL and never bundles DuckDB itself.
package duckdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	DefaultMaxRows  = 10000
	DefaultMaxBytes = 1 << 20
)

var forbiddenSQL = []string{
	"ATTACH", "COPY", "INSTALL", "LOAD", "PRAGMA", "EXPORT", "IMPORT",
	"CALL", "CREATE", "DROP", "ALTER", "INSERT", "UPDATE", "DELETE",
	"TRUNCATE", "VACUUM", "READ_PARQUET", "READ_CSV", "READ_JSON",
	"HTTP", "S3", "GLOB",
}

// Template is one reviewed, parameterized analysis statement.
type Template struct {
	ID       string
	SQL      string
	SHA256   string
	MaxRows  int
	MaxBytes int
}

// LoadTemplate validates a fixed analysis template and computes its digest.
func LoadTemplate(id string, sql []byte) (Template, error) {
	text := strings.TrimSpace(string(sql))
	if id == "" || text == "" {
		return Template{}, fmt.Errorf("duckdb template id and SQL are required")
	}
	upper := strings.ToUpper(text)
	for _, word := range forbiddenSQL {
		if strings.Contains(upper, word) {
			return Template{}, fmt.Errorf("duckdb template contains forbidden token %q", word)
		}
	}
	if !strings.HasPrefix(upper, "SELECT ") && !strings.HasPrefix(upper, "SELECT\n") && !strings.HasPrefix(upper, "WITH ") {
		return Template{}, fmt.Errorf("duckdb template must be a SELECT")
	}
	if !strings.Contains(upper, "FROM AUDIT_EVENTS") {
		return Template{}, fmt.Errorf("duckdb template must read only audit_events")
	}
	if strings.Contains(text, ";") {
		return Template{}, fmt.Errorf("duckdb template must contain one statement")
	}
	sum := sha256.Sum256([]byte(text))
	return Template{ID: id, SQL: text, SHA256: hex.EncodeToString(sum[:]), MaxRows: DefaultMaxRows, MaxBytes: DefaultMaxBytes}, nil
}

// BindWindow replaces the two positional window parameters with literal
// timestamps. The template is reviewed, so this is not a general SQL binder.
func BindWindow(template Template, from, to string) (string, error) {
	if strings.Count(template.SQL, "?") != 2 {
		return "", fmt.Errorf("duckdb template must contain exactly two window parameters")
	}
	parts := strings.SplitN(template.SQL, "?", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("duckdb template must contain exactly two window parameters")
	}
	// Bind both placeholders from the original split. Sequential strings.Replace
	// would substitute into the literal just inserted when from/to contains "?".
	return parts[0] + "TIMESTAMP '" + escapeLiteral(from) + "'" +
		parts[1] + "TIMESTAMP '" + escapeLiteral(to) + "'" + parts[2], nil
}

func escapeLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
