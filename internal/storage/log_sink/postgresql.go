package log_sink

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgreSQLSink struct {
	db    *sql.DB
	table string
}

func NewPostgreSQLSink(cfg config.PostgreSQLConfig) (*PostgreSQLSink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.DSN == "" {
		return nil, fmt.Errorf("postgresql dsn is required")
	}
	if cfg.Table == "" {
		cfg.Table = "cheesewaf_logs"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	table, err := quoteIdentifierPath(cfg.Table)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect postgresql: %w", err)
	}
	sink := &PostgreSQLSink{db: db, table: table}
	if err := sink.ensureTable(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return sink, nil
}

func (s *PostgreSQLSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if entry == nil {
		return nil
	}
	id := entry.ID
	if id == "" {
		id = entry.TraceID
	}
	if id == "" {
		id = fmt.Sprintf("log-%d", time.Now().UnixNano())
	}
	tags, err := json.Marshal(entry.Tags)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s (
		id, timestamp, trace_id, site_id, client_ip, method, uri, status_code,
		action, detector_id, category, severity, message, payload, user_agent,
		country, latency_ms, tags, metadata
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8,
		$9, $10, $11, $12, $13, $14, $15,
		$16, $17, $18::jsonb, $19::jsonb
	)
	ON CONFLICT (id) DO UPDATE SET
		timestamp = EXCLUDED.timestamp,
		trace_id = EXCLUDED.trace_id,
		site_id = EXCLUDED.site_id,
		client_ip = EXCLUDED.client_ip,
		method = EXCLUDED.method,
		uri = EXCLUDED.uri,
		status_code = EXCLUDED.status_code,
		action = EXCLUDED.action,
		detector_id = EXCLUDED.detector_id,
		category = EXCLUDED.category,
		severity = EXCLUDED.severity,
		message = EXCLUDED.message,
		payload = EXCLUDED.payload,
		user_agent = EXCLUDED.user_agent,
		country = EXCLUDED.country,
		latency_ms = EXCLUDED.latency_ms,
		tags = EXCLUDED.tags,
		metadata = EXCLUDED.metadata`, s.table),
		id, entry.Timestamp, entry.TraceID, entry.SiteID, entry.ClientIP, entry.Method, entry.URI, entry.StatusCode,
		entry.Action, entry.DetectorID, entry.Category, entry.Severity, entry.Message, entry.Payload, entry.UserAgent,
		entry.Country, float64(entry.Latency)/float64(time.Millisecond), string(tags), string(metadata),
	)
	return err
}

func (s *PostgreSQLSink) Query(ctx context.Context, filter storage.LogFilter) ([]storage.LogEntry, int64, error) {
	where, args, err := postgresqlWhere(filter)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s%s", s.table, where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	queryArgs := append(append([]any{}, args...), limit, offset)
	query := fmt.Sprintf(`SELECT
		id, timestamp, trace_id, site_id, client_ip, method, uri, status_code,
		action, detector_id, category, severity, message, payload, user_agent,
		country, latency_ms, tags, metadata
		FROM %s%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d`, s.table, where, len(queryArgs)-1, len(queryArgs))
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []storage.LogEntry
	for rows.Next() {
		var entry storage.LogEntry
		var latencyMS float64
		var tagsRaw, metadataRaw []byte
		if err := rows.Scan(
			&entry.ID, &entry.Timestamp, &entry.TraceID, &entry.SiteID, &entry.ClientIP, &entry.Method, &entry.URI, &entry.StatusCode,
			&entry.Action, &entry.DetectorID, &entry.Category, &entry.Severity, &entry.Message, &entry.Payload, &entry.UserAgent,
			&entry.Country, &latencyMS, &tagsRaw, &metadataRaw,
		); err != nil {
			return nil, 0, err
		}
		entry.Latency = time.Duration(latencyMS * float64(time.Millisecond))
		if len(tagsRaw) > 0 {
			_ = json.Unmarshal(tagsRaw, &entry.Tags)
		}
		if len(metadataRaw) > 0 {
			_ = json.Unmarshal(metadataRaw, &entry.Metadata)
		}
		entries = append(entries, entry)
	}
	return entries, total, rows.Err()
}

func (s *PostgreSQLSink) Flush(context.Context) error {
	return nil
}

func (s *PostgreSQLSink) Close() error {
	return s.db.Close()
}

func (s *PostgreSQLSink) ensureTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id text PRIMARY KEY,
		timestamp timestamptz NOT NULL,
		trace_id text,
		site_id text,
		client_ip text,
		method text,
		uri text,
		status_code integer,
		action text,
		detector_id text,
		category text,
		severity text,
		message text,
		payload text,
		user_agent text,
		country text,
		latency_ms double precision,
		tags jsonb NOT NULL DEFAULT '[]'::jsonb,
		metadata jsonb NOT NULL DEFAULT '{}'::jsonb
	)`, s.table))
	if err != nil {
		return fmt.Errorf("create postgresql log table: %w", err)
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (timestamp DESC)`, indexName(s.table, "timestamp"), s.table))
	if err != nil {
		return fmt.Errorf("create postgresql timestamp index: %w", err)
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s (trace_id)`, indexName(s.table, "trace_id"), s.table))
	if err != nil {
		return fmt.Errorf("create postgresql trace index: %w", err)
	}
	return nil
}

func postgresqlWhere(filter storage.LogFilter) (string, []any, error) {
	var clauses []string
	var args []any
	add := func(sql string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(sql, len(args)))
	}
	if filter.SiteID != "" {
		add("site_id = $%d", filter.SiteID)
	}
	if filter.ClientIP != "" {
		add("client_ip = $%d", filter.ClientIP)
	}
	if filter.Category != "" {
		add("category = $%d", filter.Category)
	}
	if filter.Action != "" {
		add("action = $%d", filter.Action)
	}
	if filter.TraceID != "" {
		add("trace_id = $%d", filter.TraceID)
	}
	if !filter.StartTime.IsZero() {
		add("timestamp >= $%d", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		add("timestamp <= $%d", filter.EndTime)
	}
	for _, tag := range filter.Tags {
		raw, err := json.Marshal([]string{tag})
		if err != nil {
			return "", nil, err
		}
		add("tags @> $%d::jsonb", string(raw))
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

func quoteIdentifierPath(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("postgresql table is required")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("postgresql table supports table or schema.table")
	}
	ident := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for idx, part := range parts {
		if !ident.MatchString(part) {
			return "", fmt.Errorf("unsafe postgresql identifier %q", part)
		}
		parts[idx] = `"` + strings.ReplaceAll(part, `"`, `""`) + `"`
	}
	return strings.Join(parts, "."), nil
}

func indexName(table, suffix string) string {
	name := strings.NewReplacer(`"`, "", ".", "_").Replace(table)
	name = strings.Trim(name, "_")
	return fmt.Sprintf(`"%s_%s_idx"`, name, suffix)
}
