package log_sink

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgreSQLSink struct {
	db    *sql.DB
	table string
	async *asyncLogWriter
}

const (
	postgresqlLogBatchSize  = 64
	postgresqlLogQueueSize  = 1024
	postgresqlLogQueueBytes = 64 << 20
)

var postgresqlGeneratedID atomic.Uint64

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
	sink.async = newAsyncLogWriter("postgresql", sink.writeSync, nil, sink.db.Close, asyncLogWriterOptions{
		queueSize:        postgresqlLogQueueSize,
		queueBytes:       postgresqlLogQueueBytes,
		operationTimeout: cfg.Timeout,
		batchSize:        postgresqlLogBatchSize,
		writeBatch:       sink.writeBatchSync,
		alertCooldown:    time.Minute,
		alert: func(kind string, stats AsyncLogSinkStats, err error) {
			log.Printf("postgresql log sink %s: %v (pending=%d queue_depth=%d dropped=%d failed=%d)",
				kind, err, stats.Pending, stats.QueueDepth, stats.Dropped, stats.Failed)
		},
	})
	return sink, nil
}

func (s *PostgreSQLSink) Write(ctx context.Context, entry *storage.LogEntry) error {
	if s.async == nil {
		return s.writeSync(ctx, entry)
	}
	return s.async.Write(ctx, entry)
}

func (s *PostgreSQLSink) writeSync(ctx context.Context, entry *storage.LogEntry) error {
	return s.writeBatchSync(ctx, []*storage.LogEntry{entry})
}

func (s *PostgreSQLSink) writeBatchSync(ctx context.Context, entries []*storage.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	for start := 0; start < len(entries); start += postgresqlLogBatchSize {
		end := start + postgresqlLogBatchSize
		if end > len(entries) {
			end = len(entries)
		}

		rows := make([][]any, 0, end-start)
		positions := make(map[string]int, end-start)
		for _, entry := range entries[start:end] {
			row, err := postgresqlLogEntryValues(entry)
			if err != nil {
				return err
			}
			if row == nil {
				continue
			}
			// PostgreSQL rejects two rows in one INSERT that target the same
			// ON CONFLICT key. Keep the last update, matching sequential writes.
			id := row[0].(string)
			if position, ok := positions[id]; ok {
				rows[position] = row
				continue
			}
			positions[id] = len(rows)
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			continue
		}

		query, err := postgresqlInsertQuery(s.table, len(rows))
		if err != nil {
			return err
		}
		args := make([]any, 0, len(rows))
		for _, row := range rows {
			args = append(args, row...)
		}
		if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	return nil
}

const (
	postgresqlLogColumnCount = 19
	postgresqlLogColumns     = `id, timestamp, trace_id, site_id, client_ip, method, uri, status_code,
	action, detector_id, category, severity, message, payload, user_agent,
	country, latency_ms, tags, metadata`
	postgresqlLogConflictUpdate = `timestamp = EXCLUDED.timestamp,
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
		metadata = EXCLUDED.metadata`
)

func postgresqlLogEntryValues(entry *storage.LogEntry) ([]any, error) {
	if entry == nil {
		return nil, nil
	}
	id := entry.ID
	if id == "" {
		id = entry.TraceID
	}
	if id == "" {
		id = fmt.Sprintf("log-%d-%d", time.Now().UnixNano(), postgresqlGeneratedID.Add(1))
	}
	tags, err := json.Marshal(entry.Tags)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return nil, err
	}
	return []any{
		id, entry.Timestamp, entry.TraceID, entry.SiteID, entry.ClientIP, entry.Method, entry.URI, entry.StatusCode,
		entry.Action, entry.DetectorID, entry.Category, entry.Severity, entry.Message, entry.Payload, entry.UserAgent,
		entry.Country, float64(entry.Latency) / float64(time.Millisecond), string(tags), string(metadata),
	}, nil
}

func postgresqlInsertQuery(table string, rowCount int) (string, error) {
	if rowCount <= 0 || rowCount > postgresqlLogBatchSize {
		return "", fmt.Errorf("postgresql log batch row count %d is outside 1..%d", rowCount, postgresqlLogBatchSize)
	}
	values := make([]string, rowCount)
	for row := 0; row < rowCount; row++ {
		placeholders := make([]string, postgresqlLogColumnCount)
		for column := range placeholders {
			placeholder := fmt.Sprintf("$%d", row*postgresqlLogColumnCount+column+1)
			if column >= 17 {
				placeholder += "::jsonb"
			}
			placeholders[column] = placeholder
		}
		values[row] = "(" + strings.Join(placeholders, ", ") + ")"
	}
	return fmt.Sprintf("INSERT INTO %s (\n\t%s\n) VALUES\n\t%s\nON CONFLICT (id) DO UPDATE SET\n\t%s", table, postgresqlLogColumns, strings.Join(values, ",\n\t"), postgresqlLogConflictUpdate), nil
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
	order := "DESC"
	if filter.Ascending {
		order = "ASC"
	}
	query := fmt.Sprintf(`SELECT
		id, timestamp, trace_id, site_id, client_ip, method, uri, status_code,
		action, detector_id, category, severity, message, payload, user_agent,
		country, latency_ms, tags, metadata
		FROM %s%s
		ORDER BY timestamp %s, id %s
		LIMIT $%d OFFSET $%d`, s.table, where, order, order, len(queryArgs)-1, len(queryArgs))
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

func (s *PostgreSQLSink) Flush(ctx context.Context) error {
	if s.async == nil {
		return nil
	}
	return s.async.Flush(ctx)
}

func (s *PostgreSQLSink) Close() error {
	if s.async == nil {
		return s.db.Close()
	}
	return s.async.Close()
}

func (s *PostgreSQLSink) AsyncStats() AsyncLogSinkStats {
	if s.async == nil {
		return AsyncLogSinkStats{}
	}
	return s.async.Stats()
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
	if filter.ID != "" {
		add("id = $%d", filter.ID)
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
	if search := strings.TrimSpace(filter.Search); search != "" {
		add(`concat_ws(' ', id, trace_id, site_id, client_ip, method, uri, action, detector_id, category, severity, message, payload, user_agent, country) ILIKE $%d ESCAPE '\'`, "%"+escapeSQLLike(search)+"%")
	}
	switch strings.ToLower(strings.TrimSpace(filter.Kind)) {
	case "security":
		clauses = append(clauses, `(coalesce(category,'') <> '' OR coalesce(detector_id,'') <> '' OR coalesce(severity,'') <> '' OR lower(coalesce(action,'')) IN ('block','challenge','log','monitor') OR status_code IN (403,429))`)
	case "access":
		clauses = append(clauses, `(coalesce(category,'') = '' AND coalesce(detector_id,'') = '' AND coalesce(severity,'') = '' AND lower(coalesce(action,'')) IN ('','pass','cache_hit','redirect') AND status_code NOT IN (403,429))`)
	case "", "all":
	default:
		clauses = append(clauses, "FALSE")
	}
	if !filter.StartTime.IsZero() {
		add("timestamp >= $%d", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		add("timestamp <= $%d", filter.EndTime)
	}
	addKeyset := func(timestamp time.Time, id string, direction string) {
		if timestamp.IsZero() && id == "" {
			return
		}
		if timestamp.IsZero() {
			clauses = append(clauses, fmt.Sprintf("id %s $%d", direction, len(args)+1))
			args = append(args, id)
			return
		}
		if id == "" {
			clauses = append(clauses, fmt.Sprintf("timestamp %s $%d", direction, len(args)+1))
			args = append(args, timestamp)
			return
		}
		args = append(args, timestamp, timestamp, id)
		first, second, third := len(args)-2, len(args)-1, len(args)
		clauses = append(clauses, fmt.Sprintf("(timestamp %s $%d OR (timestamp = $%d AND id %s $%d))", direction, first, second, direction, third))
	}
	if filter.Ascending {
		addKeyset(filter.WatermarkTime, filter.WatermarkID, ">")
	} else {
		addKeyset(filter.WatermarkTime, filter.WatermarkID, "<")
	}
	addKeyset(filter.BeforeTime, filter.BeforeID, "<")
	addKeyset(filter.AfterTime, filter.AfterID, ">")
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

func escapeSQLLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	value = strings.ReplaceAll(value, "_", `\_`)
	return value
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
