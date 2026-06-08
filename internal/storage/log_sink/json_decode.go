package log_sink

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func decodeLogEntryJSONLines(body io.ReadCloser) ([]storage.LogEntry, error) {
	defer body.Close()
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var entries []storage.LogEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry, err := decodeLogEntryJSON([]byte(line))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

func decodeLogEntryJSON(data []byte) (storage.LogEntry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return storage.LogEntry{}, err
	}
	entry := storage.LogEntry{
		ID:         jsonString(raw, "id"),
		TraceID:    jsonString(raw, "trace_id"),
		SiteID:     jsonString(raw, "site_id"),
		ClientIP:   jsonString(raw, "client_ip"),
		Method:     jsonString(raw, "method"),
		URI:        jsonString(raw, "uri"),
		StatusCode: int(jsonNumber(raw, "status_code")),
		Action:     jsonString(raw, "action"),
		DetectorID: jsonString(raw, "detector_id"),
		Category:   jsonString(raw, "category"),
		Severity:   jsonString(raw, "severity"),
		Message:    jsonString(raw, "message"),
		Payload:    jsonString(raw, "payload"),
		UserAgent:  jsonString(raw, "user_agent"),
		Country:    jsonString(raw, "country"),
		Tags:       jsonStringSlice(raw, "tags"),
		Metadata:   jsonObject(raw, "metadata"),
	}
	if entry.Message == "" {
		entry.Message = jsonString(raw, "_msg")
	}
	if timestamp := jsonTime(raw, "timestamp"); !timestamp.IsZero() {
		entry.Timestamp = timestamp
	} else {
		entry.Timestamp = jsonTime(raw, "_time")
	}
	if latency := jsonNumber(raw, "latency"); latency > 0 {
		entry.Latency = time.Duration(latency)
	} else if latencyMS := jsonNumber(raw, "latency_ms"); latencyMS > 0 {
		entry.Latency = time.Duration(latencyMS * float64(time.Millisecond))
	}
	return entry, nil
}

func jsonString(raw map[string]json.RawMessage, key string) string {
	value, ok := raw[key]
	if !ok || len(value) == 0 || string(value) == "null" {
		return ""
	}
	var out string
	if err := json.Unmarshal(value, &out); err == nil {
		return out
	}
	var number json.Number
	if err := json.Unmarshal(value, &number); err == nil {
		return number.String()
	}
	var boolean bool
	if err := json.Unmarshal(value, &boolean); err == nil {
		return strconv.FormatBool(boolean)
	}
	return ""
}

func jsonNumber(raw map[string]json.RawMessage, key string) float64 {
	value, ok := raw[key]
	if !ok || len(value) == 0 || string(value) == "null" {
		return 0
	}
	var number json.Number
	if err := json.Unmarshal(value, &number); err == nil {
		out, _ := number.Float64()
		return out
	}
	var text string
	if err := json.Unmarshal(value, &text); err == nil {
		out, _ := strconv.ParseFloat(strings.TrimSpace(text), 64)
		return out
	}
	return 0
}

func jsonTime(raw map[string]json.RawMessage, key string) time.Time {
	text := jsonString(raw, key)
	if text == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.UTC()
		}
	}
	if unix, err := strconv.ParseFloat(text, 64); err == nil && unix > 0 {
		seconds := int64(unix)
		nanos := int64((unix - float64(seconds)) * 1e9)
		return time.Unix(seconds, nanos).UTC()
	}
	return time.Time{}
}

func jsonStringSlice(raw map[string]json.RawMessage, key string) []string {
	value, ok := raw[key]
	if !ok || len(value) == 0 || string(value) == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal(value, &out); err == nil {
		return out
	}
	text := jsonString(raw, key)
	if text == "" {
		return nil
	}
	parts := strings.Split(text, ",")
	out = make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func jsonObject(raw map[string]json.RawMessage, key string) map[string]any {
	value, ok := raw[key]
	if !ok || len(value) == 0 || string(value) == "null" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(value, &out); err == nil {
		return out
	}
	text := jsonString(raw, key)
	if text == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(text), &out); err == nil {
		return out
	}
	return map[string]any{"raw": text}
}

func numericValue(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int:
		return int64(typed)
	case int64:
		return typed
	case json.Number:
		out, _ := typed.Int64()
		return out
	case string:
		out, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return out
	default:
		return 0
	}
}

func encodeLogEntryForVictoriaLogs(entry *storage.LogEntry) (map[string]any, error) {
	if entry == nil {
		return nil, fmt.Errorf("log entry is nil")
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	timestamp := entry.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	out["_time"] = timestamp.UTC().Format(time.RFC3339Nano)
	if entry.Message != "" {
		out["_msg"] = entry.Message
	} else if entry.Payload != "" {
		out["_msg"] = entry.Payload
	}
	return out, nil
}
