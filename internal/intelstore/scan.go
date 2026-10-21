package intelstore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

type rowScanner interface {
	Scan(dest ...any) error
}

const (
	sqliteTimeLayout = "2006-01-02T15:04:05.000000000Z"
	zeroTimeText     = "0001-01-01T00:00:00.000000000Z"
)

func formatSQLiteTime(value time.Time) string {
	if value.IsZero() {
		return zeroTimeText
	}
	return value.UTC().Format(sqliteTimeLayout)
}

func asTime(value any) (time.Time, error) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return typed.UTC(), nil
	case string:
		if typed == "" {
			return time.Time{}, nil
		}
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: parse timestamp: %v", ErrInvalid, err)
		}
		return parsed.UTC(), nil
	case []byte:
		return asTime(string(typed))
	default:
		return time.Time{}, fmt.Errorf("%w: unsupported timestamp type %T", ErrInvalid, value)
	}
}

func asBool(value any) (bool, error) {
	switch typed := value.(type) {
	case bool:
		return typed, nil
	case int64:
		return typed != 0, nil
	case []byte:
		return typed != nil && len(typed) > 0 && string(typed) != "0" && string(typed) != "false", nil
	case string:
		return typed != "" && typed != "0" && typed != "false", nil
	default:
		return false, fmt.Errorf("%w: unsupported boolean type %T", ErrInvalid, value)
	}
}

func asJSONBytes(value any) []byte {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return []byte(typed)
	case []byte:
		return typed
	default:
		return nil
	}
}

func asStringList(value any) ([]string, error) {
	raw := asJSONBytes(value)
	if len(raw) == 0 {
		return nil, nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("%w: decode string list: %v", ErrInvalid, err)
	}
	return values, nil
}

func encodeStringList(values []string, label string) (string, error) {
	if values == nil {
		values = []string{}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("%w: encode %s: %v", ErrInvalid, label, err)
	}
	if len(encoded) > maxListJSONBytes {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalid, label, maxListJSONBytes)
	}
	return string(encoded), nil
}

func scanSource(row rowScanner) (intel.Source, error) {
	var (
		source   intel.Source
		rawTrust string
		enabled  any
	)
	if err := row.Scan(&source.ID, &source.Type, &source.URL, &rawTrust, &enabled, &source.ETag, &source.LastModified); err != nil {
		return intel.Source{}, err
	}
	source.Trust = intel.ParseTrustLevel(rawTrust)
	value, err := asBool(enabled)
	if err != nil {
		return intel.Source{}, err
	}
	source.Enabled = value
	return source, nil
}

func scanItem(row rowScanner) (intel.Item, error) {
	var (
		item        intel.Item
		external    any
		products    any
		versions    any
		references  any
		publishedAt any
	)
	if err := row.Scan(
		&item.ID, &item.SourceID, &external, &item.Title, &item.ContentHash, &publishedAt,
		&products, &versions, &item.AttackVector, &item.ExploitStatus, &references, &item.RawExcerpt,
	); err != nil {
		return intel.Item{}, err
	}
	var err error
	if item.ExternalIDs, err = asStringList(external); err != nil {
		return intel.Item{}, err
	}
	if item.Products, err = asStringList(products); err != nil {
		return intel.Item{}, err
	}
	if item.AffectedVersions, err = asStringList(versions); err != nil {
		return intel.Item{}, err
	}
	if item.References, err = asStringList(references); err != nil {
		return intel.Item{}, err
	}
	if item.PublishedAt, err = asTime(publishedAt); err != nil {
		return intel.Item{}, err
	}
	return item, nil
}

func scanCandidate(row rowScanner) (intel.Candidate, error) {
	var (
		candidate  intel.Candidate
		ruleJSON   any
		rawState   string
		confidence float64
		provenance any
		expiresAt  any
		createdAt  any
	)
	if err := row.Scan(
		&candidate.ID, &candidate.ItemID, &candidate.SiteID, &ruleJSON, &candidate.Action,
		&rawState, &confidence, &provenance, &expiresAt, &createdAt,
	); err != nil {
		return intel.Candidate{}, err
	}
	candidate.RuleJSON = string(asJSONBytes(ruleJSON))
	candidate.State = intel.CandidateState(rawState)
	candidate.Confidence = confidence
	if raw := asJSONBytes(provenance); len(raw) > 0 {
		if err := json.Unmarshal(raw, &candidate.Provenance); err != nil {
			return intel.Candidate{}, fmt.Errorf("%w: decode candidate provenance: %v", ErrInvalid, err)
		}
	}
	created, err := asTime(createdAt)
	if err != nil {
		return intel.Candidate{}, err
	}
	expiry, err := asTime(expiresAt)
	if err != nil {
		return intel.Candidate{}, err
	}
	candidate.CreatedAt = created
	if !created.IsZero() && !expiry.IsZero() {
		ttl := expiry.Sub(created)
		if ttl <= 0 || ttl > intel.MaxCandidateTTL {
			return intel.Candidate{}, fmt.Errorf("%w: stored candidate expiry is out of range", ErrInvalid)
		}
		candidate.TTL = ttl
	}
	return candidate, nil
}

func scanJob(row rowScanner) (ImportJob, error) {
	var (
		job        ImportJob
		extraction any
		createdAt  any
		updatedAt  any
	)
	if err := row.Scan(&job.ID, &job.URL, &job.ContentHash, &job.Status, &extraction, &job.Error, &createdAt, &updatedAt); err != nil {
		return ImportJob{}, err
	}
	if raw := asJSONBytes(extraction); len(raw) > 0 {
		job.ExtractionJSON = string(raw)
	}
	var err error
	if job.CreatedAt, err = asTime(createdAt); err != nil {
		return ImportJob{}, err
	}
	if job.UpdatedAt, err = asTime(updatedAt); err != nil {
		return ImportJob{}, err
	}
	return job, nil
}

const (
	sourceColumns    = `id, type, url, trust, enabled, etag, last_modified`
	itemColumns      = `id, source_id, external_ids, title, content_hash, published_at, products, affected_versions, attack_vector, exploit_status, references_json, raw_excerpt`
	candidateColumns = `id, item_id, site_id, rule_json, action, state, confidence, provenance_json, expires_at, created_at`
	jobColumns       = `id, url, content_hash, status, extraction_json, error, created_at, updated_at`
)
