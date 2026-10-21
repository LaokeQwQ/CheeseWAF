package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

// Extractor turns one normalized item into zero or more structured extraction
// values. Implementations must be deterministic and must not execute rules or
// mutate configuration. Returning no extraction means the item yields no
// candidate.
type Extractor interface {
	Extract(ctx context.Context, item intel.Item) ([]intel.Extraction, error)
}

// ExtractorFunc adapts a function to the Extractor interface.
type ExtractorFunc func(ctx context.Context, item intel.Item) ([]intel.Extraction, error)

// Extract calls the underlying function.
func (f ExtractorFunc) Extract(ctx context.Context, item intel.Item) ([]intel.Extraction, error) {
	return f(ctx, item)
}

// SingleExtractorFunc adapts a single-extraction function.
type SingleExtractorFunc func(ctx context.Context, item intel.Item) (intel.Extraction, error)

// Extract calls the underlying function and wraps the result.
func (f SingleExtractorFunc) Extract(ctx context.Context, item intel.Item) ([]intel.Extraction, error) {
	extraction, err := f(ctx, item)
	if err != nil {
		return nil, err
	}
	return []intel.Extraction{extraction}, nil
}

// FixedExtractor returns the same extraction for every item. It is intended
// for deterministic tests and for dry-run tooling, not production extraction.
func FixedExtractor(extraction intel.Extraction) Extractor {
	return ExtractorFunc(func(context.Context, intel.Item) ([]intel.Extraction, error) {
		return []intel.Extraction{extraction}, nil
	})
}

// ExcerptExtractor adapts an intel.Extractor to feed items, which carry
// normalized text rather than fetched HTML. The item excerpt becomes the
// document text so extraction never performs network I/O.
type ExcerptExtractor struct {
	Next intel.Extractor
}

// Extract builds a plain-text document from the item and delegates.
func (e ExcerptExtractor) Extract(ctx context.Context, item intel.Item) ([]intel.Extraction, error) {
	if e.Next == nil {
		return nil, ErrExtractionFailed
	}
	document := intel.Document{
		Title: item.Title,
		Text:  item.RawExcerpt,
		SHA256: func() string {
			sum := sha256.Sum256([]byte(item.RawExcerpt))
			return hex.EncodeToString(sum[:])
		}(),
	}
	extraction, err := e.Next.Extract(ctx, item, document)
	if err != nil {
		return nil, err
	}
	return []intel.Extraction{extraction}, nil
}
