package intel

import "context"

// Extractor converts normalized, untrusted document content into structured
// extraction data. Implementations must return extraction values only: they
// never execute rules, call tools, or mutate configuration.
type Extractor interface {
	Extract(ctx context.Context, item Item, document Document) (Extraction, error)
}

// ExtractorFunc adapts a function to the Extractor interface.
type ExtractorFunc func(ctx context.Context, item Item, document Document) (Extraction, error)

// Extract calls the underlying function.
func (f ExtractorFunc) Extract(ctx context.Context, item Item, document Document) (Extraction, error) {
	return f(ctx, item, document)
}
