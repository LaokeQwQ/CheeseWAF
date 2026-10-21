package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/feed"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel/scheduler"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
)

const defaultIntelPollInterval = 15 * time.Minute

// startIntelScheduler starts the background feed poller. It stores normalized
// feed items only; candidate generation stays review-first and requires an
// explicit site scope through the import API. The runner is a no-op when there
// are no enabled sources.
func startIntelScheduler(ctx context.Context, cfg config.IntelConfig, store intelstore.Store) {
	if ctx == nil || store == nil || !cfg.Enabled {
		return
	}
	sources := make([]feed.Source, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		if !source.Enabled || strings.TrimSpace(source.URL) == "" || !feedSourceType(source.Type) {
			continue
		}
		sources = append(sources, feed.Source{
			ID:      source.ID,
			Name:    source.ID,
			URL:     source.URL,
			Trust:   feed.ParseTrustLevel(source.Trust),
			Enabled: true,
		})
	}
	if len(sources) == 0 {
		return
	}
	fetcher, err := intel.NewFetcher(intel.FetchOptions{MaxBodyBytes: cfg.MaxFetchBytes})
	if err != nil {
		log.Printf("intel scheduler: %v", err)
		return
	}
	interval := cfg.PollInterval
	if interval <= 0 {
		interval = defaultIntelPollInterval
	}
	runner, err := scheduler.New(scheduler.Options{
		Config: scheduler.Config{Interval: interval},
		Provider: scheduler.SourceProviderFunc(func(context.Context) ([]feed.Source, error) {
			return append([]feed.Source(nil), sources...), nil
		}),
		Fetcher: scheduler.FetcherFunc(func(ctx context.Context, request scheduler.Request) (scheduler.Response, error) {
			result, err := fetcher.Fetch(ctx, intel.FetchRequest{
				URL: request.URL, ETag: request.ETag, LastModified: request.LastModified,
			})
			if err != nil {
				return scheduler.Response{}, err
			}
			return scheduler.Response{
				StatusCode: result.StatusCode, Body: result.Body,
				ETag: result.ETag, LastModified: result.LastModified, NotModified: result.NotModified,
			}, nil
		}),
		Sink: scheduler.SinkFunc(func(ctx context.Context, source feed.Source, items []feed.FeedItem) error {
			stored := 0
			for _, item := range items {
				created, err := storeFeedItem(ctx, store, source, item)
				if err != nil {
					return err
				}
				if created {
					stored++
				}
			}
			intel.RecordFeedItemsStored(stored)
			return nil
		}),
	})
	if err != nil {
		log.Printf("intel scheduler: %v", err)
		return
	}
	go func() {
		if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("intel scheduler stopped: %v", err)
		}
	}()
}

func feedSourceType(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "rss", "atom", "api":
		return true
	default:
		return false
	}
}

func storeFeedItem(ctx context.Context, store intelstore.Store, source feed.Source, item feed.FeedItem) (bool, error) {
	if store == nil {
		return false, nil
	}
	hash := strings.ToLower(strings.TrimSpace(item.ContentHash))
	if hash == "" {
		sum := sha256.Sum256([]byte(item.Title + "\n" + item.Summary + "\n" + item.Link))
		hash = hex.EncodeToString(sum[:])
	}
	id := item.ExternalID
	if id == "" {
		id = hash[:16]
	}
	ids := make([]string, 0, 4)
	ids = append(ids, id)
	ids = append(ids, item.CVEIDs...)
	ids = append(ids, item.AVDIDs...)
	ids = append(ids, item.GHSAIDs...)
	intelItem := intel.Item{
		ID:          "feed-" + hash[:16],
		SourceID:    source.ID,
		ExternalIDs: ids,
		Title:       item.Title,
		ContentHash: hash,
		PublishedAt: item.Published,
		Products:    item.Products,
		References:  item.References,
		RawExcerpt:  item.Summary,
	}
	_, created, err := store.InsertItem(ctx, intelItem)
	if err != nil {
		return false, fmt.Errorf("store feed item %q: %w", id, err)
	}
	return created, nil
}
