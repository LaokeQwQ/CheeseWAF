package notifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

const (
	jsonMaxAttempts = 3
	jsonRetryDelay  = 25 * time.Millisecond
)

func newNotifierHTTPClient(allowPrivate bool) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: 10 * time.Second,
		Policy: netguard.URLPolicy{
			Purpose:        "notifier",
			HostPurpose:    "notifier endpoint",
			AllowedSchemes: []string{"http", "https"},
			AllowPrivate:   allowPrivate,
		},
	})
}

func deliverJSON(ctx context.Context, client *http.Client, endpoint string, body []byte, headers map[string]string) error {
	if client == nil {
		return errors.New("notifier HTTP client is required")
	}
	var lastErr error
	for attempt := 1; attempt <= jsonMaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			netguard.DrainAndClose(resp.Body)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("notifier returned %s", resp.Status)
			if !retryableWebhookStatus(resp.StatusCode) {
				return lastErr
			}
		} else {
			lastErr = requestErr
		}
		if attempt == jsonMaxAttempts {
			break
		}
		if err := waitWebhookRetry(ctx, attempt); err != nil {
			return fmt.Errorf("notifier delivery stopped after attempt %d: %w", attempt, err)
		}
	}
	return fmt.Errorf("notifier delivery failed after %d attempts: %w", jsonMaxAttempts, lastErr)
}

func closeIfPossible(body io.ReadCloser) {
	if body != nil {
		_ = body.Close()
	}
}
