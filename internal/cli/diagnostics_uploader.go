package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/integration"
)

const maxDiagnosticUploadBytes = 8 << 20

// httpUploadAdapter posts one encrypted diagnostic envelope to the operator's
// upload endpoint. It never decrypts the envelope and never retries on its own;
// the durable queue owns retry and retention.
type httpUploadAdapter struct {
	endpoint string
	token    func(context.Context) (string, error)
	client   *http.Client
}

func newHTTPUploadAdapter(endpoint, tokenFile string, timeout time.Duration) *httpUploadAdapter {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &httpUploadAdapter{
		endpoint: endpoint,
		token:    fileTokenSource(tokenFile),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *httpUploadAdapter) Upload(ctx context.Context, request integration.UploadRequest) error {
	if a == nil || a.client == nil {
		return fmt.Errorf("diagnostic upload: adapter is not configured")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("diagnostic upload: encode: %w", err)
	}
	if len(body) > maxDiagnosticUploadBytes {
		return fmt.Errorf("diagnostic upload: envelope exceeds %d bytes", maxDiagnosticUploadBytes)
	}
	token, err := a.token(ctx)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("diagnostic upload: request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("diagnostic upload: transport: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("diagnostic upload: status %d", resp.StatusCode)
	}
	return nil
}
