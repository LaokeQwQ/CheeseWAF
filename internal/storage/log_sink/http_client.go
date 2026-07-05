package log_sink

import (
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

func guardedLogSinkHTTPClient(timeout time.Duration, purpose string, allowPrivate bool) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: timeout,
		Policy: netguard.URLPolicy{
			Purpose:        purpose,
			HostPurpose:    purpose,
			AllowedSchemes: []string{"http", "https"},
			AllowPrivate:   allowPrivate,
		},
	})
}
