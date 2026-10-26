package notifier

import (
	"context"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// TestEmailRejectsHeaderInjection guards the recipient parsing path: a CRLF in
// the configured address must never reach the SMTP envelope.
func TestEmailRejectsHeaderInjection(t *testing.T) {
	notifier, err := NewRegistry().New(config.NotifierConfig{
		ID:       "mail",
		Type:     "email",
		Endpoint: "smtp://127.0.0.1:2525",
		To:       "ops@example.test\r\nBcc: evil@example.test",
		Headers:  map[string]string{"from": "waf@example.test"},
	}, nil)
	if err != nil {
		t.Fatalf("create email provider: %v", err)
	}
	err = notifier.Notify(context.Background(), testAlert())
	if err == nil || !strings.Contains(err.Error(), "valid recipient") {
		t.Fatalf("expected recipient rejection, got %v", err)
	}
}
