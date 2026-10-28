package notifier

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// SMTP must honour allow_private_endpoint just like the HTTP providers: a
// loopback endpoint with the switch off must not be dialed at all.
func TestEmailNotifierRejectsPrivateSMTPUnlessAllowed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	cfg := config.NotifierConfig{
		ID: "mail", Type: "email", Endpoint: "smtp://" + listener.Addr().String(),
		To: "ops@example.test", Headers: map[string]string{"from": "waf@example.test"}, Enabled: true,
	}
	err = newEmailNotifier(cfg).Notify(context.Background(), monitor.Alert{RuleID: "r"})
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("error = %v, want a private-address rejection", err)
	}
	select {
	case <-accepted:
		t.Fatal("private SMTP address was dialed")
	case <-time.After(200 * time.Millisecond):
	}

	cfg.AllowPrivateEndpoint = true
	_ = newEmailNotifier(cfg).Notify(context.Background(), monitor.Alert{RuleID: "r"})
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("allowed private SMTP address was not dialed")
	}
}
