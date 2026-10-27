package notifier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

const smtpTimeout = 10 * time.Second

type EmailNotifier struct {
	cfg config.NotifierConfig
}

func newEmailNotifier(cfg config.NotifierConfig) *EmailNotifier {
	return &EmailNotifier{cfg: cfg}
}

func (e *EmailNotifier) Notify(ctx context.Context, alert monitor.Alert) error {
	if e == nil {
		return nil
	}
	cfg := e.cfg
	address, host, err := smtpEndpoint(cfg.Endpoint)
	if err != nil {
		return fmt.Errorf("notifier %q: %w", cfg.ID, err)
	}
	recipient, err := mail.ParseAddress(strings.TrimSpace(cfg.To))
	if err != nil || strings.TrimSpace(cfg.To) == "" {
		return fmt.Errorf("notifier %q requires a valid recipient in to", cfg.ID)
	}
	fromValue := firstNonEmpty(strings.TrimSpace(cfg.Headers["from"]), strings.TrimSpace(cfg.Headers["username"]))
	if fromValue == "" {
		return fmt.Errorf("notifier %q requires headers.from or headers.username", cfg.ID)
	}
	sender, err := mail.ParseAddress(fromValue)
	if err != nil {
		return fmt.Errorf("notifier %q sender address is invalid: %w", cfg.ID, err)
	}
	username := strings.TrimSpace(cfg.Headers["username"])
	message := emailMessage(sender, recipient, alert)

	conn, err := e.dialSMTP(ctx, address)
	if err != nil {
		return fmt.Errorf("notifier %q SMTP dial %s failed: %w", cfg.ID, address, err)
	}
	// Bound every SMTP socket operation, not just the TCP connect. Without
	// this a malicious or stalled server can hold the notifier worker forever.
	if err := conn.SetDeadline(time.Now().Add(smtpTimeout)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("notifier %q SMTP deadline failed: %w", cfg.ID, err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notifier %q SMTP handshake failed: %w", cfg.ID, err)
	}
	defer func() { _ = client.Close() }()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("notifier %q SMTP STARTTLS failed: %w", cfg.ID, err)
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, cfg.Token, host)); err != nil {
			return fmt.Errorf("notifier %q SMTP authentication failed: %w", cfg.ID, err)
		}
	}
	if err := client.Mail(sender.Address); err != nil {
		return fmt.Errorf("notifier %q SMTP sender rejected: %w", cfg.ID, err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("notifier %q SMTP recipient rejected: %w", cfg.ID, err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("notifier %q SMTP data failed: %w", cfg.ID, err)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("notifier %q SMTP message failed: %w", cfg.ID, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("notifier %q SMTP message failed: %w", cfg.ID, err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("notifier %q SMTP quit failed: %w", cfg.ID, err)
	}
	return nil
}

// dialSMTP applies the notifier's private-endpoint policy to SMTP too. The
// HTTP providers resolve and check every address before connecting; a raw TCP
// dial here would let an allowed-looking hostname reach loopback services.
func (e *EmailNotifier) dialSMTP(ctx context.Context, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: smtpTimeout}
	if e.cfg.AllowPrivateEndpoint {
		return dialer.DialContext(ctx, "tcp", address)
	}
	hostOnly, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", hostOnly)
	if err != nil {
		return nil, fmt.Errorf("resolve SMTP host %q: %w", hostOnly, err)
	}
	var lastErr error
	for _, ip := range addresses {
		if !netguard.IsPublicIP(ip) {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("SMTP host %q resolves only to private addresses and allow_private_endpoint is false", hostOnly)
}

func smtpEndpoint(raw string) (address, host string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("endpoint is required")
	}
	if strings.Contains(trimmed, "://") {
		parsed, parseErr := url.Parse(trimmed)
		if parseErr != nil {
			return "", "", fmt.Errorf("endpoint is invalid: %w", parseErr)
		}
		if !strings.EqualFold(parsed.Scheme, "smtp") {
			return "", "", errors.New("endpoint must use the smtp scheme")
		}
		if parsed.User != nil {
			return "", "", errors.New("endpoint must not contain credentials; use headers.username and token")
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return "", "", errors.New("endpoint must contain only host and port")
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" {
			return "", "", errors.New("endpoint must not contain query parameters or fragments")
		}
		trimmed = parsed.Host
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil || host == "" || port == "" {
		return "", "", errors.New("endpoint must be smtp://host:port or host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("endpoint port %q is invalid", port)
	}
	return net.JoinHostPort(host, port), host, nil
}

func emailMessage(sender, recipient *mail.Address, alert monitor.Alert) []byte {
	title := firstNonEmpty(strings.TrimSpace(alert.Name), strings.TrimSpace(alert.RuleID), "Security alert")
	subject := title
	if severity := strings.TrimSpace(alert.Severity); severity != "" {
		subject = "[" + severity + "] " + title
	}
	var message strings.Builder
	fmt.Fprintf(&message, "From: %s\r\n", sender.String())
	fmt.Fprintf(&message, "To: %s\r\n", recipient.String())
	fmt.Fprintf(&message, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", singleLine(subject)))
	fmt.Fprintf(&message, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	message.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	message.WriteString("\r\n")
	message.WriteString(strings.ReplaceAll(alertText(alert), "\n", "\r\n"))
	message.WriteString("\r\n")
	return []byte(message.String())
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
