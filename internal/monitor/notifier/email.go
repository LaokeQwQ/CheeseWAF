package notifier

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type emailSendFunc func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error

// Email delivers alerts through a customer-provided SMTP server. It never
// operates as an open relay or a hosted mail service.
type Email struct {
	cfg  config.NotifierConfig
	send emailSendFunc
	now  func() time.Time
}

func NewEmail(cfg config.NotifierConfig, send emailSendFunc) *Email {
	if send == nil {
		if strings.EqualFold(strings.TrimSpace(cfg.TLSMode), "implicit") {
			send = sendSMTPImplicit
		} else {
			send = sendSMTP
		}
	}
	return &Email{cfg: cfg, send: send, now: func() time.Time { return time.Now().UTC() }}
}

func (e *Email) Notify(ctx context.Context, alert monitor.Alert) error {
	if e == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	from, recipients, err := e.addresses()
	if err != nil {
		return err
	}
	message, err := buildEmailMessage(from, recipients, e.cfg.SubjectPrefix, alert, e.now())
	if err != nil {
		return err
	}
	host := strings.TrimSpace(e.cfg.SMTPHost)
	port := e.cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	if host == "" {
		return fmt.Errorf("email notifier %q requires smtp_host", e.cfg.ID)
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var auth smtp.Auth
	if strings.TrimSpace(e.cfg.SMTPUsername) != "" {
		auth = smtp.PlainAuth("", e.cfg.SMTPUsername, e.cfg.Token, host)
	}
	if err := e.send(addr, auth, from, recipients, message); err != nil {
		return fmt.Errorf("email notifier %q delivery failed: %w", e.cfg.ID, err)
	}
	return nil
}

func (e *Email) addresses() (string, []string, error) {
	from := strings.TrimSpace(e.cfg.From)
	if from == "" {
		return "", nil, fmt.Errorf("email notifier %q requires from", e.cfg.ID)
	}
	if strings.ContainsAny(from, "\r\n") {
		return "", nil, fmt.Errorf("email notifier %q contains an invalid from header", e.cfg.ID)
	}
	parsedFrom, err := mail.ParseAddress(from)
	if err != nil {
		return "", nil, fmt.Errorf("email notifier %q from is invalid: %w", e.cfg.ID, err)
	}
	parts := strings.Split(e.cfg.To, ",")
	recipients := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, "\r\n") {
			return "", nil, fmt.Errorf("email notifier %q contains an invalid recipient", e.cfg.ID)
		}
		parsed, err := mail.ParseAddress(value)
		if err != nil {
			return "", nil, fmt.Errorf("email notifier %q recipient is invalid: %w", e.cfg.ID, err)
		}
		recipients = append(recipients, parsed.Address)
	}
	if len(recipients) == 0 {
		return "", nil, fmt.Errorf("email notifier %q requires at least one recipient", e.cfg.ID)
	}
	return parsedFrom.Address, recipients, nil
}

func buildEmailMessage(from string, recipients []string, subjectPrefix string, alert monitor.Alert, now time.Time) ([]byte, error) {
	title, text := alertTitleText(alert)
	subject := strings.TrimSpace(subjectPrefix)
	if subject == "" {
		subject = "[CheeseWAF]"
	}
	subject += " " + title
	if strings.ContainsAny(subject, "\r\n") {
		return nil, fmt.Errorf("email subject contains a header separator")
	}
	var message strings.Builder
	message.WriteString("From: " + from + "\r\n")
	message.WriteString("To: " + strings.Join(recipients, ", ") + "\r\n")
	message.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	message.WriteString("Date: " + now.UTC().Format(time.RFC1123Z) + "\r\n")
	message.WriteString("Message-ID: <" + randomMessageID() + "@cheesewaf.local>\r\n")
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	message.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	message.WriteString(text)
	message.WriteString("\r\n")
	return []byte(message.String()), nil
}

func randomMessageID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(raw)
}

func sendSMTP(addr string, auth smtp.Auth, from string, to []string, message []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func sendSMTPImplicit(addr string, auth smtp.Auth, from string, to []string, message []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
