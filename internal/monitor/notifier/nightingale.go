package notifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

// nightingaleNotifier delivers alerts to a Nightingale (n9e) callback address.
// The callback URL is configured in Nightingale under alert notification
// settings and is used verbatim as Endpoint. Token is optional and is sent as a
// bearer token for reverse proxies or gateways in front of Nightingale; it is
// never placed in the JSON body.
type nightingaleNotifier struct {
	cfg    config.NotifierConfig
	client *http.Client
	now    func() time.Time
}

func newNightingaleNotifier(cfg config.NotifierConfig, client *http.Client) *nightingaleNotifier {
	return &nightingaleNotifier{
		cfg:    cfg,
		client: notifierHTTPClient(cfg, client),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func (n *nightingaleNotifier) Notify(ctx context.Context, alert monitor.Alert) error {
	if n == nil || strings.TrimSpace(n.cfg.Endpoint) == "" {
		return nil
	}
	endpoint, err := nightingaleCallbackEndpoint(n.cfg)
	if err != nil {
		return fmt.Errorf("notifier %q: %w", n.cfg.ID, err)
	}
	triggerTime := alert.StartsAt
	if triggerTime.IsZero() {
		triggerTime = n.now()
	}
	event := nightingaleEvent{
		Cate:             "cheesewaf",
		Cluster:          "cheesewaf",
		GroupName:        "CheeseWAF",
		Hash:             nightingaleEventKey(alert),
		RuleID:           0,
		RuleName:         alertTitle(alert),
		RuleProd:         "metric",
		Severity:         nightingaleSeverity(alert.Severity),
		PromForDuration:  0,
		PromEvalInterval: 0,
		Callbacks:        []string{},
		NotifyRecovered:  0,
		NotifyChannels:   []string{"webhook"},
		NotifyGroups:     []int64{},
		TargetIdent:      "cheesewaf",
		TriggerTime:      triggerTime.UTC().Unix(),
		TriggerValue:     strconv.FormatFloat(alert.Value, 'g', -1, 64),
		Tags:             nightingaleTags(alert),
		TagsMap:          nightingaleTagsMap(alert),
		Annotations:      nightingaleAnnotations(alert),
		IsRecovered:      false,
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("notifier %q could not encode event: %w", n.cfg.ID, err)
	}
	return sendJSON(ctx, n.cfg, n.client, jsonDelivery{
		endpoint: endpoint,
		body:     body,
		headers:  notifierHeaders(n.cfg, "Authorization", bearerValue(n.cfg.Token)),
	})
}

// nightingaleEvent mirrors the AlertCurEvent fields that a callback receiver
// relies on. RuleID is numeric in Nightingale while CheeseWAF rule IDs are
// strings, so the numeric field stays zero and the original identifier is
// carried in tags, tags_map, and annotations.
type nightingaleEvent struct {
	Cate             string            `json:"cate"`
	Cluster          string            `json:"cluster"`
	GroupName        string            `json:"group_name"`
	Hash             string            `json:"hash"`
	RuleID           int64             `json:"rule_id"`
	RuleName         string            `json:"rule_name"`
	RuleProd         string            `json:"rule_prod"`
	Severity         int               `json:"severity"`
	PromForDuration  int               `json:"prom_for_duration"`
	PromEvalInterval int               `json:"prom_eval_interval"`
	Callbacks        []string          `json:"callbacks"`
	NotifyRecovered  int               `json:"notify_recovered"`
	NotifyChannels   []string          `json:"notify_channels"`
	NotifyGroups     []int64           `json:"notify_groups"`
	TargetIdent      string            `json:"target_ident"`
	TriggerTime      int64             `json:"trigger_time"`
	TriggerValue     string            `json:"trigger_value"`
	Tags             []string          `json:"tags"`
	TagsMap          map[string]string `json:"tags_map"`
	Annotations      map[string]string `json:"annotations"`
	IsRecovered      bool              `json:"is_recovered"`
}

func nightingaleCallbackEndpoint(cfg config.NotifierConfig) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint is invalid: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return "", errors.New("endpoint must be an absolute URL")
	}
	if parsed.User != nil {
		return "", errors.New("endpoint must not contain credentials")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if strings.TrimSpace(cfg.Token) != "" {
			return "", errors.New("endpoint must use HTTPS when a token is configured")
		}
	default:
		return "", errors.New("endpoint must use HTTP or HTTPS")
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

// nightingaleSeverity maps CheeseWAF severities onto Nightingale's numeric
// levels: 1 = Emergency, 2 = Warning, 3 = Notice.
func nightingaleSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "fatal", "emergency", "high", "error":
		return 1
	case "info", "low", "notice", "debug":
		return 3
	default:
		return 2
	}
}

// nightingaleEventKey returns a stable event hash for the alert instance.
func nightingaleEventKey(alert monitor.Alert) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		alert.RuleID, alert.Name, alert.Metric, alert.StartsAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func nightingaleTags(alert monitor.Alert) []string {
	tags := []string{"source=cheesewaf"}
	for _, pair := range nightingaleTagValues(alert) {
		if pair[1] == "" {
			continue
		}
		tags = append(tags, pair[0]+"="+pair[1])
	}
	return tags
}

func nightingaleTagsMap(alert monitor.Alert) map[string]string {
	result := map[string]string{"source": "cheesewaf"}
	for _, pair := range nightingaleTagValues(alert) {
		if pair[1] != "" {
			result[pair[0]] = pair[1]
		}
	}
	return result
}

func nightingaleTagValues(alert monitor.Alert) [][2]string {
	return [][2]string{
		{"rule_id", nightingaleTagValue(alert.RuleID)},
		{"rule_name", nightingaleTagValue(alert.Name)},
		{"severity", nightingaleTagValue(alert.Severity)},
		{"metric", nightingaleTagValue(alert.Metric)},
	}
}

func nightingaleAnnotations(alert monitor.Alert) map[string]string {
	annotations := map[string]string{
		"rule_id":   alert.RuleID,
		"severity":  alert.Severity,
		"metric":    alert.Metric,
		"value":     strconv.FormatFloat(alert.Value, 'g', -1, 64),
		"threshold": strconv.FormatFloat(alert.Threshold, 'g', -1, 64),
	}
	if !alert.StartsAt.IsZero() {
		annotations["starts_at"] = alert.StartsAt.UTC().Format(time.RFC3339)
	}
	if message := strings.TrimSpace(alert.Message); message != "" {
		annotations["message"] = message
	}
	for key, value := range annotations {
		if value == "" {
			delete(annotations, key)
		}
	}
	return annotations
}

// nightingaleTagValue keeps a value on one line so tag parsing stays intact.
func nightingaleTagValue(value string) string {
	value = strings.TrimSpace(value)
	replacer := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
	return strings.TrimSpace(replacer.Replace(value))
}
