package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type Client struct {
	apiBase      string
	apiKey       string
	apiKeyHeader string
	model        string
	http         *http.Client
}

func NewClient(cfg config.AIConfig, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		apiBase:      strings.TrimRight(cfg.APIBase, "/"),
		apiKey:       cfg.APIKey,
		apiKeyHeader: normalizeAPIKeyHeader(cfg.APIKeyHeader),
		model:        cfg.Model,
		http:         httpClient,
	}
}

func (c *Client) Complete(ctx context.Context, messages []Message) (string, error) {
	if c == nil {
		return "", fmt.Errorf("ai client is nil")
	}
	if c.apiBase == "" {
		return "", fmt.Errorf("ai api_base is required")
	}
	if c.model == "" {
		return "", fmt.Errorf("ai model is required")
	}
	payload := chatRequest{Model: c.model, Messages: messages, Temperature: 0.2}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		c.applyAPIKey(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("ai api returned %s", resp.Status)
	}
	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("ai api returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func (c *Client) applyAPIKey(req *http.Request) {
	switch strings.ToLower(c.apiKeyHeader) {
	case "", "authorization", "bearer", "authorization-bearer":
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	default:
		req.Header.Set(c.apiKeyHeader, c.apiKey)
	}
}

func normalizeAPIKeyHeader(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return "authorization"
	}
	return header
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}
