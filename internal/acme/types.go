package acme

import (
	"context"
	"time"
)

type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepSucceeded StepStatus = "succeeded"
	StepFailed    StepStatus = "failed"
)

type Event struct {
	Step      string     `json:"step"`
	Status    StepStatus `json:"status"`
	Message   string     `json:"message,omitempty"`
	Output    string     `json:"output,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

type DNSProvider struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	API     string            `json:"api"`
	Env     map[string]string `json:"env,omitempty"`
	Enabled bool              `json:"enabled"`
}

type IssueRequest struct {
	SiteID       string            `json:"site_id"`
	Domains      []string          `json:"domains"`
	ProviderID   string            `json:"provider_id"`
	DNSAPI       string            `json:"dns_api"`
	DNSEnv       map[string]string `json:"dns_env"`
	AccountEmail string            `json:"account_email"`
	Server       string            `json:"server"`
	KeyType      string            `json:"key_type"`
	ACMESHPath   string            `json:"acme_sh_path"`
	Home         string            `json:"home"`
	CertDir      string            `json:"cert_dir"`
	ReloadCmd    string            `json:"reload_cmd"`
	AutoRenew    bool              `json:"auto_renew"`
	Notify       bool              `json:"notify"`
}

type IssueResult struct {
	RunID       string    `json:"run_id"`
	SiteID      string    `json:"site_id"`
	Domains     []string  `json:"domains"`
	CertFile    string    `json:"cert_file"`
	KeyFile     string    `json:"key_file"`
	Fullchain   string    `json:"fullchain"`
	KeyType     string    `json:"key_type"`
	Server      string    `json:"server"`
	DNSAPI      string    `json:"dns_api"`
	Events      []Event   `json:"events"`
	IssuedAt    time.Time `json:"issued_at"`
	RenewAfter  time.Time `json:"renew_after,omitempty"`
	AutoRenew   bool      `json:"auto_renew"`
	Notify      bool      `json:"notify"`
	ElapsedMS   int64     `json:"elapsed_ms"`
	ProviderID  string    `json:"provider_id,omitempty"`
	PrimaryName string    `json:"primary_name"`
}

type Issuer interface {
	Providers() []DNSProvider
	Issue(ctx context.Context, req IssueRequest) (IssueResult, error)
}
