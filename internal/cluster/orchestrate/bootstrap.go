// Package orchestrate implements M2 production-style cluster install/join and rolling upgrade flows.
package orchestrate

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// BootstrapRequest describes a one-shot “install then join” plan for a new node.
type BootstrapRequest struct {
	Role          string `json:"role"`
	NodeID        string `json:"node_id"`
	ControllerURL string `json:"controller_url"`
	AdvertiseAddr string `json:"advertise_addr"`
	TokenTTL      string `json:"token_ttl,omitempty"`
	TokenMaxUses  int    `json:"token_max_uses,omitempty"`
}

// BootstrapPlan is the operator-facing checklist returned after a join token is minted.
type BootstrapPlan struct {
	Role            string    `json:"role"`
	NodeID          string    `json:"node_id"`
	ControllerURL   string    `json:"controller_url"`
	AdvertiseAddr   string    `json:"advertise_addr"`
	TokenID         string    `json:"token_id"`
	TokenValue      string    `json:"token_value,omitempty"`
	TokenExpiresAt  time.Time `json:"token_expires_at,omitempty"`
	JoinCommand     string    `json:"join_command"`
	InstallHint     string    `json:"install_hint"`
	PostJoinHint    string    `json:"post_join_hint"`
	RecommendedNext []string  `json:"recommended_next,omitempty"`
}

// BuildBootstrapPlan validates inputs and builds join CLI guidance. The caller must mint the token.
func BuildBootstrapPlan(req BootstrapRequest, tokenID, tokenValue string, expiresAt time.Time) (BootstrapPlan, error) {
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "waf"
	}
	if role != "waf" && role != "monitor" {
		return BootstrapPlan{}, fmt.Errorf("role must be waf or monitor")
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return BootstrapPlan{}, fmt.Errorf("node_id is required")
	}
	controller := strings.TrimSpace(req.ControllerURL)
	if controller == "" {
		return BootstrapPlan{}, fmt.Errorf("controller_url is required")
	}
	if _, err := url.ParseRequestURI(controller); err != nil {
		return BootstrapPlan{}, fmt.Errorf("controller_url is invalid: %w", err)
	}
	advertise := strings.TrimSpace(req.AdvertiseAddr)
	if advertise == "" {
		return BootstrapPlan{}, fmt.Errorf("advertise_addr is required")
	}
	if strings.TrimSpace(tokenValue) == "" {
		return BootstrapPlan{}, fmt.Errorf("token value is required")
	}
	join := fmt.Sprintf(
		"cheesewaf cluster join --controller %s --token %s --node-id %s --role %s --advertise-addr %s",
		shellQuote(controller),
		shellQuote(tokenValue),
		shellQuote(nodeID),
		shellQuote(role),
		shellQuote(advertise),
	)
	plan := BootstrapPlan{
		Role:           role,
		NodeID:         nodeID,
		ControllerURL:  controller,
		AdvertiseAddr:  advertise,
		TokenID:        strings.TrimSpace(tokenID),
		TokenValue:     tokenValue,
		TokenExpiresAt: expiresAt.UTC(),
		JoinCommand:    join,
		InstallHint:    "Deploy the CheeseWAF binary to the target host (SSH action install or Ansible package), then run the join command on that host.",
		PostJoinHint:   "After join succeeds, start cheesewaf serve (or systemctl start cheesewaf). Monitor nodes should run: cheesewaf cluster monitor-node",
		RecommendedNext: []string{
			"SSH action: install (or Ansible playbook)",
			"Run join command on the new node",
			"Verify /api/cluster/status and node list",
			"If role=monitor: cheesewaf cluster monitor-node",
			"If role=waf: enable traffic after config sync",
		},
	}
	return plan, nil
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if !strings.ContainsAny(value, " \t\n'\"\\$`") {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
