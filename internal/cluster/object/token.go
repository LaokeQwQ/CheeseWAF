package object

import "time"

type JoinTokenSpec struct {
	TokenID   string    `json:"token_id" yaml:"token_id"`
	Role      string    `json:"role" yaml:"role"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
	MaxUses   int       `json:"max_uses" yaml:"max_uses"`
}

type JoinTokenStatus struct {
	UsedCount int    `json:"used_count" yaml:"used_count"`
	Revoked   bool   `json:"revoked" yaml:"revoked"`
	Reason    string `json:"reason,omitempty" yaml:"reason,omitempty"`
}
