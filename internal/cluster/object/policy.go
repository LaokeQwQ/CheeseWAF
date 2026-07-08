package object

type ClusterPolicySpec struct {
	HAMode               string `json:"ha_mode" yaml:"ha_mode"`
	ConsensusProvider    string `json:"consensus_provider" yaml:"consensus_provider"`
	AutoApprovalPolicy   string `json:"auto_approval_policy" yaml:"auto_approval_policy"`
	MaxAutoChangesPerDay int    `json:"max_auto_changes_per_day" yaml:"max_auto_changes_per_day"`
}

type ClusterPolicyStatus struct {
	Healthy              bool   `json:"healthy" yaml:"healthy"`
	CurrentCoordinator   string `json:"current_coordinator,omitempty" yaml:"current_coordinator,omitempty"`
	MajorityConfirmed    bool   `json:"majority_confirmed" yaml:"majority_confirmed"`
	ProtectionModeReason string `json:"protection_mode_reason,omitempty" yaml:"protection_mode_reason,omitempty"`
}
