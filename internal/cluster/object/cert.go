package object

import "time"

type ClusterCASpec struct {
	CommonName string    `json:"common_name" yaml:"common_name"`
	NotAfter   time.Time `json:"not_after" yaml:"not_after"`
}

type ClusterCAStatus struct {
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Serial      string `json:"serial" yaml:"serial"`
}

type NodeCertificateSpec struct {
	NodeID        string    `json:"node_id" yaml:"node_id"`
	Role          string    `json:"role" yaml:"role"`
	AdvertiseAddr string    `json:"advertise_addr" yaml:"advertise_addr"`
	NotAfter      time.Time `json:"not_after" yaml:"not_after"`
}

type NodeCertificateStatus struct {
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Revoked     bool   `json:"revoked" yaml:"revoked"`
	Reason      string `json:"reason,omitempty" yaml:"reason,omitempty"`
}
