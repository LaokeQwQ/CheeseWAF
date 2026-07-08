package object

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	APIVersionV1        = "cluster.cheesewaf.io/v1"
	KindNode            = "Node"
	KindJoinToken       = "JoinToken"
	KindClusterPolicy   = "ClusterPolicy"
	KindClusterCA       = "ClusterCA"
	KindNodeCertificate = "NodeCertificate"
)

type Metadata struct {
	ID              string            `json:"id" yaml:"id"`
	Name            string            `json:"name,omitempty" yaml:"name,omitempty"`
	Labels          map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Owner           string            `json:"owner,omitempty" yaml:"owner,omitempty"`
	Generation      int64             `json:"generation" yaml:"generation"`
	ResourceVersion string            `json:"resource_version" yaml:"resource_version"`
	UpdatedAt       time.Time         `json:"updated_at" yaml:"updated_at"`
	LastAppliedHash string            `json:"last_applied_hash" yaml:"last_applied_hash"`
}

type Resource[S any, T any] struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       S        `json:"spec" yaml:"spec"`
	Status     T        `json:"status,omitempty" yaml:"status,omitempty"`
}

func HashSpec(spec any) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func Normalize[S any, T any](res Resource[S, T]) (Resource[S, T], error) {
	if res.APIVersion == "" {
		res.APIVersion = APIVersionV1
	}
	if res.Kind == "" {
		return res, fmt.Errorf("resource kind is required")
	}
	if res.Metadata.ID == "" {
		return res, fmt.Errorf("resource metadata.id is required")
	}
	hash, err := HashSpec(res.Spec)
	if err != nil {
		return res, err
	}
	if res.Metadata.Generation == 0 {
		res.Metadata.Generation = 1
	}
	res.Metadata.LastAppliedHash = hash
	res.Metadata.ResourceVersion = hash[:16]
	res.Metadata.UpdatedAt = time.Now().UTC()
	return res, nil
}

func Key(kind, id string) string {
	return kind + "/" + id
}
