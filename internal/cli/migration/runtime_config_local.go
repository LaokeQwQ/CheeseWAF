package migration

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"gopkg.in/yaml.v3"
)

// decodeRecoveryRuntimeConfig loads only the local fields required to locate
// and authorize recovery. It intentionally avoids config.Validate because
// that validator may resolve configured external AI endpoints.
func decodeRecoveryRuntimeConfig(raw []byte) (*config.Config, error) {
	if len(raw) == 0 || len(raw) > config.MaxConfigFileBytes {
		return nil, ErrRuntimeConfiguration
	}
	candidate := config.Default()
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&candidate); err != nil {
		return nil, ErrRuntimeConfiguration
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrRuntimeConfiguration
	}
	profile := strings.ToLower(strings.TrimSpace(candidate.Storage.Profile))
	if profile == "" {
		profile = config.StorageProfileTemporary
	}
	candidate.Storage.Profile = profile
	switch profile {
	case config.StorageProfileTemporary:
		if strings.TrimSpace(candidate.Storage.SQLite.Path) == "" {
			return nil, ErrRuntimeConfiguration
		}
	case config.StorageProfileProduction:
		if err := validateRecoveryCandidateLocal(&candidate); err != nil {
			return nil, ErrRuntimeConfiguration
		}
	default:
		return nil, ErrRuntimeConfiguration
	}
	return &candidate, nil
}
