package materializer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"gopkg.in/yaml.v3"
)

const (
	BaselineName          = "previous-config.json"
	RuntimeReceiptName    = "runtime-receipt.json"
	baselineSchema        = "materializer.baseline.v1"
	runtimeReceiptSchema  = "materializer.runtime.v1"
	maxDurableStateBytes  = 4 << 20
	defaultRuntimeTimeout = 30 * time.Second
)

type configSnapshot struct {
	YAML                       []byte `json:"yaml"`
	AssistantPrivateAPIBaseSet bool   `json:"assistant_private_api_base_set"`
	ReasoningPrivateAPIBaseSet bool   `json:"reasoning_private_api_base_set"`
	APISecurityJWKSCacheRoot   string `json:"api_security_jwks_cache_root"`
}

type Baseline struct {
	Schema         string         `json:"schema"`
	Commit         CommitIdentity `json:"commit"`
	PreviousDigest string         `json:"previous_digest"`
	TargetDigest   string         `json:"target_digest"`
	Previous       configSnapshot `json:"previous"`
	Target         configSnapshot `json:"target"`
}

type RuntimeReceipt struct {
	Schema         string         `json:"schema"`
	Commit         CommitIdentity `json:"commit"`
	ConfigDigest   string         `json:"config_digest"`
	IdempotencyKey string         `json:"idempotency_key"`
}

type RuntimeState string

const (
	RuntimeStateUnknown  RuntimeState = "unknown"
	RuntimeStatePrevious RuntimeState = "previous"
	RuntimeStateTarget   RuntimeState = "target"
)

type RuntimeRequest struct {
	Commit         CommitIdentity
	IdempotencyKey string
	ConfigDigest   string
	Config         *config.Config
}

type RuntimeController interface {
	Query(context.Context, RuntimeRequest, RuntimeRequest) (RuntimeState, error)
	Apply(context.Context, RuntimeRequest) error
}

func ConfigDigest(cfg *config.Config) (string, error) {
	_, digest, err := encodeConfigSnapshot(cfg)
	return digest, err
}

func NewRuntimeReceipt(request RuntimeRequest) (RuntimeReceipt, error) {
	if err := validateRuntimeRequest(request); err != nil {
		return RuntimeReceipt{}, err
	}
	receipt := RuntimeReceipt{Schema: runtimeReceiptSchema, Commit: request.Commit, ConfigDigest: request.ConfigDigest, IdempotencyKey: request.IdempotencyKey}
	if err := receipt.Validate(); err != nil {
		return RuntimeReceipt{}, err
	}
	return receipt, nil
}

func (r RuntimeReceipt) Matches(request RuntimeRequest) bool {
	return r.Schema == runtimeReceiptSchema && r.Commit == request.Commit && r.ConfigDigest == request.ConfigDigest && r.IdempotencyKey == request.IdempotencyKey
}

func (r RuntimeReceipt) Validate() error {
	if r.Schema != runtimeReceiptSchema || r.ConfigDigest == "" || !controlplane.ValidIdentity(r.IdempotencyKey) {
		return fmt.Errorf("%w: runtime receipt is invalid", ErrReceiptCorrupt)
	}
	if !controlplane.ValidIdentity(r.Commit.ClusterID) || !controlplane.ValidIdentity(r.Commit.LeaderID) || !controlplane.ValidIdentity(r.Commit.Version) || !controlplane.ValidIdentity(r.Commit.Nonce) || r.Commit.Epoch == 0 || r.Commit.Revision == 0 || r.Commit.Digest == "" {
		return fmt.Errorf("%w: runtime receipt commit identity is invalid", ErrReceiptCorrupt)
	}
	return nil
}

func newBaseline(receipt Receipt, previous, target *config.Config) (Baseline, error) {
	previousSnapshot, previousDigest, err := encodeConfigSnapshot(previous)
	if err != nil {
		return Baseline{}, fmt.Errorf("encode previous config baseline: %w", err)
	}
	targetSnapshot, targetDigest, err := encodeConfigSnapshot(target)
	if err != nil {
		return Baseline{}, fmt.Errorf("encode target config baseline: %w", err)
	}
	baseline := Baseline{
		Schema:         baselineSchema,
		Commit:         receipt.Commit,
		PreviousDigest: previousDigest,
		TargetDigest:   targetDigest,
		Previous:       previousSnapshot,
		Target:         targetSnapshot,
	}
	if err := baseline.Validate(receipt); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func (b Baseline) Validate(receipt Receipt) error {
	if b.Schema != baselineSchema || b.Commit != receipt.Commit {
		return fmt.Errorf("%w: baseline is not bound to exact commit", ErrReceiptCorrupt)
	}
	_, previousDigest, err := decodeConfigSnapshot(b.Previous)
	if err != nil || previousDigest != b.PreviousDigest {
		return fmt.Errorf("%w: previous config baseline digest mismatch: %v", ErrReceiptCorrupt, err)
	}
	_, targetDigest, err := decodeConfigSnapshot(b.Target)
	if err != nil || targetDigest != b.TargetDigest {
		return fmt.Errorf("%w: target config baseline digest mismatch: %v", ErrReceiptCorrupt, err)
	}
	return nil
}

func (b Baseline) Configs(receipt Receipt) (previous, target *config.Config, err error) {
	if err := b.Validate(receipt); err != nil {
		return nil, nil, err
	}
	previous, _, err = decodeConfigSnapshot(b.Previous)
	if err != nil {
		return nil, nil, err
	}
	target, _, err = decodeConfigSnapshot(b.Target)
	if err != nil {
		return nil, nil, err
	}
	return previous, target, nil
}

func runtimeRequest(receipt Receipt, cfg *config.Config, digest string) RuntimeRequest {
	return RuntimeRequest{
		Commit:         receipt.Commit,
		IdempotencyKey: receipt.Commit.ClusterID + ":" + fmt.Sprint(receipt.Commit.Epoch) + ":" + fmt.Sprint(receipt.Commit.Revision) + ":" + receipt.Commit.Nonce + ":" + digest,
		ConfigDigest:   digest,
		Config:         cfg,
	}
}

func validateRuntimeRequest(request RuntimeRequest) error {
	if request.Config == nil || request.ConfigDigest == "" || !controlplane.ValidIdentity(request.IdempotencyKey) {
		return fmt.Errorf("%w: runtime request is incomplete", ErrReceiptCorrupt)
	}
	_, digest, err := encodeConfigSnapshot(request.Config)
	if err != nil {
		return err
	}
	if digest != request.ConfigDigest {
		return fmt.Errorf("%w: runtime config digest mismatch", ErrReceiptCorrupt)
	}
	return nil
}

func encodeConfigSnapshot(cfg *config.Config) (configSnapshot, string, error) {
	if cfg == nil {
		return configSnapshot{}, "", ErrMissingPrevious
	}
	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return configSnapshot{}, "", err
	}
	snapshot := configSnapshot{
		YAML:                       yamlBytes,
		AssistantPrivateAPIBaseSet: cfg.AI.Assistant.AllowPrivateAPIBaseSet,
		ReasoningPrivateAPIBaseSet: cfg.AI.Reasoning.AllowPrivateAPIBaseSet,
		APISecurityJWKSCacheRoot:   cfg.APISec.Auth.JWKSCacheRoot,
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return configSnapshot{}, "", err
	}
	sum := sha256.Sum256(canonical)
	return snapshot, hex.EncodeToString(sum[:]), nil
}

func decodeConfigSnapshot(snapshot configSnapshot) (*config.Config, string, error) {
	if len(snapshot.YAML) == 0 {
		return nil, "", errors.New("config snapshot YAML is empty")
	}
	var cfg config.Config
	if err := yaml.Unmarshal(snapshot.YAML, &cfg); err != nil {
		return nil, "", err
	}
	reencoded, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(reencoded, snapshot.YAML) {
		return nil, "", errors.New("config snapshot YAML is not canonical")
	}
	cfg.AI.Assistant.AllowPrivateAPIBaseSet = snapshot.AssistantPrivateAPIBaseSet
	cfg.AI.Reasoning.AllowPrivateAPIBaseSet = snapshot.ReasoningPrivateAPIBaseSet
	cfg.APISec.Auth.JWKSCacheRoot = snapshot.APISecurityJWKSCacheRoot
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return &cfg, hex.EncodeToString(sum[:]), nil
}

func encodeCanonical(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxDurableStateBytes {
		return nil, fmt.Errorf("%w: durable materializer state size is invalid", ErrReceiptCorrupt)
	}
	return data, nil
}

func decodeCanonical(data []byte, value any) error {
	if len(data) == 0 || len(data) > maxDurableStateBytes {
		return fmt.Errorf("%w: durable materializer state size is invalid", ErrReceiptCorrupt)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: decode durable materializer state: %v", ErrReceiptCorrupt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: durable materializer state has trailing JSON", ErrReceiptCorrupt)
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return fmt.Errorf("%w: durable materializer state is not canonical", ErrReceiptCorrupt)
	}
	return nil
}

func (s *JournalStore) SaveBaselineContext(ctx context.Context, receipt Receipt, baseline Baseline) error {
	if err := baseline.Validate(receipt); err != nil {
		return err
	}
	data, err := encodeCanonical(baseline)
	if err != nil {
		return err
	}
	return s.saveExactFileContext(ctx, BaselineName, data)
}

func (s *JournalStore) LoadBaselineContext(ctx context.Context, receipt Receipt) (baseline Baseline, err error) {
	data, err := s.loadExactFileContext(ctx, BaselineName)
	if err != nil {
		return Baseline{}, err
	}
	if err := decodeCanonical(data, &baseline); err != nil {
		return Baseline{}, err
	}
	if err := baseline.Validate(receipt); err != nil {
		return Baseline{}, err
	}
	return baseline, nil
}

func (s *JournalStore) DeleteBaselineContext(ctx context.Context, receipt Receipt) error {
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		path := filepath.Join(s.dir, BaselineName)
		data, err := readPrivateFile(path, maxDurableStateBytes)
		if errors.Is(err, os.ErrNotExist) {
			return s.hooks.SyncDir(s.dir)
		}
		if err != nil {
			return err
		}
		var baseline Baseline
		if err := decodeCanonical(data, &baseline); err != nil {
			return err
		}
		if err := baseline.Validate(receipt); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove previous config baseline: %w", err)
		}
		if err := s.hooks.SyncDir(s.dir); err != nil {
			return fmt.Errorf("sync baseline removal: %w", err)
		}
		return nil
	})
}

func (s *JournalStore) SaveRuntimeReceiptContext(ctx context.Context, receipt RuntimeReceipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	data, err := encodeCanonical(receipt)
	if err != nil {
		return err
	}
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		path := filepath.Join(s.dir, RuntimeReceiptName)
		currentData, readErr := readPrivateFile(path, maxDurableStateBytes)
		if readErr == nil {
			var current RuntimeReceipt
			if err := decodeCanonical(currentData, &current); err != nil {
				return err
			}
			if newerCommitIdentity(current.Commit, receipt.Commit) {
				return ErrStaleRevision
			}
			if current.Commit.Epoch == receipt.Commit.Epoch && current.Commit.Revision == receipt.Commit.Revision && (current.Commit != receipt.Commit || current.ConfigDigest != receipt.ConfigDigest || current.IdempotencyKey != receipt.IdempotencyKey) {
				return ErrCommitConflict
			}
			if bytes.Equal(currentData, data) {
				return s.hooks.SyncDir(s.dir)
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		return s.writeOne(RuntimeReceiptName, data)
	})
}

func (s *JournalStore) LoadRuntimeReceiptContext(ctx context.Context) (receipt RuntimeReceipt, err error) {
	data, err := s.loadExactFileContext(ctx, RuntimeReceiptName)
	if err != nil {
		return RuntimeReceipt{}, err
	}
	if err := decodeCanonical(data, &receipt); err != nil {
		return RuntimeReceipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return RuntimeReceipt{}, err
	}
	return receipt, nil
}

func (s *JournalStore) saveExactFileContext(ctx context.Context, name string, data []byte) error {
	return s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		path := filepath.Join(s.dir, name)
		current, err := readPrivateFile(path, maxDurableStateBytes)
		if err == nil {
			if !bytes.Equal(current, data) {
				return ErrCommitConflict
			}
			return s.hooks.SyncDir(s.dir)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return s.writeOne(name, data)
	})
}

func (s *JournalStore) loadExactFileContext(ctx context.Context, name string) (data []byte, err error) {
	err = s.withDirectoryLease(ctx, func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		data, err = readPrivateFile(filepath.Join(s.dir, name), maxDurableStateBytes)
		if errors.Is(err, os.ErrNotExist) {
			return ErrReceiptNotFound
		}
		return err
	})
	return data, err
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	if err := validateTargetPath(path, false); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: durable state file is not a regular 0600 file", ErrReceiptUnsafe)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: durable state file is too large", ErrReceiptCorrupt)
	}
	return data, nil
}

func newerCommitIdentity(a, b CommitIdentity) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	return a.Revision > b.Revision
}
