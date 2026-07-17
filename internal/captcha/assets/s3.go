package assets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint             string        `yaml:"endpoint" json:"endpoint"`
	Region               string        `yaml:"region" json:"region"`
	Bucket               string        `yaml:"bucket" json:"bucket"`
	Prefix               string        `yaml:"prefix" json:"prefix"`
	AccessKeyFile        string        `yaml:"access_key_file" json:"access_key_file"`
	SecretKeyFile        string        `yaml:"secret_key_file" json:"secret_key_file"`
	SessionTokenFile     string        `yaml:"session_token_file" json:"session_token_file"`
	PathStyle            bool          `yaml:"path_style" json:"path_style"`
	UseTLS               bool          `yaml:"use_tls" json:"use_tls"`
	AllowPrivateEndpoint bool          `yaml:"allow_private_endpoint" json:"allow_private_endpoint"`
	MetadataKey          []byte        `yaml:"-" json:"-"`
	RequestTimeout       time.Duration `yaml:"request_timeout" json:"request_timeout"`
}

type S3Store struct {
	config S3Config
	client ObjectClient
	limits Limits
}

func NewS3Store(cfg S3Config, client ObjectClient, limits Limits) (*S3Store, error) {
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	if cfg.Bucket == "" || client == nil {
		return nil, fmt.Errorf("captcha S3 bucket and client are required")
	}
	if len(cfg.MetadataKey) < 32 {
		return nil, fmt.Errorf("captcha S3 metadata integrity key must contain at least 32 bytes")
	}
	cfg.Prefix = strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	return &S3Store{config: cfg, client: client, limits: limits.normalized()}, nil
}
func (s *S3Store) Put(ctx context.Context, req PutRequest) (Asset, error) {
	data, ct, err := validate(req.Kind, req.Name, req.ContentType, req.Reader, s.limits)
	if err != nil {
		return Asset{}, err
	}
	id, err := randomID()
	if err != nil {
		return Asset{}, err
	}
	a := newAsset(id, req.Kind, req.Name, ct, data)
	a.MetadataMAC = s.metadataMAC(a)
	meta, err := json.Marshal(a)
	if err != nil {
		return Asset{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	if err = s.client.PutObject(ctx, s.config.Bucket, s.key(req.Kind, id, "bin"), ct, bytes.NewReader(data), int64(len(data))); err != nil {
		return Asset{}, err
	}
	if err = s.client.PutObject(ctx, s.config.Bucket, s.key(req.Kind, id, "json"), "application/json", bytes.NewReader(meta), int64(len(meta))); err != nil {
		_ = s.client.DeleteObject(context.Background(), s.config.Bucket, s.key(req.Kind, id, "bin"))
		return Asset{}, err
	}
	return a, nil
}
func (s *S3Store) Open(ctx context.Context, id string) (Asset, io.ReadCloser, error) {
	if !validID(id) {
		return Asset{}, nil, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	a, k, err := s.find(ctx, id)
	if err != nil {
		return Asset{}, nil, err
	}
	r, err := s.client.GetObject(ctx, s.config.Bucket, strings.TrimSuffix(k, ".json")+".bin")
	if err != nil {
		return Asset{}, nil, err
	}
	data, err := readAndVerifyStoredAsset(r, a, s.limits)
	_ = r.Close()
	if err != nil {
		return Asset{}, nil, err
	}
	return a, io.NopCloser(bytes.NewReader(data)), nil
}

func (s *S3Store) List(ctx context.Context, kind Kind) ([]Asset, error) {
	if kind != "" && !knownKind(kind) {
		return nil, ErrInvalidAsset
	}
	prefix := s.config.Prefix
	if kind != "" {
		prefix = path.Join(prefix, string(kind))
	}
	objects, err := s.client.ListObjects(ctx, s.config.Bucket, prefix)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for _, obj := range objects {
		if !strings.HasSuffix(obj.Key, ".json") {
			continue
		}
		r, getErr := s.client.GetObject(ctx, s.config.Bucket, obj.Key)
		if getErr != nil {
			return nil, getErr
		}
		data, readErr := readBoundedS3Metadata(r)
		_ = r.Close()
		if readErr != nil {
			return nil, readErr
		}
		var a Asset
		if json.Unmarshal(data, &a) != nil || !validID(a.ID) || !knownKind(a.Kind) {
			continue
		}
		if kind != "" && a.Kind != kind {
			continue
		}
		if obj.Key != s.key(a.Kind, a.ID, "json") {
			continue
		}
		verified, body, openErr := s.Open(ctx, a.ID)
		if openErr != nil {
			if errors.Is(openErr, ErrInvalidAsset) || errors.Is(openErr, ErrNotFound) {
				continue
			}
			return nil, openErr
		}
		_ = body.Close()
		out = append(out, verified)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *S3Store) Delete(ctx context.Context, id string) error {
	a, _, err := s.find(ctx, id)
	if err != nil {
		return err
	}
	if err = s.client.DeleteObject(ctx, s.config.Bucket, s.key(a.Kind, id, "bin")); err != nil {
		return err
	}
	return s.client.DeleteObject(ctx, s.config.Bucket, s.key(a.Kind, id, "json"))
}
func (s *S3Store) find(ctx context.Context, id string) (Asset, string, error) {
	for _, kind := range allKinds() {
		key := s.key(kind, id, "json")
		r, err := s.client.GetObject(ctx, s.config.Bucket, key)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return Asset{}, "", err
		}
		data, readErr := readBoundedS3Metadata(r)
		_ = r.Close()
		if readErr != nil {
			return Asset{}, "", readErr
		}
		var a Asset
		if json.Unmarshal(data, &a) == nil && a.ID == id && a.Kind == kind {
			if !hmac.Equal([]byte(a.MetadataMAC), []byte(s.metadataMAC(a))) {
				return Asset{}, "", fmt.Errorf("%w: S3 metadata integrity check failed", ErrInvalidAsset)
			}
			return a, key, nil
		}
	}
	return Asset{}, "", ErrNotFound
}

func readBoundedS3Metadata(r io.Reader) ([]byte, error) {
	const maxMetadataBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(r, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("%w: object metadata exceeds %d bytes", ErrInvalidAsset, maxMetadataBytes)
	}
	return data, nil
}
func (s *S3Store) key(kind Kind, id, ext string) string {
	return path.Join(s.config.Prefix, string(kind), id+"."+ext)
}

func (s *S3Store) metadataMAC(a Asset) string {
	unsigned := a
	unsigned.MetadataMAC = ""
	data, _ := json.Marshal(unsigned)
	mac := hmac.New(sha256.New, s.config.MetadataKey)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
