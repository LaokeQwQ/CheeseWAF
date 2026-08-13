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
	"sync"
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
	mu     sync.Mutex
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
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	count, totalBytes, err := s.usage(ctx)
	if err != nil {
		return Asset{}, err
	}
	if !s.limits.allows(count, totalBytes, a.Size) {
		return Asset{}, ErrQuotaExceeded
	}
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
	ctx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	prefix := s.config.Prefix
	if kind != "" {
		prefix = path.Join(prefix, string(kind))
	}
	objects, err := s.listObjects(ctx, prefix)
	if err != nil {
		return nil, err
	}
	binSizes := make(map[string]int64)
	for _, obj := range objects {
		objKind, id, ext, ok := s.parseKey(obj.Key)
		if ok && ext == "bin" && (kind == "" || objKind == kind) {
			if obj.Size < 0 {
				continue
			}
			binSizes[s.key(objKind, id, "bin")] = obj.Size
		}
	}
	var out []Asset
	for _, obj := range objects {
		if !strings.HasSuffix(obj.Key, ".json") {
			continue
		}
		objKind, objID, ext, keyOK := s.parseKey(obj.Key)
		if !keyOK || ext != "json" || (kind != "" && objKind != kind) {
			continue
		}
		r, getErr := s.client.GetObject(ctx, s.config.Bucket, obj.Key)
		if getErr != nil {
			if errors.Is(getErr, ErrNotFound) {
				continue
			}
			return nil, getErr
		}
		data, readErr := readBoundedS3Metadata(r)
		_ = r.Close()
		if readErr != nil {
			return nil, readErr
		}
		var a Asset
		if json.Unmarshal(data, &a) != nil || validateStoredMetadata(a, objKind, objID, s.limits) != nil {
			continue
		}
		if obj.Key != s.key(a.Kind, a.ID, "json") {
			continue
		}
		if !hmac.Equal([]byte(a.MetadataMAC), []byte(s.metadataMAC(a))) {
			continue
		}
		if size, ok := binSizes[s.key(a.Kind, a.ID, "bin")]; !ok || size != a.Size {
			continue
		}
		if len(out) >= s.limits.MaxAssets {
			return nil, ErrQuotaExceeded
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *S3Store) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	a, _, err := s.find(ctx, id)
	if err != nil {
		return err
	}
	if err = s.client.DeleteObject(ctx, s.config.Bucket, s.key(a.Kind, id, "bin")); err != nil {
		return err
	}
	return s.client.DeleteObject(ctx, s.config.Bucket, s.key(a.Kind, id, "json"))
}

func (s *S3Store) usage(ctx context.Context) (int, int64, error) {
	objects, err := s.listObjects(ctx, s.config.Prefix)
	if err != nil {
		return 0, 0, err
	}
	var count int
	var totalBytes int64
	for _, obj := range objects {
		kind, id, ext, ok := s.parseKey(obj.Key)
		if !ok || ext != "bin" || !knownKind(kind) || !validID(id) {
			continue
		}
		if obj.Size < 0 || totalBytes > int64(^uint64(0)>>1)-obj.Size {
			return 0, 0, ErrQuotaExceeded
		}
		count++
		totalBytes += obj.Size
		if count > s.limits.MaxAssets || totalBytes > s.limits.MaxTotalBytes {
			return count, totalBytes, nil
		}
	}
	return count, totalBytes, nil
}

func (s *S3Store) listObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	maxObjects := s.limits.MaxAssets*2 + 1
	if maxObjects < 1 || maxObjects > 10_000 {
		maxObjects = 10_000
	}
	if limited, ok := s.client.(LimitedObjectClient); ok {
		objects, err := limited.ListObjectsLimited(ctx, s.config.Bucket, prefix, maxObjects)
		if errors.Is(err, errObjectListLimit) {
			return nil, fmt.Errorf("%w: %v", ErrQuotaExceeded, err)
		}
		return objects, err
	}
	objects, err := s.client.ListObjects(ctx, s.config.Bucket, prefix)
	if err != nil {
		return nil, err
	}
	if len(objects) > maxObjects {
		return nil, fmt.Errorf("%w: object enumeration exceeds configured bound", ErrQuotaExceeded)
	}
	return objects, nil
}

func (s *S3Store) parseKey(key string) (Kind, string, string, bool) {
	prefix := strings.Trim(s.config.Prefix, "/")
	rel := key
	if prefix != "" {
		if !strings.HasPrefix(key, prefix+"/") {
			return "", "", "", false
		}
		rel = strings.TrimPrefix(key, prefix+"/")
	}
	parts := strings.Split(rel, "/")
	if len(parts) != 2 {
		return "", "", "", false
	}
	name := parts[1]
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 || dot == len(name)-1 {
		return "", "", "", false
	}
	kind := Kind(parts[0])
	id, ext := name[:dot], name[dot+1:]
	return kind, id, ext, knownKind(kind) && validID(id) && (ext == "bin" || ext == "json")
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
