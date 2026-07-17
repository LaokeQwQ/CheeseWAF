package assets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type LocalStore struct {
	root   string
	limits Limits
	fs     *localAssetFS
}

// NewLocalStore opens a local captcha asset root. When allowedRoot is non-empty,
// paths under that root are preferred; absolute operator paths outside the root
// are still accepted after SafeConfigPath validation (no request-controlled input).
func NewLocalStore(root string, limits Limits, allowedRoot ...string) (*LocalStore, error) {
	var (
		abs string
		err error
	)
	if len(allowedRoot) > 0 && strings.TrimSpace(allowedRoot[0]) != "" {
		abs, err = safeConfigPathUnderRoot(root, allowedRoot[0])
		if err != nil {
			abs, err = safeConfigPath(root)
		}
	} else {
		abs, err = safeConfigPath(root)
	}
	if err != nil {
		return nil, fmt.Errorf("captcha asset root: %w", err)
	}
	fs, err := openLocalAssetFS(abs)
	if err != nil {
		return nil, fmt.Errorf("open captcha asset root: %w", err)
	}
	return &LocalStore{root: abs, limits: limits.normalized(), fs: fs}, nil
}

func (s *LocalStore) Close() error {
	if s == nil || s.fs == nil {
		return nil
	}
	return s.fs.Close()
}

func (s *LocalStore) Put(ctx context.Context, req PutRequest) (Asset, error) {
	if err := ctx.Err(); err != nil {
		return Asset{}, err
	}
	data, ct, err := validate(req.Kind, req.Name, req.ContentType, req.Reader, s.limits)
	if err != nil {
		return Asset{}, err
	}
	id, err := randomID()
	if err != nil {
		return Asset{}, err
	}
	sum := sha256.Sum256(data)
	a := Asset{ID: id, Kind: req.Kind, Name: safeDisplayName(req.Name), ContentType: ct, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()}
	if err = s.fs.ensureKind(req.Kind); err != nil {
		return Asset{}, err
	}
	meta, err := json.Marshal(a)
	if err != nil {
		return Asset{}, err
	}
	if err = s.fs.atomicWrite(req.Kind, id+".bin", data, 0o600); err != nil {
		return Asset{}, err
	}
	if err = s.fs.atomicWrite(req.Kind, id+".json", meta, 0o600); err != nil {
		_ = s.fs.remove(req.Kind, id+".bin")
		return Asset{}, err
	}
	return a, nil
}
func (s *LocalStore) Open(ctx context.Context, id string) (Asset, io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return Asset{}, nil, err
	}
	if !validID(id) {
		return Asset{}, nil, ErrNotFound
	}
	a, kind, err := s.find(id)
	if err != nil {
		return Asset{}, nil, err
	}
	f, err := s.fs.open(kind, id+".bin")
	if errors.Is(err, os.ErrNotExist) {
		return Asset{}, nil, ErrNotFound
	}
	if err != nil {
		return Asset{}, nil, err
	}
	data, verifyErr := readAndVerifyStoredAsset(f, a, s.limits)
	_ = f.Close()
	if verifyErr != nil {
		return Asset{}, nil, verifyErr
	}
	return a, io.NopCloser(bytes.NewReader(data)), nil
}
func (s *LocalStore) List(ctx context.Context, kind Kind) ([]Asset, error) {
	kinds := allKinds()
	if kind != "" {
		if !knownKind(kind) {
			return nil, ErrInvalidAsset
		}
		kinds = []Kind{kind}
	}
	var out []Asset
	for _, k := range kinds {
		entries, err := s.fs.readDir(k)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			a, readErr := s.readMetadata(k, e.Name())
			if readErr != nil {
				continue
			}
			expectedID := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			if !validID(expectedID) || a.ID != expectedID || a.Kind != k {
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
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *LocalStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validID(id) {
		return ErrNotFound
	}
	_, kind, err := s.find(id)
	if err != nil {
		return err
	}
	if err = s.fs.remove(kind, id+".bin"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = s.fs.remove(kind, id+".json"); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	return nil
}
func (s *LocalStore) find(id string) (Asset, Kind, error) {
	for _, k := range allKinds() {
		a, err := s.readMetadata(k, id+".json")
		if err == nil && a.ID == id {
			return a, k, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Asset{}, "", err
		}
	}
	return Asset{}, "", ErrNotFound
}
func (s *LocalStore) readMetadata(kind Kind, name string) (Asset, error) {
	data, err := s.fs.readFile(kind, name, 64<<10)
	if err != nil {
		return Asset{}, err
	}
	var a Asset
	if err = json.Unmarshal(data, &a); err != nil {
		return Asset{}, err
	}
	return a, nil
}
func allKinds() []Kind { return []Kind{KindBackground, KindFont, KindIcon, KindLogo} }
func knownKind(k Kind) bool {
	for _, v := range allKinds() {
		if k == v {
			return true
		}
	}
	return false
}
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func validID(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func safeDisplayName(v string) string {
	v = filepath.Base(strings.TrimSpace(v))
	if v == "." || v == string(filepath.Separator) || v == "" {
		return "asset"
	}
	if len(v) > 255 {
		v = v[:255]
	}
	return v
}
