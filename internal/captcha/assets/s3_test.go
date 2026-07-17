package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

type memoryObjectClient struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemoryObjectClient() *memoryObjectClient {
	return &memoryObjectClient{objects: map[string][]byte{}}
}
func (m *memoryObjectClient) PutObject(_ context.Context, bucket, key, _ string, body io.Reader, _ int64) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[bucket+"/"+key] = data
	return nil
}
func (m *memoryObjectClient) GetObject(_ context.Context, bucket, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), data...))), nil
}
func (m *memoryObjectClient) DeleteObject(_ context.Context, bucket, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	full := bucket + "/" + key
	if _, ok := m.objects[full]; !ok {
		return ErrNotFound
	}
	delete(m.objects, full)
	return nil
}
func (m *memoryObjectClient) ListObjects(_ context.Context, bucket, prefix string) ([]ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []ObjectInfo
	needle := bucket + "/" + prefix
	for k, v := range m.objects {
		if strings.HasPrefix(k, needle) {
			out = append(out, ObjectInfo{Key: strings.TrimPrefix(k, bucket+"/"), Size: int64(len(v))})
		}
	}
	return out, nil
}

func TestS3StoreUsesNamespacedOpaqueKeys(t *testing.T) {
	client := newMemoryObjectClient()
	store, err := NewS3Store(testS3Config(), client, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindLogo, Name: "../../cheesewaf-logo.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	for key := range client.objects {
		if strings.Contains(key, "..") || strings.Contains(key, "cheesewaf-logo.png") {
			t.Fatalf("client filename leaked into object key: %s", key)
		}
	}
	if !strings.HasPrefix(a.Name, "cheesewaf-logo") {
		t.Fatalf("unexpected display name %q", a.Name)
	}
	_, r, err := store.Open(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	items, err := store.List(context.Background(), KindLogo)
	if err != nil || len(items) != 1 {
		t.Fatalf("list failed: %v %#v", err, items)
	}
	if err = store.Delete(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Open(context.Background(), a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}
func TestS3StoreRequiresInjectedClientAndBucket(t *testing.T) {
	if _, err := NewS3Store(S3Config{}, nil, Limits{}); err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestS3StoreOpenRejectsTamperedObjectContent(t *testing.T) {
	client, store, asset := putS3TestImage(t)
	key := "captcha-assets/private/captcha/icon/" + asset.ID + ".bin"
	client.mu.Lock()
	client.objects[key][len(client.objects[key])-1] ^= 0xff
	client.mu.Unlock()

	if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
		t.Fatalf("tampered object must be rejected before returning a body: body=%v err=%v", body, err)
	}
}

func TestS3StoreOpenRejectsTamperedMetadata(t *testing.T) {
	client, store, asset := putS3TestImage(t)
	metaKey := "captcha-assets/private/captcha/icon/" + asset.ID + ".json"
	client.mu.Lock()
	var metadata Asset
	if err := json.Unmarshal(client.objects[metaKey], &metadata); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	metadata.ContentType = "image/jpeg"
	client.objects[metaKey], _ = json.Marshal(metadata)
	client.mu.Unlock()

	if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
		t.Fatalf("mismatched metadata MIME must be rejected: body=%v err=%v", body, err)
	}
}

func TestS3StoreOpenRejectsMetadataLengthAndDigestTampering(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*Asset)
	}{
		{name: "length", fn: func(a *Asset) { a.Size++ }},
		{name: "digest", fn: func(a *Asset) { a.SHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			client, store, asset := putS3TestImage(t)
			metaKey := "captcha-assets/private/captcha/icon/" + asset.ID + ".json"
			client.mu.Lock()
			var metadata Asset
			if err := json.Unmarshal(client.objects[metaKey], &metadata); err != nil {
				client.mu.Unlock()
				t.Fatal(err)
			}
			mutate.fn(&metadata)
			client.objects[metaKey], _ = json.Marshal(metadata)
			client.mu.Unlock()

			if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
				t.Fatalf("tampered %s metadata must be rejected: body=%v err=%v", mutate.name, body, err)
			}
		})
	}
}

func TestS3StoreRejectsCoordinatedBodyAndMetadataReplacement(t *testing.T) {
	client, store, asset := putS3TestImage(t)
	bodyKey := "captcha-assets/private/captcha/icon/" + asset.ID + ".bin"
	metaKey := "captcha-assets/private/captcha/icon/" + asset.ID + ".json"
	replacement := pngData(t, 9, 9)

	client.mu.Lock()
	var metadata Asset
	if err := json.Unmarshal(client.objects[metaKey], &metadata); err != nil {
		client.mu.Unlock()
		t.Fatal(err)
	}
	metadata.Size = int64(len(replacement))
	metadata.SHA256 = fmt.Sprintf("%x", sha256.Sum256(replacement))
	client.objects[bodyKey] = replacement
	client.objects[metaKey], _ = json.Marshal(metadata)
	client.mu.Unlock()

	if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
		t.Fatalf("coordinated object replacement must be rejected by the independent metadata key: body=%v err=%v", body, err)
	}
}
func TestS3StoreOpenRejectsOversizedObjectStream(t *testing.T) {
	limits := Limits{MaxImageBytes: 128, MaxPixels: 1024}
	client := newMemoryObjectClient()
	store, err := NewS3Store(testS3Config(), client, limits)
	if err != nil {
		t.Fatal(err)
	}
	asset := newAsset("0123456789abcdef0123456789abcdef", KindIcon, "icon.png", "image/png", pngData(t, 2, 2))
	meta, _ := json.Marshal(asset)
	client.objects["captcha-assets/private/captcha/icon/"+asset.ID+".json"] = meta
	client.objects["captcha-assets/private/captcha/icon/"+asset.ID+".bin"] = bytes.Repeat([]byte{'x'}, int(limits.MaxImageBytes)+1)

	if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
		t.Fatalf("oversized stream must be rejected before returning a body: body=%v err=%v", body, err)
	}
}

func TestS3StoreListOmitsMissingOrCorruptedBodies(t *testing.T) {
	client, store, asset := putS3TestImage(t)
	bodyKey := "captcha-assets/private/captcha/icon/" + asset.ID + ".bin"
	client.mu.Lock()
	delete(client.objects, bodyKey)
	client.mu.Unlock()
	items, err := store.List(context.Background(), KindIcon)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("metadata without a verified body remained visible: %+v", items)
	}
}

func putS3TestImage(t *testing.T) (*memoryObjectClient, *S3Store, Asset) {
	t.Helper()
	client := newMemoryObjectClient()
	store, err := NewS3Store(testS3Config(), client, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", ContentType: "image/png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	return client, store, asset
}

func testS3Config() S3Config {
	return S3Config{Bucket: "captcha-assets", Prefix: "private/captcha", MetadataKey: bytes.Repeat([]byte{0x5a}, 32)}
}
