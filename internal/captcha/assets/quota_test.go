package assets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLocalStoreEnforcesCountAndByteQuotas(t *testing.T) {
	data := pngData(t, 8, 8)

	t.Run("count", func(t *testing.T) {
		store, err := NewLocalStore(t.TempDir(), Limits{MaxAssets: 1, MaxTotalBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		first, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "first.png", Reader: bytes.NewReader(data)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "second.png", Reader: bytes.NewReader(data)}); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("second upload error = %v, want quota exceeded", err)
		}
		if err = store.Delete(context.Background(), first.ID); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "replacement.png", Reader: bytes.NewReader(data)}); err != nil {
			t.Fatalf("quota was not released after delete: %v", err)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		store, err := NewLocalStore(t.TempDir(), Limits{MaxAssets: 10, MaxTotalBytes: int64(len(data)*2 - 1)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "first.png", Reader: bytes.NewReader(data)}); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "second.png", Reader: bytes.NewReader(data)}); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("byte quota error = %v, want quota exceeded", err)
		}
	})
}

func TestStoresSerializeConcurrentQuotaChecks(t *testing.T) {
	data := pngData(t, 8, 8)
	tests := []struct {
		name string
		new  func(t *testing.T) Store
	}{
		{
			name: "local",
			new: func(t *testing.T) Store {
				store, err := NewLocalStore(t.TempDir(), Limits{MaxAssets: 1, MaxTotalBytes: 1 << 20})
				if err != nil {
					t.Fatal(err)
				}
				return store
			},
		},
		{
			name: "s3",
			new: func(t *testing.T) Store {
				store, err := NewS3Store(testS3Config(), newMemoryObjectClient(), Limits{MaxAssets: 1, MaxTotalBytes: 1 << 20})
				if err != nil {
					t.Fatal(err)
				}
				return store
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := test.new(t)
			const workers = 8
			start := make(chan struct{})
			results := make(chan error, workers)
			var wg sync.WaitGroup
			for idx := 0; idx < workers; idx++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(data)})
					results <- err
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			successes := 0
			for err := range results {
				if err == nil {
					successes++
					continue
				}
				if !errors.Is(err, ErrQuotaExceeded) {
					t.Fatalf("unexpected upload error: %v", err)
				}
			}
			if successes != 1 {
				t.Fatalf("successful uploads = %d, want 1", successes)
			}
		})
	}
}

func TestS3StoreEnforcesTotalByteQuota(t *testing.T) {
	data := pngData(t, 8, 8)
	store, err := NewS3Store(testS3Config(), newMemoryObjectClient(), Limits{MaxAssets: 10, MaxTotalBytes: int64(len(data)*2 - 1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "first.png", Reader: bytes.NewReader(data)}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "second.png", Reader: bytes.NewReader(data)}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("byte quota error = %v, want quota exceeded", err)
	}
}

func TestLocalStoreListDoesNotReadAssetContent(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(store.root, string(KindIcon), asset.ID+".bin")
	original, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bodyPath, bytes.Repeat([]byte{'x'}, len(original)), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := store.List(context.Background(), KindIcon)
	if err != nil || len(items) != 1 || items[0].ID != asset.ID {
		t.Fatalf("metadata-only list failed: items=%+v err=%v", items, err)
	}
	if _, body, err := store.Open(context.Background(), asset.ID); !errors.Is(err, ErrInvalidAsset) || body != nil {
		t.Fatalf("content verification was not deferred to Open: body=%v err=%v", body, err)
	}
}

type rejectBodyGetClient struct {
	ObjectClient
	bodyGets int
}

func (c *rejectBodyGetClient) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	if strings.HasSuffix(key, ".bin") {
		c.bodyGets++
		return nil, errors.New("asset body must not be read during List")
	}
	return c.ObjectClient.GetObject(ctx, bucket, key)
}

func TestS3StoreListDoesNotFetchAssetBodies(t *testing.T) {
	base := newMemoryObjectClient()
	client := &rejectBodyGetClient{ObjectClient: base}
	store, err := NewS3Store(testS3Config(), client, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	asset, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	items, err := store.List(context.Background(), KindIcon)
	if err != nil || len(items) != 1 || items[0].ID != asset.ID {
		t.Fatalf("metadata-only S3 list failed: items=%+v err=%v", items, err)
	}
	if client.bodyGets != 0 {
		t.Fatalf("S3 List fetched %d asset bodies", client.bodyGets)
	}
}
