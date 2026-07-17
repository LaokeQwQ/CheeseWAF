package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func pngData(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestLocalStoreRoundTripAndPrivateLayout(t *testing.T) {
	root := t.TempDir()
	store, err := NewLocalStore(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	data := pngData(t, 24, 16)
	a, err := store.Put(context.Background(), PutRequest{Kind: KindLogo, Name: "cheesewaf-logo.png", ContentType: "image/png", Reader: bytes.NewReader(data)})
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != KindLogo || a.Name != "cheesewaf-logo.png" || a.Size != int64(len(data)) {
		t.Fatalf("unexpected metadata: %+v", a)
	}
	_, r, err := store.Open(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("stored content changed")
	}
	info, err := os.Stat(filepath.Join(root, "logo", a.ID+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("asset permissions too broad: %o", info.Mode().Perm())
	}
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
func TestLocalStoreRejectsTraversalAndDisguisedContent(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindBackground, Name: "../../escape.png", ContentType: "image/png", Reader: bytes.NewReader(pngData(t, 2, 2))})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(a.Name, "..") || strings.ContainsAny(a.Name, "/\\") {
		t.Fatalf("unsafe display name: %q", a.Name)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "payload.png", ContentType: "image/png", Reader: strings.NewReader("<svg><script>alert(1)</script></svg>")})
	if !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("expected invalid asset, got %v", err)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "wrong.jpg", ContentType: "image/jpeg", Reader: bytes.NewReader(pngData(t, 2, 2))})
	if !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("expected type mismatch, got %v", err)
	}
}
func TestLocalStoreEnforcesByteAndPixelLimits(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{MaxImageBytes: 64, MaxPixels: 4})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindBackground, Name: "large.png", Reader: bytes.NewReader(make([]byte, 65))})
	if !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("expected byte limit, got %v", err)
	}
	store, err = NewLocalStore(t.TempDir(), Limits{MaxImageBytes: 1 << 20, MaxPixels: 4})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindBackground, Name: "pixels.png", Reader: bytes.NewReader(pngData(t, 3, 3))})
	if !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("expected pixel limit, got %v", err)
	}
}
func TestFontValidationAllowsTrueTypeAndRejectsWebFont(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ttf := append([]byte{0, 1, 0, 0}, make([]byte, 16)...)
	a, err := store.Put(context.Background(), PutRequest{Kind: KindFont, Name: "font.ttf", Reader: bytes.NewReader(ttf)})
	if err != nil || a.ContentType != "font/ttf" {
		t.Fatalf("ttf failed: %v %+v", err, a)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindFont, Name: "font.woff", Reader: bytes.NewReader([]byte("wOFFpayload"))})
	if !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("expected web font rejection, got %v", err)
	}
}
func TestReferenceIsScopedExpiringAndSingleUse(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	mgr.now = func() time.Time { return now }
	id := strings.Repeat("a", 32)
	token, err := mgr.Issue(id, "captcha-render", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Consume(token, "admin-download"); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("scope accepted: %v", err)
	}
	got, err := mgr.Consume(token, "captcha-render")
	if err != nil || got != id {
		t.Fatalf("consume failed: %v %q", err, got)
	}
	if _, err = mgr.Consume(token, "captcha-render"); !errors.Is(err, ErrReferenceUsed) {
		t.Fatalf("replay accepted: %v", err)
	}
	expired, err := mgr.Issue(id, "captcha-render", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if _, err = mgr.Consume(expired, "captcha-render"); !errors.Is(err, ErrReferenceExpired) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestReferenceManagerEnforcesPerOwnerCapacityWithoutBlockingOthers(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000, 0)
	mgr.now = func() time.Time { return now }
	id := strings.Repeat("b", 32)
	for i := 0; i < referenceOwnerCapacity; i++ {
		if _, err = mgr.IssueFor(id, "management-preview", "owner-a", time.Minute); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if _, err = mgr.IssueFor(id, "management-preview", "owner-a", time.Minute); !errors.Is(err, ErrReferenceCapacity) {
		t.Fatalf("owner capacity was not enforced: %v", err)
	}
	if _, err = mgr.IssueFor(id, "management-preview", "owner-b", time.Minute); err != nil {
		t.Fatalf("one owner blocked another: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, err = mgr.IssueFor(id, "management-preview", "owner-a", time.Minute); err != nil {
		t.Fatalf("expired owner capacity was not released: %v", err)
	}
}

func TestReferenceManagerRejectsUnregisteredAndOversizedTokens(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Consume(strings.Repeat("x", referenceMaxTokenBytes+1), "management-preview"); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("oversized token was accepted: %v", err)
	}
	other, err := NewReferenceManager(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 32)
	token, err := other.IssueFor(id, "management-preview", "owner-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Consume(token, "management-preview"); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("unregistered signed token was accepted: %v", err)
	}
}

func TestReferenceReservationCanBeReleasedAfterBackendFailure(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 32)
	token, err := mgr.IssueFor(id, "management-preview", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := mgr.Reserve(token, "management-preview")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Reserve(token, "management-preview"); !errors.Is(err, ErrReferenceUsed) {
		t.Fatalf("concurrent reservation was accepted: %v", err)
	}
	mgr.Release(reservation)
	retry, err := mgr.Reserve(token, "management-preview")
	if err != nil {
		t.Fatalf("released reservation could not retry: %v", err)
	}
	if err = mgr.Commit(retry); err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Reserve(token, "management-preview"); !errors.Is(err, ErrReferenceUsed) {
		t.Fatalf("committed reference was reusable: %v", err)
	}
}

func TestReferenceReservationRejectsStaleCommitAndRelease(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("e", 32)
	token, err := mgr.IssueFor(id, "management-preview", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err := mgr.Reserve(token, "management-preview")
	if err != nil {
		t.Fatal(err)
	}
	mgr.Release(first)
	second, err := mgr.Reserve(token, "management-preview")
	if err != nil {
		t.Fatal(err)
	}
	if err = mgr.Commit(first); !errors.Is(err, ErrReferenceUsed) {
		t.Fatalf("stale reservation committed a later lease: %v", err)
	}
	mgr.Release(first)
	if err = mgr.Commit(second); err != nil {
		t.Fatalf("stale release cancelled a later lease: %v", err)
	}
}

func TestReferenceConsumeAllowsExactlyOneConcurrentWinner(t *testing.T) {
	mgr, err := NewReferenceManager(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("f", 32)
	token, err := mgr.IssueFor(id, "captcha-render", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, consumeErr := mgr.Consume(token, "captcha-render")
			results <- consumeErr
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for consumeErr := range results {
		if consumeErr == nil {
			winners++
			continue
		}
		if !errors.Is(consumeErr, ErrReferenceUsed) {
			t.Fatalf("unexpected concurrent consume error: %v", consumeErr)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners = %d, want 1", winners)
	}
}
func TestLocalStoreHonorsCancelledContext(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.Put(ctx, PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 1, 1))})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled, got %v", err)
	}
}

func TestLocalStoreRejectsLinkedRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "asset-root")
	makeTestDirectoryLink(t, target, link)
	if _, err := NewLocalStore(link, Limits{}); err == nil {
		t.Fatal("linked asset root was accepted")
	}
}

func TestLocalStoreRejectsLinkedParentOfRoot(t *testing.T) {
	target := t.TempDir()
	parentLink := filepath.Join(t.TempDir(), "linked-parent")
	makeTestDirectoryLink(t, target, parentLink)
	if _, err := NewLocalStore(filepath.Join(parentLink, "assets"), Limits{}); err == nil {
		t.Fatal("asset root below linked parent was accepted")
	}
}

func TestLocalStoreRejectsLinkedKindDirectory(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	makeTestDirectoryLink(t, target, filepath.Join(root, string(KindIcon)))
	store, err := NewLocalStore(root, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 1, 1))})
	if err == nil {
		t.Fatal("linked kind directory was used")
	}
	entries, readErr := os.ReadDir(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("linked target was modified: %v", entries)
	}
}

func TestLocalStoreRejectsLinkedMetadataAndContent(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 2, 2))})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(store.root, string(KindIcon))
	for _, ext := range []string{".json", ".bin"} {
		t.Run(ext, func(t *testing.T) {
			path := filepath.Join(dir, a.ID+ext)
			original, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			target := filepath.Join(t.TempDir(), "target"+ext)
			if writeErr := os.WriteFile(target, original, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			if removeErr := os.Remove(path); removeErr != nil {
				t.Fatal(removeErr)
			}
			makeTestFileLink(t, target, path)

			if ext == ".json" {
				if _, _, openErr := store.Open(context.Background(), a.ID); openErr == nil {
					t.Fatal("linked metadata was accepted")
				}
			} else {
				if _, r, openErr := store.Open(context.Background(), a.ID); openErr == nil {
					r.Close()
					t.Fatal("linked content was accepted")
				}
			}
			if deleteErr := store.Delete(context.Background(), a.ID); deleteErr == nil {
				t.Fatal("delete accepted linked asset")
			}
			got, readErr := os.ReadFile(target)
			if readErr != nil {
				t.Fatalf("delete affected link target: %v", readErr)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("delete changed link target")
			}
		})
	}
}

func TestLocalStoreRejectsContentTamperingAfterUpload(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, string(KindIcon), a.ID+".bin")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)-1] ^= 0xff
	if err = os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Open(context.Background(), a.ID); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("tampered content was accepted: %v", err)
	}
}

func TestLocalStoreRejectsMetadataTamperingAfterUpload(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindLogo, Name: "logo.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(store.root, string(KindLogo), a.ID+".json")
	a.ContentType = "image/jpeg"
	meta, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(metaPath, meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Open(context.Background(), a.ID); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("tampered metadata was accepted: %v", err)
	}
}

func TestLocalStoreListOmitsAssetsThatFailContentVerification(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := store.Put(context.Background(), PutRequest{Kind: KindIcon, Name: "icon.png", Reader: bytes.NewReader(pngData(t, 8, 8))})
	if err != nil {
		t.Fatal(err)
	}
	contentPath := filepath.Join(store.root, string(KindIcon), a.ID+".bin")
	if err = os.WriteFile(contentPath, []byte("not-an-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := store.List(context.Background(), KindIcon)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("corrupted asset remained visible in list: %+v", items)
	}
}

func TestLocalStoreCloseIsIdempotentAndDisablesOperations(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	_, err = store.Put(context.Background(), PutRequest{
		Kind:   KindIcon,
		Name:   "closed.png",
		Reader: bytes.NewReader(pngData(t, 1, 1)),
	})
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Put after Close = %v, want os.ErrClosed", err)
	}
}
