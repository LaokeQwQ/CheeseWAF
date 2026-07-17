package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	captchaassets "github.com/LaokeQwQ/CheeseWAF/internal/captcha/assets"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

type blockingCAPTCHAAssetStore struct {
	asset   captchaassets.Asset
	body    []byte
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	opens   int
	closes  int
}

func (s *blockingCAPTCHAAssetStore) Put(context.Context, captchaassets.PutRequest) (captchaassets.Asset, error) {
	return captchaassets.Asset{}, captchaassets.ErrInvalidAsset
}

func (s *blockingCAPTCHAAssetStore) Open(ctx context.Context, id string) (captchaassets.Asset, io.ReadCloser, error) {
	s.mu.Lock()
	s.opens++
	s.mu.Unlock()
	if id != s.asset.ID {
		return captchaassets.Asset{}, nil, captchaassets.ErrNotFound
	}
	if s.entered != nil {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return captchaassets.Asset{}, nil, ctx.Err()
		}
	}
	return s.asset, io.NopCloser(bytes.NewReader(s.body)), nil
}

func (s *blockingCAPTCHAAssetStore) List(context.Context, captchaassets.Kind) ([]captchaassets.Asset, error) {
	return []captchaassets.Asset{s.asset}, nil
}

func (s *blockingCAPTCHAAssetStore) Delete(context.Context, string) error { return nil }

func (s *blockingCAPTCHAAssetStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closes++
	return nil
}

func (s *blockingCAPTCHAAssetStore) openCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens
}

func (s *blockingCAPTCHAAssetStore) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func newCAPTCHAAssetHandler(t *testing.T) (*Handler, http.Handler) {
	t.Helper()
	cfg := config.Default()
	cfg.CAPTCHAAssets.Local.Path = filepath.Join(t.TempDir(), "assets")
	store, refs, err := initializeCAPTCHAAssets(&cfg, "test-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Config: &cfg, Secret: "test-secret", CAPTCHAAssets: store, CAPTCHAAssetReferences: refs, Auditor: middleware.NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"))}
	h.captchaAssetRuntime.Store(&captchaAssetRuntime{store: store, references: refs, limits: cfg.CAPTCHAAssets.Limits, config: cfg.CAPTCHAAssets})
	r := chi.NewRouter()
	r.Get("/assets", h.ListCAPTCHAAssets)
	r.Post("/assets", h.UploadCAPTCHAAsset)
	r.Delete("/assets/{id}", h.DeleteCAPTCHAAsset)
	r.Post("/assets/{id}/preview", h.IssueCAPTCHAAssetPreview)
	r.Get("/preview/{reference}", h.PreviewCAPTCHAAsset)
	r.Get("/config", h.GetCAPTCHAAssetConfig)
	r.Put("/config", h.UpdateCAPTCHAAssetConfig)
	return h, r
}

func captchaAssetRequest(method, target, subject string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	claims := &middleware.Claims{Subject: subject, Username: subject, Role: "admin"}
	return request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
}

func uploadCAPTCHAAsset(t *testing.T, router http.Handler) captchaassets.Asset {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("kind", "icon")
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="icon.png"`)
	header.Set("Content-Type", "image/png")
	part, err := mw.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	if err = png.Encode(part, img); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/assets", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data captchaassets.Asset `json:"data"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func captchaAssetTestPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var body bytes.Buffer
	if err := png.Encode(&body, img); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func TestCAPTCHAAssetUploadListPreviewReplayDeleteAndAudit(t *testing.T) {
	h, router := newCAPTCHAAssetHandler(t)
	asset := uploadCAPTCHAAsset(t, router)
	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/assets?kind=icon", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), asset.ID) {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	issue := httptest.NewRecorder()
	router.ServeHTTP(issue, captchaAssetRequest(http.MethodPost, "/assets/"+asset.ID+"/preview", "owner-a", nil))
	var issued struct {
		Data struct {
			Reference string `json:"reference"`
		} `json:"data"`
	}
	if issue.Code != http.StatusOK || json.Unmarshal(issue.Body.Bytes(), &issued) != nil || issued.Data.Reference == "" {
		t.Fatalf("issue preview: %d %s", issue.Code, issue.Body.String())
	}
	previewPath := "/preview/" + issued.Data.Reference
	preview := httptest.NewRecorder()
	router.ServeHTTP(preview, captchaAssetRequest(http.MethodGet, previewPath, "owner-a", nil))
	if preview.Code != http.StatusOK || preview.Header().Get("Cache-Control") != "private, no-store, max-age=0" {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	if got := preview.Header().Get("Content-Security-Policy"); got != "default-src 'none'; sandbox" {
		t.Fatalf("preview CSP = %q", got)
	}
	if got := preview.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("preview nosniff = %q", got)
	}
	if got := preview.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("preview referrer policy = %q", got)
	}
	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, captchaAssetRequest(http.MethodGet, previewPath, "owner-a", nil))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay should fail: %d %s", replay.Code, replay.Body.String())
	}
	del := httptest.NewRecorder()
	router.ServeHTTP(del, httptest.NewRequest(http.MethodDelete, "/assets/"+asset.ID, nil))
	if del.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", del.Code, del.Body.String())
	}
	entries, err := h.Auditor.Query(10)
	if err != nil || len(entries) < 2 {
		t.Fatalf("audit entries: %+v err=%v", entries, err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Message, "test-secret") {
			t.Fatal("audit leaked secret")
		}
	}
}

func TestCAPTCHAAssetConfigDoesNotEchoCredentialAndRollsBackOnSaveFailure(t *testing.T) {
	h, router := newCAPTCHAAssetHandler(t)
	candidateStore := &blockingCAPTCHAAssetStore{}
	originalInitializer := initializeCAPTCHAAssetStore
	initializeCAPTCHAAssetStore = func(_ *config.Config, secret string, _ captchaassets.Store) (captchaassets.Store, *captchaassets.ReferenceManager, error) {
		_, refs, err := initializeCAPTCHAAssets(h.Config, secret, candidateStore)
		return candidateStore, refs, err
	}
	defer func() { initializeCAPTCHAAssetStore = originalInitializer }()
	h.Config.CAPTCHAAssets.S3.CredentialFile = `C:\secret\credential.json`
	h.Config.CAPTCHAAssets.S3.MetadataKeyFile = `C:\secret\metadata.key`
	runtime := *h.captchaAssetRuntime.Load()
	runtime.config = h.Config.CAPTCHAAssets
	h.captchaAssetRuntime.Store(&runtime)
	view := httptest.NewRecorder()
	router.ServeHTTP(view, httptest.NewRequest(http.MethodGet, "/config", nil))
	if view.Code != http.StatusOK || strings.Contains(view.Body.String(), "credential.json") || strings.Contains(view.Body.String(), "metadata.key") || !strings.Contains(view.Body.String(), `"credential_configured":true`) || !strings.Contains(view.Body.String(), `"metadata_key_configured":true`) {
		t.Fatalf("credential response: %d %s", view.Code, view.Body.String())
	}
	oldStore := h.CAPTCHAAssets
	oldPath := h.Config.CAPTCHAAssets.Local.Path
	badTarget := filepath.Join(t.TempDir(), "config-as-directory")
	if err := os.Mkdir(badTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = badTarget
	newPath := filepath.Join(t.TempDir(), "replacement")
	payload, _ := json.Marshal(map[string]any{"backend": "local", "local": map[string]any{"path": newPath}, "limits": h.Config.CAPTCHAAssets.Limits})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(payload)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected save failure: %d %s", rec.Code, rec.Body.String())
	}
	if h.Config.CAPTCHAAssets.Local.Path != oldPath || h.CAPTCHAAssets != oldStore {
		t.Fatal("runtime state changed after config persistence failure")
	}
	if candidateStore.closeCount() != 1 {
		t.Fatal(`unpublished store was not closed`)
	}
}

func TestCAPTCHAAssetConfigMutationUsesLatestConfigUnderLock(t *testing.T) {
	h, router := newCAPTCHAAssetHandler(t)
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, h.Config); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = configPath

	candidateStore := &blockingCAPTCHAAssetStore{}
	initializerEntered := make(chan struct{})
	releaseInitializer := make(chan struct{})
	originalInitializer := initializeCAPTCHAAssetStore
	initializeCAPTCHAAssetStore = func(cfg *config.Config, secret string, _ captchaassets.Store) (captchaassets.Store, *captchaassets.ReferenceManager, error) {
		close(initializerEntered)
		<-releaseInitializer
		_, refs, err := initializeCAPTCHAAssets(cfg, secret, candidateStore)
		return candidateStore, refs, err
	}
	defer func() { initializeCAPTCHAAssetStore = originalInitializer }()

	newPath := filepath.Join(t.TempDir(), "replacement")
	payload, _ := json.Marshal(map[string]any{
		"backend": "local",
		"local":   map[string]any{"path": newPath},
		"limits":  h.Config.CAPTCHAAssets.Limits,
	})
	updateDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(payload)))
		updateDone <- rec
	}()
	<-initializerEntered

	mutationDone := make(chan error, 1)
	go func() {
		_, err := h.commitConfigMutation(func(candidate *config.Config) error {
			candidate.Logging.Level = "debug"
			return nil
		}, nil)
		mutationDone <- err
	}()
	close(releaseInitializer)

	if rec := <-updateDone; rec.Code != http.StatusOK {
		t.Fatalf("captcha config update failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := <-mutationDone; err != nil {
		t.Fatalf("independent config mutation failed: %v", err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Logging.Level != "debug" {
		t.Fatalf("independent config mutation was lost: logging=%q", loaded.Logging.Level)
	}
	if loaded.CAPTCHAAssets.Local.Path != newPath {
		t.Fatalf("captcha asset config was not committed: path=%q", loaded.CAPTCHAAssets.Local.Path)
	}
	if h.CAPTCHAAssets != candidateStore || candidateStore.closeCount() != 0 {
		t.Fatalf("published store state is inconsistent: current=%t closes=%d", h.CAPTCHAAssets == candidateStore, candidateStore.closeCount())
	}
}

func TestDefaultCAPTCHAAssetCandidateFixesZeroTimeout(t *testing.T) {
	v := defaultCAPTCHAAssetCandidate(config.CAPTCHAAssetsConfig{})
	if v.S3.RequestTimeout != config.Default().CAPTCHAAssets.S3.RequestTimeout {
		t.Fatalf("unexpected timeout %s", v.S3.RequestTimeout)
	}
}

func TestCAPTCHAAssetPreviewIsBoundToAuthenticatedSubject(t *testing.T) {
	_, router := newCAPTCHAAssetHandler(t)
	asset := uploadCAPTCHAAsset(t, router)
	issue := httptest.NewRecorder()
	router.ServeHTTP(issue, captchaAssetRequest(http.MethodPost, "/assets/"+asset.ID+"/preview", "owner-a", nil))
	var issued struct {
		Data struct {
			Reference string `json:"reference"`
		} `json:"data"`
	}
	if issue.Code != http.StatusOK || json.Unmarshal(issue.Body.Bytes(), &issued) != nil || issued.Data.Reference == "" {
		t.Fatalf("issue preview: %d %s", issue.Code, issue.Body.String())
	}
	previewPath := "/preview/" + issued.Data.Reference
	wrongOwner := httptest.NewRecorder()
	router.ServeHTTP(wrongOwner, captchaAssetRequest(http.MethodGet, previewPath, "owner-b", nil))
	if wrongOwner.Code != http.StatusBadRequest {
		t.Fatalf("cross-subject preview should fail: %d %s", wrongOwner.Code, wrongOwner.Body.String())
	}
	owner := httptest.NewRecorder()
	router.ServeHTTP(owner, captchaAssetRequest(http.MethodGet, previewPath, "owner-a", nil))
	if owner.Code != http.StatusOK {
		t.Fatalf("owner could not consume preview after rejected cross-subject request: %d %s", owner.Code, owner.Body.String())
	}
}
func TestCAPTCHAAssetAuditUsesAuthenticatedIdentityWithoutRequestSecrets(t *testing.T) {
	h, _ := newCAPTCHAAssetHandler(t)
	req := httptest.NewRequest(http.MethodPut, "/config?credential_file=secret", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "user-id", Username: "admin", Role: "admin"}))
	h.auditCAPTCHAAssetWrite(req, http.StatusOK, "captcha_assets_config", "updated")
	entries, err := h.Auditor.Query(1)
	if err != nil || len(entries) != 1 || entries[0].Subject != "user-id" || strings.Contains(entries[0].Path, "secret") {
		t.Fatalf("unsafe audit entry: %+v err=%v", entries, err)
	}
}

func TestCAPTCHAAssetRuntimeSnapshotStaysCoherentAcrossConcurrentSwap(t *testing.T) {
	id := strings.Repeat("a", 32)
	bodyA := captchaAssetTestPNG(t, 2, 2)
	bodyB := captchaAssetTestPNG(t, 3, 3)
	assetA := captchaassets.Asset{ID: id, Kind: captchaassets.KindIcon, Name: "a.png", ContentType: "image/png", Size: int64(len(bodyA))}
	assetB := captchaassets.Asset{ID: id, Kind: captchaassets.KindIcon, Name: "b.png", ContentType: "image/png", Size: int64(len(bodyB))}
	storeA := &blockingCAPTCHAAssetStore{asset: assetA, body: bodyA, entered: make(chan struct{}), release: make(chan struct{})}
	storeB := &blockingCAPTCHAAssetStore{asset: assetB, body: bodyB}
	key := bytes.Repeat([]byte{9}, 32)
	refsA, err := captchaassets.NewReferenceManager(key)
	if err != nil {
		t.Fatal(err)
	}
	refsB, err := captchaassets.NewReferenceManager(key)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{}
	h.captchaAssetRuntime.Store(&captchaAssetRuntime{store: storeA, references: refsA})
	router := chi.NewRouter()
	router.Post("/assets/{id}/preview", h.IssueCAPTCHAAssetPreview)
	router.Get("/preview/{reference}", h.PreviewCAPTCHAAsset)

	issued := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, captchaAssetRequest(http.MethodPost, "/assets/"+id+"/preview", "owner-a", nil))
		issued <- rec
	}()
	<-storeA.entered
	old := h.captchaAssetRuntime.Swap(&captchaAssetRuntime{store: storeB, references: refsB})
	old.retire()
	if storeA.closeCount() != 0 {
		t.Fatal(`store closed while request was in flight`)
	}
	close(storeA.release)
	rec := <-issued
	if rec.Code != http.StatusOK {
		t.Fatalf("issue preview failed: %d %s", rec.Code, rec.Body.String())
	}
	if got := storeA.closeCount(); got != 1 {
		t.Fatalf(`close count = %d`, got)
	}
	var response struct {
		Data struct {
			Reference string `json:"reference"`
		} `json:"data"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Data.Reference == "" {
		t.Fatalf("invalid preview response: err=%v body=%s", err, rec.Body.String())
	}
	reservation, err := refsA.Reserve(response.Data.Reference, "management-preview", "subject:owner-a")
	if err != nil {
		t.Fatalf("request mixed old store with new reference manager: %v", err)
	}
	refsA.Release(reservation)
	if _, err = refsB.Reserve(response.Data.Reference, "management-preview", "subject:owner-a"); err == nil {
		t.Fatal("old-generation reference was registered in the new runtime")
	}

	preview := httptest.NewRecorder()
	router.ServeHTTP(preview, captchaAssetRequest(http.MethodGet, "/preview/"+response.Data.Reference, "owner-a", nil))
	if preview.Code != http.StatusBadRequest {
		t.Fatalf("old-generation reference reached the new store: %d %s", preview.Code, preview.Body.String())
	}
	if got := storeB.openCount(); got != 0 {
		t.Fatalf("new store was opened before rejecting old reference: %d", got)
	}
}

func TestCAPTCHAAssetRuntimeReleaseDoesNotUnderflow(t *testing.T) {
	runtime := &captchaAssetRuntime{}
	runtime.release()
	if runtime.users != 0 {
		t.Fatalf(`users=%d`, runtime.users)
	}
}

func TestCAPTCHAAssetConfigViewUsesThePublishedRuntimeSnapshot(t *testing.T) {
	h, _ := newCAPTCHAAssetHandler(t)
	runtime := h.captchaAssetRuntime.Load()
	if runtime == nil {
		t.Fatal("captcha asset runtime was not published")
	}
	published := runtime.config
	h.Config.CAPTCHAAssets.Backend = "s3"

	rec := httptest.NewRecorder()
	h.GetCAPTCHAAssetConfig(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get config failed: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"backend":"`+published.Backend+`"`) {
		t.Fatalf("response did not use the published runtime snapshot: %s", rec.Body.String())
	}
}
