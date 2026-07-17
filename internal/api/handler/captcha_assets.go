package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	captchaassets "github.com/LaokeQwQ/CheeseWAF/internal/captcha/assets"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

const captchaAssetMultipartOverhead = 1 << 20
const captchaAssetPreviewTTL = 2 * time.Minute

type captchaAssetConfigResponse struct {
	Backend string                    `json:"backend"`
	Local   config.CAPTCHAAssetLocal  `json:"local"`
	S3      captchaAssetS3Response    `json:"s3"`
	Limits  config.CAPTCHAAssetLimits `json:"limits"`
}
type captchaAssetS3Response struct {
	Endpoint              string        `json:"endpoint"`
	Bucket                string        `json:"bucket"`
	Region                string        `json:"region"`
	PathStyle             bool          `json:"path_style"`
	Prefix                string        `json:"prefix"`
	UseTLS                bool          `json:"use_tls"`
	AllowPrivateEndpoint  bool          `json:"allow_private_endpoint"`
	RequestTimeout        time.Duration `json:"request_timeout"`
	CredentialConfigured  bool          `json:"credential_configured"`
	MetadataKeyConfigured bool          `json:"metadata_key_configured"`
}
type captchaAssetConfigRequest struct {
	Backend string                   `json:"backend"`
	Local   config.CAPTCHAAssetLocal `json:"local"`
	S3      struct {
		Endpoint             string        `json:"endpoint"`
		Bucket               string        `json:"bucket"`
		Region               string        `json:"region"`
		PathStyle            bool          `json:"path_style"`
		Prefix               string        `json:"prefix"`
		UseTLS               bool          `json:"use_tls"`
		AllowPrivateEndpoint bool          `json:"allow_private_endpoint"`
		CredentialFile       string        `json:"credential_file"`
		MetadataKeyFile      string        `json:"metadata_key_file"`
		RequestTimeout       time.Duration `json:"request_timeout"`
	} `json:"s3"`
	Limits config.CAPTCHAAssetLimits `json:"limits"`
}

func (h *Handler) ListCAPTCHAAssets(w http.ResponseWriter, r *http.Request) {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if !ok {
		return
	}
	defer runtime.release()
	items, err := runtime.store.List(r.Context(), captchaassets.Kind(strings.TrimSpace(r.URL.Query().Get("kind"))))
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	if items == nil {
		items = []captchaassets.Asset{}
	}
	writeData(w, map[string]any{"items": items})
}
func (h *Handler) UploadCAPTCHAAsset(w http.ResponseWriter, r *http.Request) {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if !ok {
		return
	}
	defer runtime.release()
	max := captchaAssetUploadLimit(runtime.limits)
	r.Body = http.MaxBytesReader(w, r.Body, max+captchaAssetMultipartOverhead)
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_MULTIPART_INVALID", "multipart form is required")
		return
	}
	kind, name, ct, file, err := readCAPTCHAAssetMultipart(reader, max)
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	asset, err := runtime.store.Put(r.Context(), captchaassets.PutRequest{Kind: kind, Name: name, ContentType: ct, Reader: file})
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	h.auditCAPTCHAAssetWrite(r, http.StatusOK, "captcha_asset:"+asset.ID, "uploaded "+string(asset.Kind))
	writeData(w, asset)
}
func (h *Handler) DeleteCAPTCHAAsset(w http.ResponseWriter, r *http.Request) {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if !ok {
		return
	}
	defer runtime.release()
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if err := runtime.store.Delete(r.Context(), id); err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	h.auditCAPTCHAAssetWrite(r, http.StatusOK, "captcha_asset:"+id, "deleted")
	writeData(w, map[string]any{"deleted": true})
}
func (h *Handler) IssueCAPTCHAAssetPreview(w http.ResponseWriter, r *http.Request) {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if !ok {
		return
	}
	defer runtime.release()
	owner, ok := captchaAssetPreviewOwner(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	asset, body, err := runtime.store.Open(r.Context(), id)
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	body.Close()
	if asset.Kind == captchaassets.KindFont {
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_PREVIEW_UNSUPPORTED", "font preview is not available")
		return
	}
	ref, err := runtime.references.IssueFor(id, "management-preview", owner, captchaAssetPreviewTTL)
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	writeData(w, map[string]any{"reference": ref, "expires_in": int(captchaAssetPreviewTTL.Seconds())})
}
func (h *Handler) PreviewCAPTCHAAsset(w http.ResponseWriter, r *http.Request) {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if !ok {
		return
	}
	defer runtime.release()
	owner, ok := captchaAssetPreviewOwner(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	reservation, err := runtime.references.Reserve(chi.URLParam(r, "reference"), "management-preview", owner)
	if err != nil {
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	asset, body, err := runtime.store.Open(r.Context(), reservation.ID)
	if err != nil {
		runtime.references.Release(reservation)
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	if err = runtime.references.Commit(reservation); err != nil {
		body.Close()
		h.writeCAPTCHAAssetError(w, err)
		return
	}
	defer body.Close()
	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, no-store, max-age=0")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.LimitReader(body, asset.Size))
}
func (h *Handler) GetCAPTCHAAssetConfig(w http.ResponseWriter, _ *http.Request) {
	if h == nil {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_ASSET_CONFIG_UNAVAILABLE", "captcha asset configuration is unavailable")
		return
	}
	if runtime, ok := h.loadCAPTCHAAssetRuntime(nil); ok {
		defer runtime.release()
		writeData(w, captchaAssetConfigView(runtime.config))
		return
	}
	if h.Config == nil {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_ASSET_CONFIG_UNAVAILABLE", "captcha asset configuration is unavailable")
		return
	}
	writeData(w, captchaAssetConfigView(h.Config.CAPTCHAAssets))
}
func (h *Handler) UpdateCAPTCHAAssetConfig(w http.ResponseWriter, r *http.Request) {
	var req captchaAssetConfigRequest
	if !decode(w, r, &req) {
		return
	}

	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	if h.configWriteFrozen {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", "configuration writes are frozen: "+h.configFreezeReason)
		return
	}
	if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
		writeError(w, http.StatusConflict, "CONFIG_WRITE_PROTECTED", reason)
		return
	}

	next, err := config.Clone(h.Config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_CLONE_ERROR", "unable to prepare configuration")
		return
	}
	candidate := defaultCAPTCHAAssetCandidate(req.config())
	if strings.TrimSpace(candidate.S3.CredentialFile) == "" {
		candidate.S3.CredentialFile = next.CAPTCHAAssets.S3.CredentialFile
	}
	if strings.TrimSpace(candidate.S3.MetadataKeyFile) == "" {
		candidate.S3.MetadataKeyFile = next.CAPTCHAAssets.S3.MetadataKeyFile
	}
	next.CAPTCHAAssets = candidate
	if err = config.Validate(next); err != nil {
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_CONFIG_INVALID", err.Error())
		return
	}
	store, refs, err := initializeCAPTCHAAssetStore(next, h.Secret, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_BACKEND_UNAVAILABLE", "CAPTCHA asset backend is unavailable")
		return
	}
	published := false
	defer func() {
		if !published {
			closeCAPTCHAAssetStore(store)
		}
	}()
	if err = h.persistConfigCandidateLocked(next); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	*h.Config = *next
	h.CAPTCHAAssets = store
	h.CAPTCHAAssetReferences = refs
	h.CAPTCHAAssetInitError = nil
	old := h.captchaAssetRuntime.Swap(&captchaAssetRuntime{store: store, references: refs, limits: candidate.Limits, config: candidate})
	published = true
	if old != nil {
		old.retire()
	}
	h.auditCAPTCHAAssetWrite(r, http.StatusOK, "captcha_assets_config", "updated backend "+candidate.Backend)
	writeData(w, captchaAssetConfigView(candidate))
}

func (h *Handler) TestCAPTCHAAssetConfig(w http.ResponseWriter, r *http.Request) {
	var req captchaAssetConfigRequest
	if !decode(w, r, &req) {
		return
	}
	candidate := req.config()
	candidate = defaultCAPTCHAAssetCandidate(candidate)
	if strings.TrimSpace(candidate.S3.CredentialFile) == "" && h.Config != nil {
		candidate.S3.CredentialFile = h.Config.CAPTCHAAssets.S3.CredentialFile
	}
	if strings.TrimSpace(candidate.S3.MetadataKeyFile) == "" && h.Config != nil {
		candidate.S3.MetadataKeyFile = h.Config.CAPTCHAAssets.S3.MetadataKeyFile
	}
	if err := validateCAPTCHAAssetCandidate(candidate); err != nil {
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_CONFIG_INVALID", err.Error())
		return
	}
	store, _, err := initializeCAPTCHAAssetStore(&config.Config{CAPTCHAAssets: candidate}, h.Secret, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "CAPTCHA_ASSET_CONNECTION_FAILED", "CAPTCHA asset connection failed")
		return
	}
	defer closeCAPTCHAAssetStore(store)
	ctx, cancel := context.WithTimeout(r.Context(), candidate.S3.RequestTimeout)
	defer cancel()
	if _, err = store.List(ctx, ""); err != nil {
		writeError(w, http.StatusBadGateway, "CAPTCHA_ASSET_CONNECTION_FAILED", "CAPTCHA asset connection failed")
		return
	}
	h.auditCAPTCHAAssetWrite(r, http.StatusOK, "captcha_assets_config", "connection tested")
	writeData(w, map[string]any{"ok": true})
}

func (r captchaAssetConfigRequest) config() config.CAPTCHAAssetsConfig {
	return config.CAPTCHAAssetsConfig{Backend: strings.ToLower(strings.TrimSpace(r.Backend)), Local: r.Local, S3: config.CAPTCHAAssetS3{Endpoint: strings.TrimSpace(r.S3.Endpoint), Bucket: strings.TrimSpace(r.S3.Bucket), Region: strings.TrimSpace(r.S3.Region), PathStyle: r.S3.PathStyle, Prefix: strings.Trim(strings.TrimSpace(r.S3.Prefix), "/"), UseTLS: r.S3.UseTLS, AllowPrivateEndpoint: r.S3.AllowPrivateEndpoint, CredentialFile: strings.TrimSpace(r.S3.CredentialFile), MetadataKeyFile: strings.TrimSpace(r.S3.MetadataKeyFile), RequestTimeout: r.S3.RequestTimeout}, Limits: r.Limits}
}
func captchaAssetConfigView(v config.CAPTCHAAssetsConfig) captchaAssetConfigResponse {
	return captchaAssetConfigResponse{Backend: v.Backend, Local: v.Local, S3: captchaAssetS3Response{Endpoint: v.S3.Endpoint, Bucket: v.S3.Bucket, Region: v.S3.Region, PathStyle: v.S3.PathStyle, Prefix: v.S3.Prefix, UseTLS: v.S3.UseTLS, AllowPrivateEndpoint: v.S3.AllowPrivateEndpoint, RequestTimeout: v.S3.RequestTimeout, CredentialConfigured: strings.TrimSpace(v.S3.CredentialFile) != "", MetadataKeyConfigured: strings.TrimSpace(v.S3.MetadataKeyFile) != ""}, Limits: v.Limits}
}
func defaultCAPTCHAAssetCandidate(v config.CAPTCHAAssetsConfig) config.CAPTCHAAssetsConfig {
	d := config.Default().CAPTCHAAssets
	if v.S3.Region == "" {
		v.S3.Region = d.S3.Region
	}
	if v.S3.RequestTimeout == 0 {
		v.S3.RequestTimeout = d.S3.RequestTimeout
	}
	return v
}
func validateCAPTCHAAssetCandidate(v config.CAPTCHAAssetsConfig) error {
	base := config.Default()
	base.CAPTCHAAssets = v
	return config.Validate(&base)
}
func (h *Handler) requireCAPTCHAAssets(w http.ResponseWriter) bool {
	runtime, ok := h.loadCAPTCHAAssetRuntime(w)
	if ok {
		runtime.release()
	}
	return ok
}

func (h *Handler) loadCAPTCHAAssetRuntime(w http.ResponseWriter) (*captchaAssetRuntime, bool) {
	if h != nil {
		for {
			if runtime := h.captchaAssetRuntime.Load(); runtime != nil && runtime.store != nil && runtime.references != nil {
				if runtime.acquire() {
					return runtime, true
				}
				continue
			}
			break
		}
		if h.CAPTCHAAssets != nil && h.CAPTCHAAssetReferences != nil {
			limits := config.CAPTCHAAssetLimits{}
			if h.Config != nil {
				limits = h.Config.CAPTCHAAssets.Limits
			}
			runtimeConfig := config.CAPTCHAAssetsConfig{Limits: limits}
			if h.Config != nil {
				runtimeConfig = h.Config.CAPTCHAAssets
			}
			runtime := &captchaAssetRuntime{store: h.CAPTCHAAssets, references: h.CAPTCHAAssetReferences, limits: limits, config: runtimeConfig}
			if h.captchaAssetRuntime.CompareAndSwap(nil, runtime) && runtime.acquire() {
				return runtime, true
			}
			return h.loadCAPTCHAAssetRuntime(w)
		}
	}
	if w != nil {
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_ASSET_STORE_UNAVAILABLE", "captcha asset storage is unavailable")
	}
	return nil, false
}
func captchaAssetUploadLimit(a config.CAPTCHAAssetLimits) int64 {
	if a.MaxImageBytes > a.MaxFontBytes {
		return a.MaxImageBytes
	}
	if a.MaxFontBytes > 0 {
		return a.MaxFontBytes
	}
	return captchaassets.DefaultMaxFontBytes
}
func readCAPTCHAAssetMultipart(mr *multipart.Reader, max int64) (captchaassets.Kind, string, string, io.Reader, error) {
	var kind captchaassets.Kind
	var name, ct string
	var data []byte
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", "", nil, fmt.Errorf("%w: invalid multipart body", captchaassets.ErrInvalidAsset)
		}
		switch part.FormName() {
		case "kind":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			kind = captchaassets.Kind(strings.TrimSpace(string(b)))
		case "file":
			name = part.FileName()
			ct = part.Header.Get("Content-Type")
			data, err = io.ReadAll(io.LimitReader(part, max+1))
			if err != nil {
				return "", "", "", nil, err
			}
		}
		part.Close()
	}
	if len(data) == 0 || int64(len(data)) > max {
		return "", "", "", nil, fmt.Errorf("%w: missing or oversized file", captchaassets.ErrInvalidAsset)
	}
	return kind, name, ct, bytes.NewReader(data), nil
}
func (h *Handler) writeCAPTCHAAssetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, captchaassets.ErrReferenceCapacity):
		writeError(w, http.StatusServiceUnavailable, "CAPTCHA_ASSET_REFERENCE_CAPACITY", "captcha asset preview service is temporarily busy")
	case errors.Is(err, captchaassets.ErrNotFound):
		writeError(w, http.StatusNotFound, "CAPTCHA_ASSET_NOT_FOUND", "captcha asset was not found")
	case errors.Is(err, captchaassets.ErrInvalidAsset), errors.Is(err, captchaassets.ErrReferenceExpired), errors.Is(err, captchaassets.ErrReferenceUsed):
		writeError(w, http.StatusBadRequest, "CAPTCHA_ASSET_INVALID", "captcha asset request is invalid")
	default:
		writeError(w, http.StatusInternalServerError, "CAPTCHA_ASSET_ERROR", "captcha asset operation failed")
	}
}

func captchaAssetPreviewOwner(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || strings.TrimSpace(claims.Subject) == "" {
		return "", false
	}
	return "subject:" + strings.TrimSpace(claims.Subject), true
}
func (h *Handler) auditCAPTCHAAssetWrite(r *http.Request, status int, target, message string) {
	if h == nil || h.Auditor == nil {
		return
	}
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	entry := middleware.AuditEntry{Timestamp: h.nowUTC(), Method: r.Method, Path: r.URL.Path, Status: status, RemoteIP: remoteIPFromRequest(r), Target: target, Message: message}
	if claims != nil {
		entry.Subject = claims.Subject
		entry.User = claims.Username
		entry.Role = claims.Role
	}
	_ = h.Auditor.Write(context.Background(), entry)
}
