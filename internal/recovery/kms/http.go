package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TokenSource interface {
	Token(context.Context) (string, error)
}
type TokenFunc func(context.Context) (string, error)

func (f TokenFunc) Token(ctx context.Context) (string, error) {
	if f == nil {
		return "", ErrUnsupported
	}
	return f(ctx)
}

type HTTPOptions struct {
	Endpoint string
	Client   *http.Client
	Token    func(context.Context) (string, error)
	Timeout  time.Duration
}
type HTTPBackend struct {
	endpoint *url.URL
	client   *http.Client
	token    TokenSource
	timeout  time.Duration
}

func NewHTTPBackend(o HTTPOptions) (*HTTPBackend, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrInvalidConfig
	}
	if o.Token == nil {
		return nil, ErrInvalidConfig
	}
	if o.Client == nil {
		o.Client = &http.Client{}
	}
	client := *o.Client
	if client.CheckRedirect == nil {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Timeout > 30*time.Second {
		return nil, ErrInvalidConfig
	}
	return &HTTPBackend{endpoint: u, client: &client, token: TokenFunc(o.Token), timeout: o.Timeout}, nil
}

func (b *HTTPBackend) Available(ctx context.Context) bool {
	if b == nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	res, err := b.do(c, http.MethodGet, "/health", nil)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusOK
}
func (b *HTTPBackend) Wrap(ctx context.Context, ref KeyRef, plain []byte) ([]byte, error) {
	if !validRef(ref) || len(plain) != DEKSize {
		return nil, ErrInvalidInput
	}
	var out transportResponse
	if err := b.callJSON(ctx, "/v1/wrap", transportRequest{Ref: ref, Plaintext: append([]byte(nil), plain...)}, &out); err != nil {
		return nil, err
	}
	if out.Ref != ref || len(out.Ciphertext) == 0 || len(out.Ciphertext) > maxWrappedSize {
		return nil, ErrAuthentication
	}
	return out.Ciphertext, nil
}
func (b *HTTPBackend) Unwrap(ctx context.Context, ref KeyRef, wrapped []byte) ([]byte, error) {
	if !validRef(ref) || len(wrapped) == 0 || len(wrapped) > maxWrappedSize {
		return nil, ErrInvalidInput
	}
	var out transportResponse
	if err := b.callJSON(ctx, "/v1/unwrap", transportRequest{Ref: ref, Ciphertext: append([]byte(nil), wrapped...)}, &out); err != nil {
		return nil, err
	}
	if out.Ref != ref || len(out.Plaintext) != DEKSize {
		return nil, ErrAuthentication
	}
	return out.Plaintext, nil
}
func (b *HTTPBackend) Rotate(ctx context.Context, ref KeyRef) error {
	if !validRef(ref) {
		return ErrInvalidInput
	}
	return b.callStatus(ctx, "/v1/rotate", transportRequest{Ref: ref})
}
func (b *HTTPBackend) Revoke(ctx context.Context, ref KeyRef) error {
	if !validRef(ref) {
		return ErrInvalidInput
	}
	return b.callStatus(ctx, "/v1/revoke", transportRequest{Ref: ref})
}

type transportRequest struct {
	Ref                   KeyRef
	Plaintext, Ciphertext []byte
}
type transportResponse struct {
	Ref                   KeyRef
	Plaintext, Ciphertext []byte
}

func (b *HTTPBackend) callJSON(ctx context.Context, path string, request transportRequest, out *transportResponse) error {
	body, err := json.Marshal(request)
	if err != nil {
		return ErrInvalidInput
	}
	res, err := b.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		discard(res.Body)
		return ErrProviderFailure
	}
	if err := decodeBounded(res.Body, out); err != nil {
		return ErrProviderFailure
	}
	return nil
}
func (b *HTTPBackend) callStatus(ctx context.Context, path string, request transportRequest) error {
	body, err := json.Marshal(request)
	if err != nil {
		return ErrInvalidInput
	}
	res, err := b.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		discard(res.Body)
		return ErrProviderFailure
	}
	discard(res.Body)
	return nil
}
func (b *HTTPBackend) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if b == nil || b.endpoint == nil {
		return nil, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	token, err := b.token.Token(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !strictToken(token) {
		return nil, ErrPermission
	}
	u := *b.endpoint
	u.Path = strings.TrimRight(u.Path, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalidConfig
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := b.client.Do(req)
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrUnavailable
	}
	return res, nil
}
func decodeBounded(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxWrappedSize+4097))
	if err != nil || len(data) > maxWrappedSize+4096 {
		return ErrAuthentication
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return ErrAuthentication
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrAuthentication
	}
	return nil
}
func discard(r io.Reader)       { _, _ = io.Copy(io.Discard, io.LimitReader(r, 8192)) }
func strictToken(v string) bool { return strict(v) && !strings.ContainsAny(v, " \t\r\n") }

// ValidateHTTPTransport rejects a transport that explicitly disables TLS
// verification. It is separate so callers can enforce it before construction.
func ValidateHTTPTransport(client *http.Client) error {
	if client == nil {
		return ErrInvalidConfig
	}
	if t, ok := client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return ErrInvalidConfig
	}
	return nil
}
