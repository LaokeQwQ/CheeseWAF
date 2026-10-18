package proxy

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// gRPC is currently an explicit HTTP/2 pass-through mode. The proxy does not
// decode the five-byte message envelope, protobuf fields, or grpc-encoding.
// Only the standard status trailers are allowed to leave the proxy; arbitrary
// upstream trailers are removed so they cannot bypass response inspection or
// audit logging.
var allowedGRPCTrailers = map[string]struct{}{
	"grpc-status":             {},
	"grpc-message":            {},
	"grpc-status-details-bin": {},
}

func grpcPassthroughRequest(req *http.Request, site config.SiteConfig) bool {
	if req == nil || !site.WAF.GRPCEnabled {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(req.Header.Get("Content-Type"), ";")[0]))
	return strings.HasPrefix(mediaType, "application/grpc")
}

// prepareUpstreamResponseTrailers applies the response-side trailer boundary
// before ReverseProxy commits headers, then repeats it after body EOF because
// net/http fills trailer values only when the response body is consumed.
func prepareUpstreamResponseTrailers(resp *http.Response, grpc bool, reqCtx *engine.RequestContext) {
	if resp == nil {
		return
	}
	sanitizeResponseTrailerState(resp, grpc, reqCtx)
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	if _, wrapped := resp.Body.(*responseTrailerBody); wrapped {
		return
	}
	resp.Body = &responseTrailerBody{ReadCloser: resp.Body, resp: resp, grpc: grpc, reqCtx: reqCtx}
}

type responseTrailerBody struct {
	io.ReadCloser
	resp   *http.Response
	grpc   bool
	reqCtx *engine.RequestContext
	once   sync.Once
}

func (b *responseTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.finalize()
	}
	return n, err
}

func (b *responseTrailerBody) Close() error {
	b.finalize()
	return b.ReadCloser.Close()
}

func (b *responseTrailerBody) finalize() {
	b.once.Do(func() { sanitizeResponseTrailerState(b.resp, b.grpc, b.reqCtx) })
}

func sanitizeResponseTrailerState(resp *http.Response, grpc bool, reqCtx *engine.RequestContext) {
	if resp == nil {
		return
	}
	observed := make(map[string]struct{})
	for _, value := range resp.Header.Values("Trailer") {
		for _, raw := range strings.Split(value, ",") {
			if name := strings.TrimSpace(raw); name != "" {
				observed[http.CanonicalHeaderKey(name)] = struct{}{}
			}
		}
	}
	for name := range resp.Trailer {
		if strings.TrimSpace(name) != "" {
			observed[http.CanonicalHeaderKey(name)] = struct{}{}
		}
	}

	allowed := make(map[string]struct{})
	dropped := make([]string, 0)
	for name := range resp.Trailer {
		canonical := http.CanonicalHeaderKey(name)
		lower := strings.ToLower(canonical)
		if grpc {
			if _, ok := allowedGRPCTrailers[lower]; ok {
				allowed[canonical] = struct{}{}
				continue
			}
		}
		delete(resp.Trailer, name)
		dropped = append(dropped, canonical)
	}

	// Header Trailer is a declaration, not a value. Keep only the standard
	// gRPC names in pass-through mode; ordinary HTTP responses get no trailers.
	declared := make([]string, 0, len(allowed))
	for name := range allowed {
		declared = append(declared, name)
	}
	sort.Strings(declared)
	if len(declared) == 0 {
		resp.Header.Del("Trailer")
	} else {
		resp.Header.Set("Trailer", strings.Join(declared, ", "))
	}
	sort.Strings(dropped)
	if len(observed) > 0 {
		observedNames := make([]string, 0, len(observed))
		for name := range observed {
			observedNames = append(observedNames, name)
		}
		sort.Strings(observedNames)
		setTrailerMetadata(reqCtx, "upstream_trailers", observedNames)
	}
	if len(dropped) > 0 {
		setTrailerMetadata(reqCtx, "upstream_trailers_dropped", dropped)
	}
	if grpc {
		if status := strings.TrimSpace(resp.Trailer.Get("Grpc-Status")); status != "" {
			if _, err := strconv.Atoi(status); err == nil {
				setTrailerMetadata(reqCtx, "grpc_status", status)
			}
		}
		if message := resp.Trailer.Get("Grpc-Message"); message != "" {
			setTrailerMetadata(reqCtx, "grpc_message_bytes", len([]byte(message)))
		}
		if details := resp.Trailer.Get("Grpc-Status-Details-Bin"); details != "" {
			setTrailerMetadata(reqCtx, "grpc_status_details_bytes", len([]byte(details)))
		}
	}
}

func setTrailerMetadata(reqCtx *engine.RequestContext, key string, value any) {
	if reqCtx == nil {
		return
	}
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = make(map[string]any)
	}
	if existing, ok := reqCtx.Metadata[key].([]string); ok {
		if values, ok := value.([]string); ok {
			seen := make(map[string]struct{}, len(existing))
			for _, item := range existing {
				seen[item] = struct{}{}
			}
			for _, item := range values {
				if _, exists := seen[item]; !exists {
					existing = append(existing, item)
				}
			}
			sort.Strings(existing)
			reqCtx.Metadata[key] = existing
			return
		}
	}
	if _, exists := reqCtx.Metadata[key]; !exists {
		reqCtx.Metadata[key] = value
	}
}
