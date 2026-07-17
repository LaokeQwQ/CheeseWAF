package assets

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

const (
	maxS3ListPages                    = 100
	maxS3ListObjects                  = 10_000
	maxS3ListResponseBytes            = 8 << 20
	maxS3ListCumulativeResponseBytes  = maxS3ListResponseBytes
	maxS3ContinuationTokenOccurrences = 1
)

var errS3ResponseBodyTooLarge = errors.New("S3 response body is too large")

type Credential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type HTTPObjectClient struct {
	endpoint   *url.URL
	region     string
	pathStyle  bool
	credential Credential
	client     *http.Client
}

func NewHTTPObjectClient(cfg S3Config, credentialFile string) (*HTTPObjectClient, error) {
	policy := netguard.URLPolicy{Purpose: "CAPTCHA S3 endpoint", HostPurpose: "CAPTCHA S3 endpoint", AllowedSchemes: []string{"http", "https"}, AllowPrivate: cfg.AllowPrivateEndpoint}
	u, err := netguard.ValidateURL(cfg.Endpoint, policy)
	if err != nil {
		return nil, fmt.Errorf("invalid S3 endpoint: %w", err)
	}
	if cfg.UseTLS && u.Scheme != "https" {
		return nil, fmt.Errorf("S3 TLS is required by configuration")
	}
	credPath, err := safeConfigPath(credentialFile)
	if err != nil {
		return nil, fmt.Errorf("S3 credential file path: %w", err)
	}
	raw, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("read S3 credential file: %w", err)
	}
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("S3 credential file is too large")
	}
	var cred Credential
	if err = json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("decode S3 credential file: %w", err)
	}
	if strings.TrimSpace(cred.AccessKeyID) == "" || strings.TrimSpace(cred.SecretAccessKey) == "" {
		return nil, fmt.Errorf("S3 credential file must contain access_key_id and secret_access_key")
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPObjectClient{endpoint: u, region: cfg.Region, pathStyle: cfg.PathStyle, credential: cred, client: netguard.NewHTTPClient(netguard.HTTPClientOptions{Timeout: timeout, Policy: policy})}, nil
}

func (c *HTTPObjectClient) PutObject(ctx context.Context, bucket, key, ct string, body io.Reader, size int64) error {
	data, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil || int64(len(data)) != size {
		return fmt.Errorf("read S3 object body")
	}
	req, err := c.request(ctx, http.MethodPut, bucket, key, nil, ct, data)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
func (c *HTTPObjectClient) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	req, err := c.request(ctx, http.MethodGet, bucket, key, nil, "", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("S3 returned status %d", resp.StatusCode)
	}
	return resp.Body, nil
}
func (c *HTTPObjectClient) DeleteObject(ctx context.Context, bucket, key string) error {
	req, err := c.request(ctx, http.MethodDelete, bucket, key, nil, "", nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}
func (c *HTTPObjectClient) ListObjects(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	continuationToken := ""
	seenContinuationTokens := make(map[string]int)
	pageCount := 0
	var responseBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if pageCount >= maxS3ListPages {
			return nil, fmt.Errorf("S3 list page limit exceeded (%d)", maxS3ListPages)
		}
		pageCount++
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if continuationToken != "" {
			q.Set("continuation-token", continuationToken)
		}
		req, err := c.request(ctx, http.MethodGet, bucket, "", q, "", nil)
		if err != nil {
			return nil, err
		}
		var raw struct {
			Contents []struct {
				Key          string    `xml:"Key"`
				Size         int64     `xml:"Size"`
				ETag         string    `xml:"ETag"`
				LastModified time.Time `xml:"LastModified"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		remainingBytes := maxS3ListCumulativeResponseBytes - responseBytes
		if remainingBytes <= 0 {
			return nil, fmt.Errorf("S3 list cumulative response byte limit exceeded (%d)", maxS3ListCumulativeResponseBytes)
		}
		pageResponseBytes, err := c.doWithResponseByteLimit(req, &raw, remainingBytes)
		if err != nil {
			if errors.Is(err, errS3ResponseBodyTooLarge) {
				return nil, fmt.Errorf("S3 list cumulative response byte limit exceeded (%d)", maxS3ListCumulativeResponseBytes)
			}
			return nil, err
		}
		if pageResponseBytes > maxS3ListCumulativeResponseBytes-responseBytes {
			return nil, fmt.Errorf("S3 list cumulative response byte limit exceeded (%d)", maxS3ListCumulativeResponseBytes)
		}
		responseBytes += pageResponseBytes
		if len(raw.Contents) > maxS3ListObjects-len(out) {
			return nil, fmt.Errorf("S3 list object limit exceeded (%d)", maxS3ListObjects)
		}
		for _, v := range raw.Contents {
			out = append(out, ObjectInfo{Key: v.Key, Size: v.Size, ETag: v.ETag, LastModified: v.LastModified})
		}
		if !raw.IsTruncated {
			return out, nil
		}
		if strings.TrimSpace(raw.NextContinuationToken) == "" {
			return nil, fmt.Errorf("S3 list response is truncated without a continuation token")
		}
		seenContinuationTokens[raw.NextContinuationToken]++
		if seenContinuationTokens[raw.NextContinuationToken] > maxS3ContinuationTokenOccurrences {
			return nil, fmt.Errorf("S3 list continuation token repeated")
		}
		continuationToken = raw.NextContinuationToken
	}
}

func (c *HTTPObjectClient) do(req *http.Request, dst any) error {
	_, err := c.doWithResponseBytes(req, dst)
	return err
}

func (c *HTTPObjectClient) doWithResponseBytes(req *http.Request, dst any) (int64, error) {
	return c.doWithResponseByteLimit(req, dst, maxS3ListResponseBytes)
}

func (c *HTTPObjectClient) doWithResponseByteLimit(req *http.Request, dst any, byteLimit int64) (int64, error) {
	if byteLimit < 1 {
		return 0, errS3ResponseBodyTooLarge
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("S3 returned status %d", resp.StatusCode)
	}
	if dst == nil {
		return 0, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, byteLimit+1))
	if err != nil {
		return int64(len(data)), err
	}
	if int64(len(data)) > byteLimit {
		return int64(len(data)), errS3ResponseBodyTooLarge
	}
	if err := xml.Unmarshal(data, dst); err != nil {
		return int64(len(data)), err
	}
	return int64(len(data)), nil
}
func (c *HTTPObjectClient) request(ctx context.Context, method, bucket, key string, q url.Values, ct string, body []byte) (*http.Request, error) {
	u := *c.endpoint
	if c.pathStyle {
		u.Path = path.Join(u.Path, bucket, key)
	} else {
		u.Host = bucket + "." + u.Host
		u.Path = path.Join(u.Path, key)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	c.sign(req, body)
	return req, nil
}
func (c *HTTPObjectClient) sign(req *http.Request, body []byte) {
	now := time.Now().UTC()
	date := now.Format("20060102")
	amz := now.Format("20060102T150405Z")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", amz)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	if c.credential.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.credential.SessionToken)
	}
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if c.credential.SessionToken != "" {
		headers = append(headers, "x-amz-security-token")
	}
	sort.Strings(headers)
	var canonical strings.Builder
	for _, h := range headers {
		v := req.Header.Get(h)
		if h == "host" {
			v = req.Host
			if v == "" {
				v = req.URL.Host
			}
		}
		canonical.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	signed := strings.Join(headers, ";")
	canonicalRequest := req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.Query().Encode() + "\n" + canonical.String() + "\n" + signed + "\n" + payload
	cr := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + c.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(cr[:])
	kDate := hmacSum([]byte("AWS4"+c.credential.SecretAccessKey), date)
	kRegion := hmacSum(kDate, c.region)
	kService := hmacSum(kRegion, "s3")
	sig := hex.EncodeToString(hmacSum(hmacSum(kService, "aws4_request"), stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.credential.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
func hmacSum(key []byte, value string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return m.Sum(nil)
}
