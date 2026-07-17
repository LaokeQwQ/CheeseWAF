package assets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

var (
	ErrNotFound          = errors.New("captcha asset not found")
	ErrInvalidAsset      = errors.New("invalid captcha asset")
	ErrReferenceExpired  = errors.New("captcha asset reference expired")
	ErrReferenceUsed     = errors.New("captcha asset reference already used")
	ErrReferenceCapacity = errors.New("captcha asset reference capacity reached")
)

type Kind string

const (
	KindBackground Kind = "background"
	KindFont       Kind = "font"
	KindIcon       Kind = "icon"
	KindLogo       Kind = "logo"
)

// DefaultLogoPath is a logical managed-resource name, never a filesystem route.
const DefaultLogoPath = "/cheesewaf-logo.png"

type Asset struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
	MetadataMAC string    `json:"metadata_mac,omitempty"`
}

type PutRequest struct {
	Kind        Kind
	Name        string
	ContentType string
	Reader      io.Reader
}

type Store interface {
	Put(context.Context, PutRequest) (Asset, error)
	Open(context.Context, string) (Asset, io.ReadCloser, error)
	List(context.Context, Kind) ([]Asset, error)
	Delete(context.Context, string) error
}

// ObjectClient keeps vendor SDKs outside the CAPTCHA security boundary.
type ObjectClient interface {
	PutObject(ctx context.Context, bucket, key, contentType string, body io.Reader, size int64) error
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	DeleteObject(ctx context.Context, bucket, key string) error
	ListObjects(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error)
}

type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

func newAsset(id string, kind Kind, name, contentType string, data []byte) Asset {
	sum := sha256.Sum256(data)
	return Asset{
		ID: id, Kind: kind, Name: safeDisplayName(name), ContentType: contentType,
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC(),
	}
}
