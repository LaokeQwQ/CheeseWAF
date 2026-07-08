package store

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("cluster object not found")

type Key struct {
	Kind string
	ID   string
}

type Event struct {
	Type  string
	Key   Key
	Value []byte
}

type Status struct {
	Provider          string `json:"provider"`
	MajorityConfirmed bool   `json:"majority_confirmed"`
	ReadOnly          bool   `json:"read_only"`
	ObjectCount       int    `json:"object_count"`
}

type Store interface {
	Get(ctx context.Context, key Key) ([]byte, error)
	List(ctx context.Context, kind string) (map[Key][]byte, error)
	Put(ctx context.Context, key Key, value []byte) error
	Delete(ctx context.Context, key Key) error
	Status(ctx context.Context) (Status, error)
}
