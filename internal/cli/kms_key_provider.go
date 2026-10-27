package cli

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/recovery/kms"
)

// kmsEnvelopeProvider adapts the binding-scoped KMS runtime to the envelope key
// provider contract consumed by the diagnostics subsystem. The runtime binding
// supplies tenant/key/scope/actor; the envelope only chooses the key version.
type kmsEnvelopeProvider struct {
	runtime *kms.Runtime
}

func (p kmsEnvelopeProvider) Wrap(ctx context.Context, version string, dek []byte) ([]byte, error) {
	return p.runtime.Wrap(ctx, version, dek)
}

func (p kmsEnvelopeProvider) Unwrap(ctx context.Context, version string, wrapped []byte) ([]byte, error) {
	return p.runtime.Unwrap(ctx, version, wrapped)
}

// Available reports whether the runtime was composed. The runtime constructor
// already enforces at least one usable backend, so a composed runtime is either
// externally backed or an explicitly approved single-node keyring.
func (p kmsEnvelopeProvider) Available(context.Context) bool {
	return p.runtime != nil
}
