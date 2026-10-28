package activation

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
)

type contractAuthorizationState struct {
	durable bool
}

func (s contractAuthorizationState) Durable() bool { return s.durable }

func (contractAuthorizationState) Put(context.Context, Authorization) error { return nil }

func (contractAuthorizationState) Get(context.Context, string) (Authorization, error) {
	return Authorization{}, ErrAuthorizationNotFound
}

func (contractAuthorizationState) Consume(context.Context, Authorization) error { return nil }

type contractAuthorizationProvider struct {
	durable bool
}

func (p contractAuthorizationProvider) Durable() bool { return p.durable }

func (contractAuthorizationProvider) Authorize(context.Context, TransportIdentity, AuthorizationRequest) (Authorization, error) {
	return Authorization{}, ErrAuthorizationDenied
}

func (contractAuthorizationProvider) Validate(context.Context, TransportIdentity, Authorization) error {
	return ErrAuthorizationDenied
}

func (contractAuthorizationProvider) Consume(context.Context, TransportIdentity, Authorization) error {
	return ErrAuthorizationDenied
}

func newProductionContractTestHandler(t *testing.T, state AuthorizationState, provider AuthorizationProvider) *ControlPlaneHandler {
	t.Helper()
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: "cluster-a",
		Role:      "waf",
		ClientCA:  x509.NewCertPool(),
		State:     state,
		Provider:  provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestValidateProductionControlPlaneHandlerRejectsMemoryAuthorizationState(t *testing.T) {
	state, err := NewMemoryAuthorizationState(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newProductionContractTestHandler(t, state, contractAuthorizationProvider{durable: true})
	if err := ValidateProductionControlPlaneHandler(h); !errors.Is(err, ErrProductionContract) {
		t.Fatalf("memory authorization state validation error = %v, want ErrProductionContract", err)
	}
}

func TestValidateProductionControlPlaneHandlerRejectsMissingOrNonDurableDependencies(t *testing.T) {
	tests := []struct {
		name     string
		state    AuthorizationState
		provider AuthorizationProvider
	}{
		{
			name:     "missing provider",
			state:    contractAuthorizationState{durable: true},
			provider: nil,
		},
		{
			name:     "non-durable state",
			state:    contractAuthorizationState{durable: false},
			provider: contractAuthorizationProvider{durable: true},
		},
		{
			name:     "non-durable provider",
			state:    contractAuthorizationState{durable: true},
			provider: contractAuthorizationProvider{durable: false},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var h *ControlPlaneHandler
			if test.provider == nil {
				h = newProductionContractTestHandlerWithCallbacks(t, test.state)
			} else {
				h = newProductionContractTestHandler(t, test.state, test.provider)
			}
			if err := ValidateProductionControlPlaneHandler(h); !errors.Is(err, ErrProductionContract) {
				t.Fatalf("validation error = %v, want ErrProductionContract", err)
			}
		})
	}
}

func newProductionContractTestHandlerWithCallbacks(t *testing.T, state AuthorizationState) *ControlPlaneHandler {
	t.Helper()
	h, err := NewControlPlaneHandler(ControlPlaneHandlerOptions{
		ClusterID: "cluster-a",
		Role:      "waf",
		ClientCA:  x509.NewCertPool(),
		State:     state,
		Authorize: func(context.Context, AuthorizationRequest, TransportIdentity) (Authorization, error) {
			return Authorization{}, ErrAuthorizationDenied
		},
		Validate: func(context.Context, TransportIdentity, Authorization) error {
			return ErrAuthorizationDenied
		},
		Consume: func(context.Context, TransportIdentity, Authorization) error {
			return ErrAuthorizationDenied
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestValidateProductionControlPlaneHandlerAcceptsDurableDependencies(t *testing.T) {
	h := newProductionContractTestHandler(t, contractAuthorizationState{durable: true}, contractAuthorizationProvider{durable: true})
	if err := ValidateProductionControlPlaneHandler(h); err != nil {
		t.Fatalf("durable authorization contract rejected: %v", err)
	}
}
