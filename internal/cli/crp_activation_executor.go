package cli

import (
	"context"
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

// ProductionCRPActivationExecutor adapts the process-owned activation service
// to the management API. Authority remains owned by the service: the adapter
// neither accepts nor synthesizes approval claims, confirmations, fences, or
// any other authorization material.
type ProductionCRPActivationExecutor struct {
	service *activation.Service
}

var _ handler.CRPActivationExecutor = (*ProductionCRPActivationExecutor)(nil)

// NewProductionCRPActivationExecutor binds an already-configured production
// activation service to the management API executor seam.
func NewProductionCRPActivationExecutor(service *activation.Service) (*ProductionCRPActivationExecutor, error) {
	if service == nil {
		return nil, fmt.Errorf("%w: activation service is required", ErrProductionCRPUnavailable)
	}
	return &ProductionCRPActivationExecutor{service: service}, nil
}

// ExecuteCRPActivation submits the authority-free request to the bounded
// activation worker and waits for its final receipt. Submission failures and
// worker results are returned unchanged so the HTTP layer can map stable
// cancellation, queue, authorization, and runtime errors.
func (e *ProductionCRPActivationExecutor) ExecuteCRPActivation(ctx context.Context, request activation.AsyncRequest) (activation.ActivationResult, error) {
	if e == nil || e.service == nil {
		return activation.ActivationResult{}, ErrProductionCRPUnavailable
	}
	if request.Fence != (activation.Fence{}) || request.Confirmation != nil {
		return activation.ActivationResult{}, activation.ErrAuthorizationInjection
	}
	receipt, err := e.service.SubmitAsync(ctx, request)
	if err != nil {
		return activation.ActivationResult{}, err
	}
	return receipt.Wait(ctx)
}
