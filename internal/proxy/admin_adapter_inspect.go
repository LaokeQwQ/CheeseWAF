package proxy

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/adapterapi"
	"github.com/LaokeQwQ/CheeseWAF/internal/adapterinspect"
)

func (s *Server) InspectAdminAdapter(ctx context.Context, request adapterinspect.Request) (adapterinspect.Decision, error) {
	result, err := s.InspectAdapter(ctx, adapterapi.Request{
		ContractVersion: request.ContractVersion, RequestID: request.RequestID,
		Source: adapterapi.Source(request.Source), Method: request.Method,
		Scheme: request.Scheme, Authority: request.Authority, Path: request.Path,
		Query: request.Query, Headers: request.Headers, BodyForwarded: request.BodyForwarded,
		Body: request.Body, BodyTruncated: request.BodyTruncated,
		Client: adapterapi.ClientContext{IP: request.Client.IP, UserAgent: request.Client.UserAgent},
	})
	if err != nil {
		return adapterinspect.Decision{}, err
	}
	return adapterinspect.Decision{
		ContractVersion: result.ContractVersion, Action: string(result.Action),
		StatusCode: result.StatusCode, Reason: result.Reason, RuleID: result.RuleID,
		PolicyVersion: result.PolicyVersion, Headers: result.Headers, Metadata: result.Metadata,
	}, nil
}
