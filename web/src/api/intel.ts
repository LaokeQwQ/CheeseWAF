import axios from 'axios';
import i18n from '../i18n';
import { APIRequestError, apiClient } from './client';
import type {
  IntelApproveRequest,
  IntelCandidateQuery,
  IntelCandidateResponse,
  IntelCandidatesResponse,
  IntelImpactResponse,
  IntelImportRequest,
  IntelImportResponse,
  IntelItemsResponse,
  IntelRejectRequest,
} from '../types/api';

/**
 * Intel handlers return bare JSON objects (`{"candidates":[]}`) and errors as
 * `{"error":{"code","message","reasons"}}` instead of the management-plane
 * `{data,error}` envelope, so the shared `unwrapAPIResponse` helper cannot be
 * used here. Preserve the server's review reasons because 409 responses from
 * approval are only useful with them.
 */
type IntelErrorEnvelope = {
  error?: {
    code?: unknown;
    message?: unknown;
    reasons?: unknown;
  };
};

function intelRequestError(error: unknown): unknown {
  if (!axios.isAxiosError(error)) {
    return error;
  }
  const response = error.response;
  const detail = (response?.data as IntelErrorEnvelope | undefined)?.error;
  if (detail && typeof detail.message === 'string') {
    const reasons = Array.isArray(detail.reasons)
      ? detail.reasons.filter((reason): reason is string => typeof reason === 'string' && reason.trim() !== '')
      : [];
    const message = reasons.length > 0 ? `${detail.message} (${reasons.join('; ')})` : detail.message;
    return new APIRequestError(
      message,
      typeof detail.code === 'string' ? detail.code : undefined,
      response?.status,
    );
  }
  if (response?.status) {
    return new APIRequestError(error.message, undefined, response.status);
  }
  return new APIRequestError(i18n.t('ai.intelNetworkError'), 'NETWORK_ERROR');
}

async function unwrapIntel<T>(request: Promise<{ data: T }>): Promise<T> {
  try {
    const response = await request;
    return response.data;
  } catch (error) {
    throw intelRequestError(error);
  }
}

export function importIntelURL(payload: IntelImportRequest) {
  // The server fetches the advisory before answering, so allow more than the
  // default management-plane timeout.
  return unwrapIntel<IntelImportResponse>(apiClient.post('/intel/import-url', payload, { timeout: 60_000 }));
}

export function fetchIntelItems(limit = 50) {
  return unwrapIntel<IntelItemsResponse>(apiClient.get('/intel/items', { params: { limit } }));
}

export function fetchIntelCandidates(query: IntelCandidateQuery = {}) {
  const params: Record<string, string | number> = {};
  if (query.site_id) {
    params.site_id = query.site_id;
  }
  if (query.state) {
    params.state = query.state;
  }
  if (query.limit) {
    params.limit = query.limit;
  }
  return unwrapIntel<IntelCandidatesResponse>(
    apiClient.get('/intel/candidates', Object.keys(params).length > 0 ? { params } : undefined),
  );
}

export function fetchIntelCandidate(id: string) {
  return unwrapIntel<IntelCandidateResponse>(apiClient.get(`/intel/candidates/${encodeURIComponent(id)}`));
}

export function approveIntelCandidate(id: string, payload: IntelApproveRequest) {
  return unwrapIntel<IntelCandidateResponse>(
    apiClient.post(`/intel/candidates/${encodeURIComponent(id)}/approve`, payload),
  );
}

export function rejectIntelCandidate(id: string, payload: IntelRejectRequest = {}) {
  return unwrapIntel<IntelCandidateResponse>(
    apiClient.post(`/intel/candidates/${encodeURIComponent(id)}/reject`, payload),
  );
}

export function fetchIntelImpact(siteId: string) {
  return unwrapIntel<IntelImpactResponse>(apiClient.get('/intel/impact', { params: { site_id: siteId } }));
}
