import { apiClient, unwrapAPIResponse } from './client';
import type { CAPTCHAAsset, CAPTCHAAssetConfig, CAPTCHAAssetConfigUpdate, CAPTCHAAssetKind } from '../types/api';

export async function fetchCAPTCHAAssets(kind?: CAPTCHAAssetKind) {
  const result = await unwrapAPIResponse<{ items?: CAPTCHAAsset[] | null }>(apiClient.get('/captcha/assets', { params: kind ? { kind } : undefined }));
  return { items: Array.isArray(result?.items) ? result.items : [] };
}

export function uploadCAPTCHAAsset(kind: CAPTCHAAssetKind, file: File) {
  const body = new FormData();
  body.append('kind', kind);
  body.append('file', file, file.name);
  return unwrapAPIResponse<CAPTCHAAsset>(apiClient.post('/captcha/assets', body, { headers: { 'Content-Type': 'multipart/form-data' } }));
}

export function deleteCAPTCHAAsset(id: string) {
  return unwrapAPIResponse<{ deleted: boolean }>(apiClient.delete(`/captcha/assets/${encodeURIComponent(id)}`));
}

export async function fetchCAPTCHAAssetPreview(id: string) {
  const ticket = await unwrapAPIResponse<{ reference: string; expires_in: number }>(apiClient.post(`/captcha/assets/${encodeURIComponent(id)}/preview`));
  const response = await apiClient.get<Blob>(`/captcha/assets/preview/${encodeURIComponent(ticket.reference)}`, { responseType: 'blob' });
  return { blob: response.data, expiresIn: ticket.expires_in };
}

export function fetchCAPTCHAAssetConfig() {
  return unwrapAPIResponse<CAPTCHAAssetConfig>(apiClient.get('/captcha/assets/config'));
}

export function updateCAPTCHAAssetConfig(config: CAPTCHAAssetConfigUpdate) {
  return unwrapAPIResponse<CAPTCHAAssetConfig>(apiClient.put('/captcha/assets/config', config));
}

export function testCAPTCHAAssetConfig(config: CAPTCHAAssetConfigUpdate) {
  return unwrapAPIResponse<{ ok: boolean }>(apiClient.post('/captcha/assets/config/test', config));
}
