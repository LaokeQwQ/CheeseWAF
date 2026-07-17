import { beforeEach, describe, expect, it, vi } from 'vitest';

const client = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() }));
vi.mock('./client', () => ({ apiClient: client, unwrapAPIResponse: <T>(value: Promise<{ data: { data: T } }>) => value.then((response) => response.data.data) }));

import { fetchCAPTCHAAssetPreview, fetchCAPTCHAAssets, uploadCAPTCHAAsset } from './captchaAssets';

describe('captchaAssets API', () => {
  beforeEach(() => vi.clearAllMocks());
  it('sends the selected kind as the list filter', async () => {
    client.get.mockResolvedValue({ data: { data: { items: [] } } });
    await fetchCAPTCHAAssets('icon');
    expect(client.get).toHaveBeenCalledWith('/captcha/assets', { params: { kind: 'icon' } });
  });
  it('normalizes a null asset collection to an empty list', async () => {
    client.get.mockResolvedValue({ data: { data: { items: null } } });
    await expect(fetchCAPTCHAAssets()).resolves.toEqual({ items: [] });
  });
  it('uploads kind and file as multipart form data', async () => {
    client.post.mockResolvedValue({ data: { data: { id: 'a' } } });
    const file = new File(['asset'], 'asset.png', { type: 'image/png' });
    await uploadCAPTCHAAsset('background', file);
    const body = client.post.mock.calls[0]?.[1] as FormData;
    expect(body.get('kind')).toBe('background');
    expect(body.get('file')).toBeInstanceOf(File);
  });
  it('issues and immediately consumes a one-time preview reference as a blob', async () => {
    client.post.mockResolvedValue({ data: { data: { reference: 'once', expires_in: 120 } } });
    const blob = new Blob(['image'], { type: 'image/png' });
    client.get.mockResolvedValue({ data: blob });
    await expect(fetchCAPTCHAAssetPreview('asset/id')).resolves.toEqual({ blob, expiresIn: 120 });
    expect(client.post).toHaveBeenCalledWith('/captcha/assets/asset%2Fid/preview');
    expect(client.get).toHaveBeenCalledWith('/captcha/assets/preview/once', { responseType: 'blob' });
  });
});
