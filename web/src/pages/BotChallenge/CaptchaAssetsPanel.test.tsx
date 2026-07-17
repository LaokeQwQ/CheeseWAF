import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIRequestError } from '../../api/client';
import CaptchaAssetsPanel from './CaptchaAssetsPanel';

const api = vi.hoisted(() => ({ fetchCAPTCHAAssets: vi.fn(), fetchCAPTCHAAssetConfig: vi.fn(), uploadCAPTCHAAsset: vi.fn(), deleteCAPTCHAAsset: vi.fn(), fetchCAPTCHAAssetPreview: vi.fn(), updateCAPTCHAAssetConfig: vi.fn(), testCAPTCHAAssetConfig: vi.fn() }));
vi.mock('../../api/captchaAssets', () => api);
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string, options?: { name?: string }) => options?.name ? `${key}:${options.name}` : key, i18n: { resolvedLanguage: 'en-US' } }) }));

const config = { backend: 's3' as const, local: { path: './data' }, s3: { endpoint: 's3.example.test', bucket: 'captcha', region: 'us-east-1', path_style: true, prefix: 'assets', use_tls: true, allow_private_endpoint: true, request_timeout: 5_000_000_000, credential_configured: true, metadata_key_configured: true }, limits: { max_image_bytes: 100, max_font_bytes: 200, max_pixels: 300 } };
function renderPanel() { const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); return render(<QueryClientProvider client={client}><CaptchaAssetsPanel/></QueryClientProvider>); }

describe('CaptchaAssetsPanel', () => {
  afterEach(cleanup);
  beforeEach(() => { vi.clearAllMocks(); api.fetchCAPTCHAAssets.mockResolvedValue({ items: [] }); api.fetchCAPTCHAAssetConfig.mockResolvedValue(config); api.testCAPTCHAAssetConfig.mockResolvedValue({ ok: true }); });
  it('shows the empty state when no assets match', async () => {
    renderPanel();
    expect(await screen.findByText('botChallenge.captchaAssets.empty')).toBeTruthy();
    expect(api.fetchCAPTCHAAssets).toHaveBeenCalledWith(undefined);
  });
  it('masks configured credentials and does not put the stored secret in the input', async () => {
    renderPanel();
    fireEvent.click(screen.getByRole('tab', { name: 'botChallenge.captchaAssets.storage' }));
    const configured = await screen.findByText('botChallenge.captchaAssets.credentialConfigured');
    const credential = configured.closest('label')?.querySelector('input') as HTMLInputElement;
    expect(credential.type).toBe('password');
    expect(credential.value).toBe('');
    expect(credential.placeholder).not.toBe('');
  });
  it('renders a dedicated permission state for forbidden API responses', async () => {
    api.fetchCAPTCHAAssets.mockRejectedValue(new APIRequestError('forbidden', 'FORBIDDEN', 403));
    renderPanel();
    expect(await screen.findByText('botChallenge.captchaAssets.forbidden')).toBeTruthy();
    expect(screen.getByText('botChallenge.captchaAssets.forbiddenHint')).toBeTruthy();
  });
  it('echoes, submits, and warns about the S3 private endpoint setting', async () => {
    api.updateCAPTCHAAssetConfig.mockResolvedValue(config);
    renderPanel();
    fireEvent.click(screen.getByRole('tab', { name: 'botChallenge.captchaAssets.storage' }));

    const label = await screen.findByText('botChallenge.captchaAssets.allowPrivateEndpoint');
    const toggle = label.closest('label')?.querySelector('.arco-switch');
    expect(toggle?.classList.contains('arco-switch-checked')).toBe(true);
    expect(screen.getByText('botChallenge.captchaAssets.allowPrivateEndpointRisk')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('botChallenge.captchaAssets.endpoint'), { target: { value: 's3.changed.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'botChallenge.captchaAssets.test' }));
    await waitFor(() => expect(api.testCAPTCHAAssetConfig).toHaveBeenCalledTimes(1));
    expect(api.testCAPTCHAAssetConfig.mock.calls[0]?.[0].s3).toEqual(expect.objectContaining({ endpoint: 's3.changed.test', allow_private_endpoint: true }));

    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(api.updateCAPTCHAAssetConfig).toHaveBeenCalledTimes(1));
    expect(api.updateCAPTCHAAssetConfig.mock.calls[0]?.[0].s3).toEqual(expect.objectContaining({ endpoint: 's3.changed.test', allow_private_endpoint: true }));
  });
});
