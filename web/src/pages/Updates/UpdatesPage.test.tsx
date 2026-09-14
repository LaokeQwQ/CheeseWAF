import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import i18n, { ensureLanguage } from '../../i18n';
import { fallbackSystem } from '../System/systemModel';
import UpdatesPage from './UpdatesPage';

vi.mock('../../api/client', () => ({
  fetchSystemConfig: vi.fn(),
  fetchOTAStatus: vi.fn(),
}));

import { fetchOTAStatus, fetchSystemConfig } from '../../api/client';

const mockedFetchSystemConfig = vi.mocked(fetchSystemConfig);
const mockedFetchOTAStatus = vi.mocked(fetchOTAStatus);

describe('updates availability state', () => {
  it('shows unavailable states without operational update or feed controls', async () => {
    // Only the default locale ships in the entry chunk, so the English bundle
    // has to be fetched before switching or every t() call returns the raw key.
    await ensureLanguage('en-US');
    await i18n.changeLanguage('en-US');
    mockedFetchSystemConfig.mockResolvedValue({
      ...fallbackSystem,
      capabilities: {
        ota_updates: { available: false, reason: 'EXECUTOR_UNAVAILABLE' },
        vulnerability_feeds: { available: false, reason: 'NOT_IMPLEMENTED' },
        bot_challenge_redis: { available: false, reason: 'NOT_IMPLEMENTED' },
      },
    });
    mockedFetchOTAStatus.mockResolvedValue({
      enabled: true,
      available: false,
      candidate_available: false,
      read_only: true,
      channel: 'stable',
      reason: 'EXECUTOR_UNAVAILABLE',
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(<QueryClientProvider client={queryClient}><UpdatesPage /></QueryClientProvider>);

    expect(await screen.findByText('OTA updates are unavailable')).toBeTruthy();
    expect(screen.getByText('Vulnerability feeds are unavailable')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /save/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /sync key/i })).toBeNull();
    expect(screen.queryByRole('switch')).toBeNull();
    expect(screen.queryByRole('button', { name: /add/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /delete/i })).toBeNull();
  });

  it('shows a candidate as read-only and does not expose an install action', async () => {
    mockedFetchSystemConfig.mockResolvedValue({ ...fallbackSystem });
    mockedFetchOTAStatus.mockResolvedValue({
      enabled: true,
      available: false,
      candidate_available: true,
      read_only: true,
      channel: 'stable',
      reason: 'EXECUTOR_UNAVAILABLE',
      candidate: {
        release_id: 'official/demo@1.0.0#2',
        version: '1.0.0',
        release_sequence: 2,
        resource_url: 'https://res.cheesesec.com/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/demo.crp',
        crp_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        manifest_sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        signature_set_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        source_root: 'vendor-root-v1',
        trust_level: 'official',
        signature_status: 'verified',
      },
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><UpdatesPage /></QueryClientProvider>);
    expect(await screen.findByTestId('ota-candidate')).toBeTruthy();
    expect(screen.getByText('Read-only')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /install/i })).toBeNull();
  });
});
