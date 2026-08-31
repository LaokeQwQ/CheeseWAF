import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import i18n, { ensureLanguage } from '../../i18n';
import { fallbackSystem } from '../System/systemModel';
import UpdatesPage from './UpdatesPage';

vi.mock('../../api/client', () => ({
  fetchSystemConfig: vi.fn(),
}));

import { fetchSystemConfig } from '../../api/client';

const mockedFetchSystemConfig = vi.mocked(fetchSystemConfig);

describe('updates availability state', () => {
  it('shows unavailable states without operational update or feed controls', async () => {
    // Only the default locale ships in the entry chunk, so the English bundle
    // has to be fetched before switching or every t() call returns the raw key.
    await ensureLanguage('en-US');
    await i18n.changeLanguage('en-US');
    mockedFetchSystemConfig.mockResolvedValue({
      ...fallbackSystem,
      capabilities: {
        ota_updates: { available: false, reason: 'NOT_IMPLEMENTED' },
        vulnerability_feeds: { available: false, reason: 'NOT_IMPLEMENTED' },
        bot_challenge_redis: { available: false, reason: 'NOT_IMPLEMENTED' },
      },
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
});
