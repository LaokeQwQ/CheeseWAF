import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import i18n from '../../i18n';
import { fallbackSystem } from '../System/systemModel';
import UpdatesPage from './UpdatesPage';

vi.mock('../../api/client', () => ({
  fetchSystemConfig: vi.fn(),
}));

import { fetchSystemConfig } from '../../api/client';

const mockedFetchSystemConfig = vi.mocked(fetchSystemConfig);

describe('updates availability state', () => {
  it('shows unavailable states without operational update or feed controls', async () => {
    await i18n.changeLanguage('en-US');
    mockedFetchSystemConfig.mockResolvedValue({
      ...fallbackSystem,
      capabilities: {
        ota_updates: { available: false, reason: 'NOT_IMPLEMENTED' },
        vulnerability_feeds: { available: false, reason: 'NOT_IMPLEMENTED' },
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
