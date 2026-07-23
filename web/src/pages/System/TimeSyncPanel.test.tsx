import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TimeSyncConfig } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  fetchTimeSyncStatus: vi.fn(),
  reselectTimeSync: vi.fn(),
  syncTimeNow: vi.fn(),
}));

const messageMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('@arco-design/web-react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@arco-design/web-react')>();
  return { ...actual, Message: messageMocks };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => (opts ? `${key}:${JSON.stringify(opts)}` : key),
  }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import TimeSyncPanel from './TimeSyncPanel';

const baseConfig: TimeSyncConfig = {
  enabled: true,
  sources: ['ntp-a.example.test', 'ntp-b.example.test'],
  selection_interval: 24 * 60 * 60 * 1_000_000_000,
  sync_interval: 30 * 60 * 1_000_000_000,
  timeout: 2 * 1_000_000_000,
  samples_per_source: 3,
  max_accepted_offset: 5 * 60 * 1_000_000_000,
  max_root_dispersion: 2 * 1_000_000_000,
  consensus_tolerance: 250 * 1_000_000,
};

const statusFixture = {
  enabled: true,
  state: 'synchronized',
  active_source: 'ntp-a.example.test',
  primary_source: 'ntp-a.example.test',
  backup_source: 'ntp-b.example.test',
  current_time: '2026-07-01T12:00:00Z',
  offset_ms: 1.5,
  rtt_ms: 12,
  stratum: 2,
  last_success: '2026-07-01T11:59:00Z',
  last_attempt: '2026-07-01T12:00:00Z',
  consecutive_failures: 0,
  total_failures: 1,
  last_error: '',
};

function renderPanel(config: TimeSyncConfig = baseConfig, onChange = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <TimeSyncPanel value={config} onChange={onChange} />
    </QueryClientProvider>,
  );
  return { client, onChange };
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchTimeSyncStatus.mockResolvedValue(statusFixture);
  apiMocks.reselectTimeSync.mockResolvedValue({ ...statusFixture, active_source: 'ntp-b.example.test' });
  apiMocks.syncTimeNow.mockResolvedValue({ ...statusFixture, offset_ms: 0.2 });
});

afterEach(() => {
  cleanup();
});

describe('TimeSyncPanel', () => {
  it('loads runtime status and shows active NTP source metrics', async () => {
    renderPanel();
    await waitFor(() => expect(apiMocks.fetchTimeSyncStatus).toHaveBeenCalled());
    expect(await screen.findByText('system.timeSync')).toBeTruthy();
    expect(screen.getAllByText('ntp-a.example.test').length).toBeGreaterThan(0);
    expect(screen.getAllByText('ntp-b.example.test').length).toBeGreaterThan(0);
    expect(screen.getByText('system.timeSyncOffset')).toBeTruthy();
    expect(screen.getByText('+1.5 ms')).toBeTruthy();
    expect(screen.getByText('12 ms')).toBeTruthy();
    expect(screen.getByText('system.timeSyncStateSynchronized')).toBeTruthy();
  });

  it('runs reselect and sync-now mutations when enabled', async () => {
    renderPanel();
    await waitFor(() => expect(screen.getByText('system.timeSyncStateSynchronized')).toBeTruthy());

    const reselect = screen.getByRole('button', { name: /system\.timeSyncReselect/ });
    expect((reselect as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(reselect);
    await waitFor(() => expect(apiMocks.reselectTimeSync).toHaveBeenCalled());
    expect(messageMocks.success).toHaveBeenCalledWith('system.timeSyncReselectSuccess');

    const syncNow = screen.getByRole('button', { name: /system\.timeSyncNow/ });
    fireEvent.click(syncNow);
    await waitFor(() => expect(apiMocks.syncTimeNow).toHaveBeenCalled());
    expect(messageMocks.success).toHaveBeenCalledWith('system.timeSyncNowSuccess');
  });

  it('disables reselect/sync operations when time sync is off', async () => {
    apiMocks.fetchTimeSyncStatus.mockResolvedValue({ ...statusFixture, enabled: false, state: 'disabled' });
    renderPanel({ ...baseConfig, enabled: false });
    await waitFor(() => expect(apiMocks.fetchTimeSyncStatus).toHaveBeenCalled());
    await waitFor(() => {
      const reselect = screen.getByRole('button', { name: /system\.timeSyncReselect/ }) as HTMLButtonElement;
      expect(reselect.disabled || reselect.className.includes('disabled')).toBe(true);
    });
  });

  it('patches sources through onChange when textarea is edited', async () => {
    const onChange = vi.fn();
    renderPanel(baseConfig, onChange);
    await waitFor(() => expect(apiMocks.fetchTimeSyncStatus).toHaveBeenCalled());

    const textarea = screen.getByPlaceholderText('system.timeSyncSourcesPlaceholder');
    fireEvent.change(textarea, { target: { value: 'pool.ntp.org\ntime.cloudflare.com' } });
    expect(onChange).toHaveBeenCalledWith({ sources: ['pool.ntp.org', 'time.cloudflare.com'] });
  });

  it('shows status unavailable error with retry', async () => {
    apiMocks.fetchTimeSyncStatus.mockRejectedValueOnce(new Error('ntp offline'));
    renderPanel();
    expect(await screen.findByText('system.timeSyncStatusUnavailable')).toBeTruthy();
    apiMocks.fetchTimeSyncStatus.mockResolvedValue(statusFixture);
    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));
    await waitFor(() => expect(apiMocks.fetchTimeSyncStatus).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByText('system.timeSyncStateSynchronized')).toBeTruthy());
    expect(screen.getAllByText('ntp-a.example.test').length).toBeGreaterThan(0);
  });

  it('surfaces last_error from runtime status', async () => {
    apiMocks.fetchTimeSyncStatus.mockResolvedValue({
      ...statusFixture,
      last_error: 'stratum too high',
      consecutive_failures: 3,
      total_failures: 9,
    });
    renderPanel();
    expect(await screen.findByText('system.timeSyncLastError')).toBeTruthy();
    expect(screen.getByText('stratum too high')).toBeTruthy();
  });
});
