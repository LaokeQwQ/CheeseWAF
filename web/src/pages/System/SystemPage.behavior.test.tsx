import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SystemConfig, TimeSyncConfig } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  createManagementAPIToken: vi.fn(),
  fetchManagementAPITokens: vi.fn(),
  fetchSystemConfig: vi.fn(),
  fetchTimeSyncStatus: vi.fn(),
  reselectTimeSync: vi.fn(),
  revokeManagementAPIToken: vi.fn(),
  syncTimeNow: vi.fn(),
  testStorageBackend: vi.fn(),
  updateSystemConfig: vi.fn(),
}));

const messageMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('@arco-design/web-react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@arco-design/web-react')>();
  return {
    ...actual,
    Message: messageMocks,
  };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../i18n', () => ({
  default: { changeLanguage: vi.fn() },
}));

vi.mock('../../stores', () => ({
  useAppStore: (selector: (state: Record<string, unknown>) => unknown) => selector({
    language: 'zh-CN',
    setLanguage: vi.fn(),
    setTheme: vi.fn(),
    theme: 'light',
  }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return {
    ...actual,
    ...apiMocks,
  };
});

import { APIRequestError } from '../../api/client';
import SystemPage from './SystemPage';
import { fallbackSystem, normalizeSystem } from './systemModel';

const backendTimeSyncConfig: TimeSyncConfig = {
  enabled: true,
  sources: ['ntp-a.example.test', 'ntp-b.example.test', 'ntp-c.example.test'],
  selection_interval: 24 * 60 * 60 * 1_000_000_000,
  sync_interval: 30 * 60 * 1_000_000_000,
  timeout: 2 * 1_000_000_000,
  samples_per_source: 3,
  max_accepted_offset: 5 * 60 * 1_000_000_000,
  max_root_dispersion: 2 * 1_000_000_000,
  consensus_tolerance: 250 * 1_000_000,
};

function systemWithListen(listen: string): SystemConfig {
  return normalizeSystem({
    ...fallbackSystem,
    server: { ...fallbackSystem.server, listen },
    time_sync: backendTimeSyncConfig,
  });
}

function renderSystem() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  const invalidateQueries = vi.spyOn(client, 'invalidateQueries');
  render(
    <QueryClientProvider client={client}>
      <SystemPage />
    </QueryClientProvider>,
  );
  return { client, invalidateQueries };
}

async function editRuntimeListenAndSave(initialValue: string, value: string) {
  const input = await screen.findByDisplayValue(initialValue);
  fireEvent.change(input, { target: { value } });
  fireEvent.click(screen.getAllByRole('button', { name: 'common.save' })[0]);
  return input as HTMLInputElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchManagementAPITokens.mockResolvedValue({ items: [] });
  apiMocks.fetchSystemConfig.mockResolvedValue(systemWithListen(':18080'));
  apiMocks.fetchTimeSyncStatus.mockResolvedValue({
    enabled: true,
    state: 'synchronized',
    primary_source: 'ntp-a.example.test',
    backup_source: 'ntp-b.example.test',
    active_source: 'ntp-a.example.test',
    offset_ms: 125,
    rtt_ms: 18,
    stratum: 2,
    last_success: '2026-07-15T10:00:00Z',
    last_attempt: '2026-07-15T10:00:00Z',
    consecutive_failures: 1,
    total_failures: 4,
    current_time: '2026-07-15T10:01:00Z',
  });
  apiMocks.reselectTimeSync.mockResolvedValue({
    enabled: true,
    state: 'synchronized',
    active_source: 'ntp-b.example.test',
    offset_ms: 20,
    rtt_ms: 10,
    consecutive_failures: 0,
    total_failures: 4,
    current_time: '2026-07-15T10:02:00Z',
  });
  apiMocks.syncTimeNow.mockResolvedValue({
    enabled: true,
    state: 'synchronized',
    active_source: 'ntp-a.example.test',
    offset_ms: 5,
    rtt_ms: 12,
    consecutive_failures: 0,
    total_failures: 4,
    current_time: '2026-07-15T10:02:00Z',
  });
});

afterEach(() => {
  cleanup();
});

describe('SystemPage persistence failures', () => {
  it.each([
    { code: 'FORBIDDEN', message: '403 permission denied', status: 403 },
    { code: 'CONFIG_CONFLICT', message: '409 configuration was modified', status: 409 },
  ])('shows the $status error without reporting success or invalidating state', async ({ code, message, status }) => {
    const initial = systemWithListen(':18080');
    apiMocks.fetchSystemConfig.mockResolvedValue(initial);
    apiMocks.updateSystemConfig.mockRejectedValue(new APIRequestError(message, code, status));
    const { client, invalidateQueries } = renderSystem();

    const input = await editRuntimeListenAndSave(':18080', ':8080');

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith(message));
    expect(messageMocks.success).not.toHaveBeenCalled();
    expect(invalidateQueries).not.toHaveBeenCalled();
    expect(apiMocks.fetchSystemConfig).toHaveBeenCalledTimes(1);
    expect(client.getQueryData(['system'])).toEqual(initial);
    expect(input.value).toBe(':8080');
  });
});

describe('SystemPage persistence success', () => {
  it('invalidates and rereads the saved runtime configuration', async () => {
    const initial = systemWithListen(':18080');
    const persisted = systemWithListen(':8080');
    apiMocks.fetchSystemConfig
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(persisted);
    apiMocks.updateSystemConfig.mockResolvedValue(persisted);
    const { client, invalidateQueries } = renderSystem();

    await editRuntimeListenAndSave(':18080', ':8080');

    await waitFor(() => expect(apiMocks.updateSystemConfig.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      server: expect.objectContaining({ listen: ':8080' }),
      time_sync: expect.objectContaining({
        enabled: true,
        selection_interval: backendTimeSyncConfig.selection_interval,
        sync_interval: backendTimeSyncConfig.sync_interval,
      }),
    })));
    await waitFor(() => expect(apiMocks.fetchSystemConfig).toHaveBeenCalledTimes(2));
    await waitFor(() => expect((screen.getByDisplayValue(':8080') as HTMLInputElement).value).toBe(':8080'));
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['system'] });
    expect(client.getQueryData(['system'])).toEqual(persisted);
    expect(messageMocks.success).toHaveBeenCalledWith('system.saved');
    expect(messageMocks.error).not.toHaveBeenCalled();
  });

  it('shows calibrated runtime status and invokes both time synchronization operations', async () => {
    renderSystem();

    expect((await screen.findAllByText('ntp-a.example.test')).length).toBeGreaterThan(0);
    expect(screen.getByText('+125 ms')).toBeTruthy();
    expect(screen.getByText('18 ms')).toBeTruthy();

    const reselect = screen.getByRole('button', { name: 'system.timeSyncReselect' });
    const sync = screen.getByRole('button', { name: 'system.timeSyncNow' });
    await waitFor(() => expect((sync as HTMLButtonElement).disabled).toBe(false));

    fireEvent.click(reselect);
    await waitFor(() => expect(apiMocks.reselectTimeSync).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(messageMocks.success).toHaveBeenCalledWith('system.timeSyncReselectSuccess'));

    fireEvent.click(sync);
    await waitFor(() => expect(apiMocks.syncTimeNow).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(messageMocks.success).toHaveBeenCalledWith('system.timeSyncNowSuccess'));
  });
});
