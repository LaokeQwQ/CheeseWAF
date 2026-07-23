import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchLogs: vi.fn(),
  fetchMonitorSummary: vi.fn(),
  fetchSites: vi.fn(),
  reclaimSystemResources: vi.fn(),
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
  useTranslation: () => ({ t: (key: string, opts?: Record<string, unknown>) => (opts ? `${key}:${JSON.stringify(opts)}` : key) }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import DashboardPage from './DashboardPage';

function log(partial: Record<string, unknown>) {
  return {
    id: String(Math.random()),
    timestamp: new Date().toISOString(),
    client_ip: '1.1.1.1',
    method: 'GET',
    uri: '/',
    action: 'pass',
    category: '',
    severity: '',
    status_code: 200,
    latency: 2_000_000,
    message: '',
    ...partial,
  };
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchMonitorSummary.mockResolvedValue({
    snapshot: {
      requests: 500,
      blocked: 20,
      sites: 2,
      process_count: 2,
      memory_alloc: 4 * 1024 * 1024,
      host: { cpu_percent: 12, memory_percent: 40, disk_percent: 55, swap_percent: 5, cpu_count: 4, load1: 0.5 },
    },
    alerts: [],
  });
  apiMocks.fetchLogs.mockImplementation(async (query: { start?: string; end?: string; limit?: number }) => {
    const now = Date.now();
    return {
      items: [
        log({ action: 'block', category: 'sqli', timestamp: new Date(now - 10_000).toISOString(), latency: 5_000_000 }),
        log({ action: 'block', category: 'xss', timestamp: new Date(now - 20_000).toISOString() }),
        log({ action: 'pass', timestamp: new Date(now - 5_000).toISOString() }),
        log({ action: 'pass', timestamp: new Date(now - 2_000).toISOString() }),
      ].slice(0, query.limit ?? 100),
      total: 4,
    };
  });
  apiMocks.fetchSites.mockResolvedValue([
    { id: 's1', name: 'one', domains: ['a.com'], upstreams: ['127.0.0.1:1'], enabled: true },
    { id: 's2', name: 'two', domains: ['b.com'], upstreams: ['127.0.0.1:2'], enabled: false },
  ]);
});

afterEach(() => {
  cleanup();
});

describe('DashboardPage', () => {
  it('loads monitor, logs, and sites then shows period block totals', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchMonitorSummary).toHaveBeenCalled());
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalled());
    await waitFor(() => expect(apiMocks.fetchSites).toHaveBeenCalled());
    expect(await screen.findByText('dashboard.title')).toBeTruthy();
    // 2 blocked in period logs fixture
    expect(screen.getAllByText('2').length).toBeGreaterThan(0);
    expect(screen.getByText('dashboard.totalBlocked')).toBeTruthy();
    expect(screen.getByText('dashboard.sites')).toBeTruthy();
  });

  it('reclaims memory through mutation and reports success', async () => {
    apiMocks.reclaimSystemResources.mockResolvedValue({
      ok: true,
      actions: [{ name: 'gc', ok: true }, { name: 'trim', ok: true }],
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchMonitorSummary).toHaveBeenCalled());
    await screen.findByText('dashboard.resources');
    const memoryBtn = screen.getByText('dashboard.reclaimMemory').closest('button');
    expect(memoryBtn).toBeTruthy();
    fireEvent.click(memoryBtn!);
    await waitFor(() => expect(apiMocks.reclaimSystemResources).toHaveBeenCalled());
    expect(apiMocks.reclaimSystemResources.mock.calls[0]?.[0]).toBe('memory');
    expect(messageMocks.success).toHaveBeenCalled();
  });

  it('surfaces reclaim failures', async () => {
    apiMocks.reclaimSystemResources.mockRejectedValue(new Error('permission denied'));
    renderPage();
    await waitFor(() => expect(apiMocks.fetchMonitorSummary).toHaveBeenCalled());
    await screen.findByText('dashboard.resources');
    const swapBtn = screen.getByText('dashboard.reclaimSwap').closest('button');
    expect(swapBtn).toBeTruthy();
    fireEvent.click(swapBtn!);
    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith('permission denied'));
  });
});
