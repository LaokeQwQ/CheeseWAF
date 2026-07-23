import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LogEntry } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  fetchLogs: vi.fn(),
  fetchMonitorSummary: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => (opts ? `${key}:${JSON.stringify(opts)}` : key),
  }),
}));

vi.mock('../../stores', () => ({
  useAppStore: (selector: (state: Record<string, unknown>) => unknown) => selector({ theme: 'dark' }),
}));

vi.mock('../../components/BrandLogo', () => ({
  default: () => <span data-testid="brand-logo" />,
}));

vi.mock('./GlobeMap', () => ({
  default: ({ regions }: { regions: Array<{ attacks: number }> }) => (
    <div data-testid="globe-map">globe:{regions.length}</div>
  ),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import AttackScreenPage from './AttackScreenPage';

function entry(partial: Partial<LogEntry>): LogEntry {
  const now = Date.now();
  return {
    id: partial.id ?? String(Math.random()),
    timestamp: partial.timestamp ?? new Date(now - 10_000).toISOString(),
    client_ip: partial.client_ip ?? '203.0.113.10',
    method: 'GET',
    uri: partial.uri ?? '/login',
    action: partial.action ?? 'block',
    category: partial.category ?? 'sqli',
    severity: partial.severity ?? 'critical',
    status_code: partial.status_code ?? 403,
    message: '',
    country: partial.country ?? 'CN',
    metadata: partial.metadata ?? { lat: 31.2, lon: 121.5 },
    ...partial,
  } as LogEntry;
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AttackScreenPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchLogs.mockResolvedValue({
    items: [
      entry({ id: 'a1', category: 'sqli', severity: 'critical', country: 'CN' }),
      entry({ id: 'a2', category: 'xss', severity: 'high', country: 'CN', client_ip: '203.0.113.11' }),
      entry({ id: 'a3', category: 'bot', severity: 'medium', country: 'US', client_ip: '8.8.8.8', metadata: { lat: 40, lon: -74 } }),
      entry({ id: 'p1', action: 'pass', status_code: 200, severity: '', category: '', country: 'JP' }),
    ],
    total: 4,
  });
  apiMocks.fetchMonitorSummary.mockResolvedValue({
    snapshot: { requests: 100, blocked: 3, process_count: 1, memory_alloc: 1 },
    alerts: [{ rule_id: 'r1', name: 'spike', severity: 'high', message: 'blocks up', value: 10, threshold: 5 }],
  });
});

afterEach(() => {
  cleanup();
});

describe('AttackScreenPage', () => {
  it('loads logs + monitor and shows live attack metrics', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledWith({ limit: 1000 }));
    await waitFor(() => expect(apiMocks.fetchMonitorSummary).toHaveBeenCalled());

    expect(await screen.findByText('attackMap.globalThreatMap')).toBeTruthy();
    expect(screen.getByText('attackMap.live')).toBeTruthy();
    // threat mix panel metric for total attacks
    const attackMetric = Array.from(document.querySelectorAll('.attack-screen-stats span'))
      .find((el) => el.textContent === 'attackMap.attacks');
    expect(attackMetric).toBeTruthy();
    expect(attackMetric?.previousElementSibling?.textContent).toBe('3');
    expect(screen.getByText('dashboard.threatMix')).toBeTruthy();
    expect(screen.getByText('attackMap.attackTypes')).toBeTruthy();
    expect(screen.getByText('attackMap.sourceCountries')).toBeTruthy();
    expect(screen.getByTestId('globe-map')).toBeTruthy();
  });

  it('shows threat level panel and timeline control', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalled());
    expect(await screen.findByText('attackMap.threatLevel')).toBeTruthy();
    expect(screen.getByText('attackMap.timeline')).toBeTruthy();
    const slider = screen.getByLabelText('attackMap.timelineRangeAria') as HTMLInputElement;
    expect(slider.value).toBe('100');
    fireEvent.change(slider, { target: { value: '50' } });
    await waitFor(() => expect(slider.value).toBe('50'));
    expect(await screen.findByText('attackMap.historyView')).toBeTruthy();
  });

  it('exposes an enabled refresh control after the first load', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledTimes(1));
    const refresh = await screen.findByRole('button', { name: /attackMap\.refresh/i });
    await waitFor(() => expect((refresh as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(refresh);
    await waitFor(() => expect((refresh as HTMLButtonElement).disabled).toBe(false));
    // Metrics remain visible after refresh interaction
    const attackMetric = Array.from(document.querySelectorAll('.attack-screen-stats span'))
      .find((el) => el.textContent === 'attackMap.attacks');
    expect(attackMetric?.previousElementSibling?.textContent).toBe('3');
  });

  it('shows loading placeholders while first log fetch is pending', async () => {
    let resolve!: (value: unknown) => void;
    apiMocks.fetchLogs.mockReturnValue(new Promise((ok) => { resolve = ok; }));
    renderPage();
    expect(screen.getAllByText('common.loading').length).toBeGreaterThan(0);
    resolve({ items: [entry({ id: 'late' })], total: 1 });
    await waitFor(() => expect(screen.queryByText('common.loading')).toBeNull());
    const attackMetric = Array.from(document.querySelectorAll('.attack-screen-stats span'))
      .find((el) => el.textContent === 'attackMap.attacks');
    expect(attackMetric?.previousElementSibling?.textContent).toBe('1');
  });
});
