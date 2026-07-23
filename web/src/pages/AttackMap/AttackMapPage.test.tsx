import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LogEntry } from '../../types/api';
import { forwardRef } from 'react';

const apiMocks = vi.hoisted(() => ({
  fetchLogs: vi.fn(),
  fetchChinaMapBoundaryByCode: vi.fn(),
}));

const preloadMocks = vi.hoisted(() => ({
  preloadAttackScreenPage: vi.fn(),
  preloadGlobeMap: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => (opts ? `${key}:${JSON.stringify(opts)}` : key),
  }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

vi.mock('../../routes/preload', () => preloadMocks);

vi.mock('./OsmAttackMap', () => {
  const OsmAttackMap = forwardRef(({ regions }: { regions: Array<{ attacks: number }> }, _ref) => (
    <div data-testid="osm-map">osm-regions:{regions.length}</div>
  ));
  OsmAttackMap.displayName = 'OsmAttackMap';
  return { default: OsmAttackMap };
});

vi.mock('./GlobeMap', () => ({
  default: ({ regions }: { regions: Array<{ attacks: number }> }) => (
    <div data-testid="globe-map">globe-regions:{regions.length}</div>
  ),
}));

import AttackMapPage from './AttackMapPage';

function entry(partial: Partial<LogEntry>): LogEntry {
  return {
    id: partial.id ?? String(Math.random()),
    timestamp: partial.timestamp ?? '2026-07-17T12:00:00Z',
    client_ip: partial.client_ip ?? '203.0.113.10',
    method: 'GET',
    uri: partial.uri ?? '/admin',
    action: partial.action ?? 'block',
    category: partial.category ?? 'sqli',
    severity: partial.severity ?? 'high',
    status_code: partial.status_code ?? 403,
    message: '',
    country: partial.country ?? 'CN',
    metadata: partial.metadata ?? { lat: 31.2, lon: 121.5, city: 'Shanghai' },
    ...partial,
  } as LogEntry;
}

function renderPage(path = '/attack-map') {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AttackMapPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchLogs.mockResolvedValue({
    items: [
      entry({ id: '1', country: 'CN', severity: 'critical', category: 'sqli' }),
      entry({ id: '2', country: 'CN', severity: 'high', category: 'xss', client_ip: '203.0.113.11' }),
      entry({ id: '3', country: 'US', severity: 'medium', category: 'bot', client_ip: '8.8.8.8', metadata: { lat: 37.7, lon: -122.4 } }),
      entry({ id: '4', action: 'pass', status_code: 200, country: 'JP', severity: '', category: '' }),
    ],
    total: 4,
  });
  apiMocks.fetchChinaMapBoundaryByCode.mockResolvedValue({ enabled: false, geojson: null });
});

afterEach(() => {
  cleanup();
});

describe('AttackMapPage', () => {
  it('loads attack logs and shows aggregated attack totals', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledWith({ limit: 1000 }));
    expect(await screen.findByText('attackMap.title')).toBeTruthy();
    // legend strong shows total attack count = 3 (pass ignored)
    const legend = document.querySelector('.map-legend strong');
    expect(legend?.textContent).toBe('3');
    expect(screen.getAllByText('attackMap.attacks').length).toBeGreaterThan(0);
    expect(screen.getByTestId('osm-map').textContent).toMatch(/osm-regions:[1-9]/);
  });

  it('renders risk legend levels', async () => {
    renderPage();
    await screen.findByText('attackMap.title');
    expect(screen.getByText('attackMap.risk.low')).toBeTruthy();
    expect(screen.getByText('attackMap.risk.medium')).toBeTruthy();
    expect(screen.getByText('attackMap.risk.high')).toBeTruthy();
    expect(screen.getByText('attackMap.risk.critical')).toBeTruthy();
  });

  it('switches map mode to 3d and preloads globe', async () => {
    renderPage();
    await screen.findByText('attackMap.mode3d');
    fireEvent.click(screen.getByText('attackMap.mode3d'));
    await waitFor(() => expect(preloadMocks.preloadGlobeMap).toHaveBeenCalled());
  });

  it('honors mode=china query param on mount', async () => {
    renderPage('/attack-map?mode=china');
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalled());
    expect(await screen.findByText('attackMap.modeChina')).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByText(/attackMap\.chinaRegionMapped/)).toBeTruthy();
    });
  });

  it('shows empty aggregation when logs API returns no attacks', async () => {
    apiMocks.fetchLogs.mockResolvedValue({ items: [], total: 0 });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalled());
    expect(await screen.findByText('attackMap.title')).toBeTruthy();
    const legend = document.querySelector('.map-legend strong');
    expect(legend?.textContent).toBe('0');
  });
});
