import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { LogEntry } from '../../types/api';
import { forwardRef } from 'react';

const apiMocks = vi.hoisted(() => ({
  fetchAttackMapAggregate: vi.fn(),
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

/**
 * The China mode reads its basemap from vendored GeoJSON under `public/map`.
 * jsdom has no HTTP server, so these tests serve the two files the page really
 * asks for — tiny stand-ins with the same shape (`gb` codes on the province
 * pack, `adcode` on the region pack). Everything is gzipped on the fly because
 * `fetchGzJson` pipes `.gz` responses through `DecompressionStream`.
 */
const emptyCollection = { type: 'FeatureCollection', features: [] };
const gzResponse = (payload: unknown) => new Response(gzipSync(Buffer.from(JSON.stringify(payload))));
const jsonResponse = (payload: unknown) => new Response(JSON.stringify(payload), { headers: { 'content-type': 'application/json' } });

function stubMapAssetFetch() {
  const mapFetch = vi.fn(async (input: unknown) => {
    const url = String((input as { url?: string })?.url ?? input);
    if (url.includes('china_admin_index.json')) {
      return jsonResponse([{ code: '310100', name: '上海市' }]);
    }
    if (url.includes('china_province.geojson.gz')) {
      return gzResponse({
        type: 'FeatureCollection',
        features: [
          { type: 'Feature', properties: { gb: '156310000', name: '上海市' }, geometry: { type: 'Polygon', coordinates: [[[121.4, 31.1], [121.6, 31.1], [121.6, 31.3], [121.4, 31.1]]] } },
        ],
      });
    }
    if (url.includes('china_region.geojson.gz')) {
      return gzResponse({
        type: 'FeatureCollection',
        features: [
          { type: 'Feature', properties: { adcode: '310100', name: '上海市' }, geometry: { type: 'Polygon', coordinates: [[[121.4, 31.1], [121.6, 31.1], [121.6, 31.3], [121.4, 31.1]]] } },
        ],
      });
    }
    if (url.includes('china_county.geojson.gz')) {
      return gzResponse(emptyCollection);
    }
    return new Response('not found', { status: 404 });
  });
  vi.stubGlobal('fetch', mapFetch);
  return mapFetch;
}

/** 浦东新区 (310115) — a district-level adcode inside the requested 上海 scope. */
const externalDistrictGeojson = {
  type: 'FeatureCollection' as const,
  features: [
    {
      type: 'Feature' as const,
      properties: { adcode: '310115', name: '浦东新区' },
      geometry: { type: 'Polygon' as const, coordinates: [[[121.5, 31.2], [121.6, 31.2], [121.6, 31.3], [121.5, 31.2]]] },
    },
  ],
};

beforeEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  apiMocks.fetchAttackMapAggregate.mockResolvedValue({
    events: [
      entry({ id: '1', country: 'CN', severity: 'critical', category: 'sqli' }),
      entry({ id: '2', country: 'CN', severity: 'high', category: 'xss', client_ip: '203.0.113.11' }),
      entry({ id: '3', country: 'US', severity: 'medium', category: 'bot', client_ip: '8.8.8.8', metadata: { lat: 37.7, lon: -122.4 } }),
      entry({ id: '4', action: 'pass', status_code: 200, country: 'JP', severity: '', category: '' }),
    ],
    items: [
      { key: 'CN|Shanghai', country_code: 'CN', country: 'CN', location_name: 'Shanghai', lat: 31.2, lon: 121.5, mappable: true, attacks: 2, blocked: 2, severity: 'critical', severity_rank: 4, top_category: 'sqli', categories: { sqli: 1, xss: 1 } },
      { key: 'US|New York', country_code: 'US', country: 'US', location_name: 'New York', lat: 37.7, lon: -122.4, mappable: true, attacks: 1, blocked: 1, severity: 'medium', severity_rank: 2, top_category: 'bot', categories: { bot: 1 } },
    ], total: 4, has_more: false, next: { time: '2026-07-17T12:00:00Z', id: '4' }, generated_at: '2026-07-17T12:00:00Z',
  });
  apiMocks.fetchChinaMapBoundaryByCode.mockResolvedValue({ enabled: false, geojson: null });
});

afterEach(() => {
  cleanup();
});

describe('AttackMapPage', () => {
  it('loads attack logs and shows aggregated attack totals', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchAttackMapAggregate).toHaveBeenCalledWith({ limit: 1000, after: undefined, after_id: undefined }));
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
    expect(screen.getAllByText('attackMap.risk.medium').length).toBeGreaterThan(0);
    expect(screen.getAllByText('attackMap.risk.high').length).toBeGreaterThan(0);
    expect(screen.getAllByText('attackMap.risk.critical').length).toBeGreaterThan(0);
  });

  it('switches map mode to 3d and preloads globe', async () => {
    renderPage();
    await screen.findByText('attackMap.mode3d');
    fireEvent.click(screen.getByText('attackMap.mode3d'));
    await waitFor(() => expect(preloadMocks.preloadGlobeMap).toHaveBeenCalled());
  });

  it('honors mode=china query param on mount', async () => {
    renderPage('/attack-map?mode=china');
    await waitFor(() => expect(apiMocks.fetchAttackMapAggregate).toHaveBeenCalled());
    expect(await screen.findByText('attackMap.modeChina')).toBeTruthy();
    await waitFor(() => {
      expect(screen.getByText(/attackMap\.chinaRegionMapped/)).toBeTruthy();
    });
  });

  it('shows empty aggregation when logs API returns no attacks', async () => {
    apiMocks.fetchAttackMapAggregate.mockResolvedValue({ items: [], events: [], total: 0, has_more: false, generated_at: '2026-07-17T12:00:00Z' });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchAttackMapAggregate).toHaveBeenCalled());
    expect(await screen.findByText('attackMap.title')).toBeTruthy();
    const legend = document.querySelector('.map-legend strong');
    expect(legend?.textContent).toBe('0');
  });

  it('refuses an external boundary whose coordinate system is not declared', async () => {
    stubMapAssetFetch();
    apiMocks.fetchChinaMapBoundaryByCode.mockResolvedValue({ enabled: true, geojson: externalDistrictGeojson });
    renderPage('/attack-map?mode=china');
    // The gate must reject before anything reaches the map, and say so out loud.
    expect(await screen.findByText('attackMap.externalBoundaryNoCrs')).toBeTruthy();
    await waitFor(() => expect(apiMocks.fetchChinaMapBoundaryByCode).toHaveBeenCalled());
    expect(screen.queryByText('attackMap.externalBoundaryUnsupportedCrs')).toBeNull();
    // ...and the built-in boundary stays the rendered source: the refused
    // external geometry never became the map's boundary supplier.
    await waitFor(() => expect(screen.getByText(/attackMap\.boundaryBuiltinCity/)).toBeTruthy());
  });

  it('admits an external boundary that declares GCJ-02 and converts it', async () => {
    stubMapAssetFetch();
    apiMocks.fetchChinaMapBoundaryByCode.mockResolvedValue({
      enabled: true,
      coordinate_system: 'GCJ-02',
      geojson: externalDistrictGeojson,
    });
    renderPage('/attack-map?mode=china');
    await waitFor(() => expect(apiMocks.fetchChinaMapBoundaryByCode).toHaveBeenCalled());
    // No rejection banner, and the external data really did become the
    // boundary supplier — proof it passed the gate rather than being ignored.
    await waitFor(() => expect(screen.getByText(/attackMap\.boundaryExternalDistrict/)).toBeTruthy());
    expect(screen.queryByText('attackMap.externalBoundaryNoCrs')).toBeNull();
    expect(screen.queryByText('attackMap.externalBoundaryUnsupportedCrs')).toBeNull();
  });
});
