import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchEdgePolicy: vi.fn(),
  updateEdgePolicy: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import EdgePage from './EdgePage';

const edgeFixture = {
  headers: {
    enabled: true,
    rules: [
      {
        id: 'h1',
        name: 'HSTS',
        operation: 'set',
        header: 'Strict-Transport-Security',
        value: 'max-age=31536000',
        path_prefix: '/',
        enabled: true,
      },
    ],
  },
  cache: {
    enabled: true,
    mode: 'path',
    ttl: 60_000_000_000,
    status_codes: [200],
    path_prefixes: ['/static'],
    max_body_bytes: 2 * 1024 * 1024,
  },
  compression: {
    enabled: true,
    algorithms: ['gzip'],
    level: 5,
    min_bytes: 1024,
    content_types: ['text/html'],
  },
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <EdgePage />
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchEdgePolicy.mockResolvedValue(edgeFixture);
  apiMocks.updateEdgePolicy.mockImplementation(async (body) => body);
});

afterEach(() => {
  cleanup();
});

describe('EdgePage', () => {
  it('loads policy and saves current draft', async () => {
    renderPage();
    expect(await screen.findByText('edge.title')).toBeTruthy();
    // Header rule content from fixture
    expect(await screen.findByDisplayValue('Strict-Transport-Security')).toBeTruthy();
    fireEvent.click(screen.getAllByRole('button', { name: 'common.save' })[0]!);
    await waitFor(() => expect(apiMocks.updateEdgePolicy).toHaveBeenCalled());
    const payload = apiMocks.updateEdgePolicy.mock.calls[0]?.[0];
    expect(payload.headers.rules[0].header).toBe('Strict-Transport-Security');
    expect(payload.cache.enabled).toBe(true);
  });

  it('adds a header rewrite rule into draft before save', async () => {
    renderPage();
    await screen.findByDisplayValue('Strict-Transport-Security');
    fireEvent.click(screen.getAllByRole('button', { name: 'common.add' })[0]!);
    await waitFor(() => {
      const inputs = screen.getAllByDisplayValue('');
      expect(inputs.length).toBeGreaterThan(0);
    });
    fireEvent.click(screen.getAllByRole('button', { name: 'common.save' })[0]!);
    await waitFor(() => expect(apiMocks.updateEdgePolicy).toHaveBeenCalled());
    const payload = apiMocks.updateEdgePolicy.mock.calls.at(-1)?.[0];
    expect(payload.headers.rules.length).toBeGreaterThanOrEqual(2);
  });
});
