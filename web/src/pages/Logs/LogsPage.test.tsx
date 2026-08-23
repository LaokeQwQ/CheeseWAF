import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchLogs: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import LogsPage from './LogsPage';

const items = [
  {
    id: '1',
    timestamp: '2026-07-17T10:00:00Z',
    client_ip: '203.0.113.1',
    method: 'GET',
    uri: '/wp-login.php',
    action: 'block',
    category: 'sqli',
    severity: 'high',
    status_code: 403,
    message: 'union select',
    trace_id: 'trace-block',
    country: 'CN',
  },
  {
    id: '2',
    timestamp: '2026-07-17T10:01:00Z',
    client_ip: '198.51.100.2',
    method: 'GET',
    uri: '/assets/app.js',
    action: 'pass',
    category: '',
    severity: '',
    status_code: 200,
    message: '',
    trace_id: 'trace-pass',
    country: 'US',
  },
];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LogsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchLogs.mockImplementation((params: { kind?: string; search?: string; limit?: number }) => {
    let filtered = [...items];
    if (params.kind === 'security') {
      filtered = filtered.filter((entry) => Boolean(entry.category) || ['block', 'challenge', 'log', 'monitor'].includes(entry.action) || [403, 429].includes(entry.status_code));
    } else if (params.kind === 'access') {
      filtered = filtered.filter((entry) => !entry.category && ['pass', 'cache_hit', 'redirect', ''].includes(entry.action) && ![403, 429].includes(entry.status_code));
    }
    const search = params.search?.toLowerCase();
    if (search) {
      filtered = filtered.filter((entry) => Object.values(entry).some((value) => String(value ?? '').toLowerCase().includes(search)));
    }
    return Promise.resolve({ items: filtered.slice(0, params.limit), total: filtered.length });
  });
});

afterEach(() => {
  cleanup();
});

describe('LogsPage', () => {
  it('defaults to security view and hides pure access rows', async () => {
    renderPage();
    expect(await screen.findByText('/wp-login.php')).toBeTruthy();
    expect(screen.queryByText('/assets/app.js')).toBeNull();
    expect(apiMocks.fetchLogs).toHaveBeenCalledWith(expect.objectContaining({ limit: 8, kind: 'security' }));
  });

  it('sends free-text search to the server', async () => {
    renderPage();
    await screen.findByText('/wp-login.php');
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'trace-block' } });
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledWith(expect.objectContaining({ search: 'trace-block' })));
    expect(await screen.findByText('/wp-login.php')).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'no-such' } });
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledWith(expect.objectContaining({ search: 'no-such' })));
    await waitFor(() => expect(screen.queryByText('/wp-login.php')).toBeNull());
  });

  it('uses a fixed watermark and stable before cursor for the next page', async () => {
    const pageRows = Array.from({ length: 9 }, (_, index) => ({
      ...items[0],
      id: `page-${index + 1}`,
      trace_id: `trace-page-${index + 1}`,
      uri: `/page/${index + 1}`,
      timestamp: `2026-07-17T10:${String(20 - index).padStart(2, '0')}:00Z`,
    }));
    apiMocks.fetchLogs.mockImplementation((params: { before?: string }) => Promise.resolve(
      params.before
        ? { items: [pageRows[8]], total: 1 }
        : { items: pageRows.slice(0, 8), total: 9 },
    ));
    renderPage();
    expect(await screen.findByText('/page/8')).toBeTruthy();
    fireEvent.click(await screen.findByLabelText('common.next'));
    await waitFor(() => expect(apiMocks.fetchLogs).toHaveBeenCalledWith(expect.objectContaining({
      before: pageRows[7].timestamp,
      before_id: pageRows[7].id,
      watermark: pageRows[0].timestamp,
      watermark_id: pageRows[0].id,
    })));
    expect(await screen.findByText('/page/9')).toBeTruthy();
  });

  it('does not advance until the first page has a valid watermark', async () => {
    const pageRows = Array.from({ length: 8 }, (_, index) => ({
      ...items[0],
      id: `page-${index + 1}`,
      uri: `/page/${index + 1}`,
      timestamp: index === 0 ? '' : `2026-07-17T10:${String(20 - index).padStart(2, '0')}:00Z`,
    }));
    apiMocks.fetchLogs.mockResolvedValue({ items: pageRows, total: 9 });

    renderPage();

    expect(await screen.findByText('/page/8')).toBeTruthy();
    expect((screen.getByLabelText('common.next') as HTMLButtonElement).disabled).toBe(true);
  });
});
