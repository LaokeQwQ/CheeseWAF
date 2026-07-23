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
  apiMocks.fetchLogs.mockResolvedValue({ items, total: items.length });
});

afterEach(() => {
  cleanup();
});

describe('LogsPage', () => {
  it('defaults to security view and hides pure access rows', async () => {
    renderPage();
    expect(await screen.findByText('/wp-login.php')).toBeTruthy();
    expect(screen.queryByText('/assets/app.js')).toBeNull();
    expect(apiMocks.fetchLogs).toHaveBeenCalledWith(expect.objectContaining({ limit: 500 }));
  });

  it('filters by free-text search', async () => {
    renderPage();
    await screen.findByText('/wp-login.php');
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'trace-block' } });
    expect(screen.getByText('/wp-login.php')).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText('common.search'), { target: { value: 'no-such' } });
    await waitFor(() => expect(screen.queryByText('/wp-login.php')).toBeNull());
  });
});
