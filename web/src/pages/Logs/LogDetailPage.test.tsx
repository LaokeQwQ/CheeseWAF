import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchLogEvent: vi.fn(),
  analyzeLogReferenceStream: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import LogDetailPage from './LogDetailPage';

function renderDetail(reference = 'trace-1') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/logs/${reference}`]}>
        <Routes>
          <Route path="/logs/:traceId" element={<LogDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchLogEvent.mockResolvedValue({
    id: 'evt-1',
    trace_id: 'trace-1',
    timestamp: '2026-07-17T10:00:00Z',
    client_ip: '203.0.113.9',
    method: 'POST',
    uri: '/api/login',
    action: 'block',
    category: 'sqli',
    severity: 'high',
    status_code: 403,
    message: 'union select blocked',
  });
});

afterEach(() => {
  cleanup();
});

describe('LogDetailPage', () => {
  it('loads event by route reference', async () => {
    renderDetail('trace-1');
    await waitFor(() => expect(apiMocks.fetchLogEvent).toHaveBeenCalledWith('trace-1'));
    expect(await screen.findByText('/api/login')).toBeTruthy();
    expect(screen.getByText('union select blocked')).toBeTruthy();
    expect(screen.getByText('203.0.113.9')).toBeTruthy();
  });

  it('shows error state when event is missing', async () => {
    apiMocks.fetchLogEvent.mockRejectedValue(new Error('not found'));
    renderDetail('missing');
    await waitFor(() => expect(apiMocks.fetchLogEvent).toHaveBeenCalledWith('missing'));
    expect(await screen.findByText('not found')).toBeTruthy();
  });
});
