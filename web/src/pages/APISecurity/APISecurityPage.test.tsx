import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchAPISecEndpoints: vi.fn(),
  validateAPIRequest: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import APISecurityPage from './APISecurityPage';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <APISecurityPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchAPISecEndpoints.mockResolvedValue({
    endpoints: [
      { method: 'GET', path: '/api/users', count: 12, blocked: 2, status_family: { '2xx': 10, '4xx': 2 } },
      { method: 'POST', path: '/api/login', count: 5, blocked: 0, status_family: { '2xx': 5 } },
    ],
  });
});

afterEach(() => {
  cleanup();
});

describe('APISecurityPage', () => {
  it('lists discovered endpoints and can ignore one locally', async () => {
    renderPage();
    await waitFor(() => expect(screen.getAllByText('/api/users').length).toBeGreaterThan(0));
    expect(screen.getAllByText('/api/login').length).toBeGreaterThan(0);
    const ignoreButtons = screen.getAllByRole('button', { name: 'common.ignore' });
    // Desktop + mobile rows; first ignore is GET /api/users
    fireEvent.click(ignoreButtons[0]!);
    await waitFor(() => {
      expect(screen.queryAllByText('/api/users')).toHaveLength(0);
    });
    expect(screen.getAllByText('/api/login').length).toBeGreaterThan(0);
  });

  it('validates a request and shows findings', async () => {
    apiMocks.validateAPIRequest.mockResolvedValue({
      findings: [{ message: 'missing required query q' }],
    });
    renderPage();
    await waitFor(() => expect(screen.getAllByText('/api/users').length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole('button', { name: 'apisec.validate' }));
    await waitFor(() => expect(apiMocks.validateAPIRequest).toHaveBeenCalled());
    expect(apiMocks.validateAPIRequest.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      method: 'GET',
      path: '/api/search',
    }));
    expect(await screen.findByText('missing required query q')).toBeTruthy();
  });

  it('shows clean tag when validation finds nothing', async () => {
    apiMocks.validateAPIRequest.mockResolvedValue({ findings: [] });
    renderPage();
    await waitFor(() => expect(screen.getAllByText('/api/users').length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole('button', { name: 'apisec.validate' }));
    expect(await screen.findByText('apisec.clean')).toBeTruthy();
  });
});
