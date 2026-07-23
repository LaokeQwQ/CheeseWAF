import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchMonitorSummary: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import MonitorPage from './MonitorPage';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MonitorPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
});

describe('MonitorPage', () => {
  it('renders live metrics and alerts from monitor summary', async () => {
    apiMocks.fetchMonitorSummary.mockResolvedValue({
      snapshot: {
        requests: 1200,
        blocked: 48,
        process_count: 3,
        memory_alloc: 8 * 1024 * 1024,
        disk_usage: { data: 100 * 1024 * 1024, logs: 20 * 1024 * 1024 },
      },
      alerts: [
        { rule_id: 'r1', name: 'High block rate', severity: 'high', message: 'blocked spike', value: 40, threshold: 20 },
      ],
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchMonitorSummary).toHaveBeenCalled());
    expect(await screen.findByText('1200')).toBeTruthy();
    expect(screen.getByText('48')).toBeTruthy();
    expect(screen.getByText('High block rate')).toBeTruthy();
    expect(screen.getByText('blocked spike')).toBeTruthy();
    expect(screen.getByText('40 / 20')).toBeTruthy();
  });

  it('shows loading placeholders before data arrives', async () => {
    let resolve!: (value: unknown) => void;
    apiMocks.fetchMonitorSummary.mockReturnValue(new Promise((ok) => { resolve = ok; }));
    renderPage();
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    resolve({ snapshot: { requests: 1, blocked: 0, process_count: 1, memory_alloc: 0, disk_usage: {} }, alerts: [] });
    await waitFor(() => expect(screen.getAllByText('1').length).toBeGreaterThan(0));
  });
});
