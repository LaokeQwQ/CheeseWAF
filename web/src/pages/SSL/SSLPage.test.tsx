import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fallbackSystem } from '../System/systemModel';

const apiMocks = vi.hoisted(() => ({
  fetchSystemConfig: vi.fn(),
  updateSystemConfig: vi.fn(),
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
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import SSLPage from './SSLPage';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <SSLPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchSystemConfig.mockResolvedValue({
    ...fallbackSystem,
    acme: {
      ...fallbackSystem.acme,
      enabled: true,
      account_email: 'ops@example.com',
      dns_providers: [],
    },
  });
  apiMocks.updateSystemConfig.mockImplementation(async (body) => ({
    ...fallbackSystem,
    acme: body.acme,
  }));
});

afterEach(() => {
  cleanup();
});

describe('SSLPage', () => {
  it('loads ACME settings and saves email changes', async () => {
    renderPage();
    const email = await screen.findByDisplayValue('ops@example.com');
    fireEvent.change(email, { target: { value: 'security@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(apiMocks.updateSystemConfig).toHaveBeenCalled());
    expect(apiMocks.updateSystemConfig.mock.calls[0]?.[0].acme.account_email).toBe('security@example.com');
    expect(messageMocks.success).toHaveBeenCalledWith('system.saved');
  });

  it('adds a DNS provider card to the ACME draft', async () => {
    renderPage();
    await screen.findByDisplayValue('ops@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'common.add' }));
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(apiMocks.updateSystemConfig).toHaveBeenCalled());
    const providers = apiMocks.updateSystemConfig.mock.calls[0]?.[0].acme.dns_providers;
    expect(Array.isArray(providers)).toBe(true);
    expect(providers.length).toBe(1);
    expect(providers[0].api).toBe('dns_cf');
  });
});
