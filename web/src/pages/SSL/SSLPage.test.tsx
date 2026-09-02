import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fallbackSystem } from '../System/systemModel';

const apiMocks = vi.hoisted(() => ({
  fetchSystemConfig: vi.fn(),
  updateSystemConfig: vi.fn(),
}));

const toastMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('sonner', () => ({
  toast: toastMocks,
}));

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
  it('uses a closed reload profile selector instead of a command input', async () => {
    renderPage();
    await screen.findByDisplayValue('ops@example.com');
    const label = screen.getByText('system.acmeReloadProfile').closest('label');
    expect(label?.querySelector('[role="combobox"]')).not.toBeNull();
    expect(label?.querySelector('input')).toBeNull();
    expect(label?.textContent).toContain('system.acmeReloadDisabled');
    expect(screen.queryByPlaceholderText('systemctl reload cheesewaf')).toBeNull();
  });

  it('loads ACME settings and saves email changes', async () => {
    renderPage();
    const email = await screen.findByDisplayValue('ops@example.com');
    fireEvent.change(email, { target: { value: 'security@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(apiMocks.updateSystemConfig).toHaveBeenCalled());
    expect(apiMocks.updateSystemConfig.mock.calls[0]?.[0].acme.account_email).toBe('security@example.com');
    expect(toastMocks.success).toHaveBeenCalledWith('system.saved');
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

  it('keeps the last provider editor attached to its provider when deleting the middle provider', async () => {
    apiMocks.fetchSystemConfig.mockReset();
    apiMocks.fetchSystemConfig.mockResolvedValue({
      ...fallbackSystem,
      acme: {
        ...fallbackSystem.acme,
        enabled: true,
        account_email: 'ops@example.com',
        dns_providers: [
          { id: 'provider-first', name: 'First', api: 'dns_cf', enabled: true, env: { FIRST_TOKEN: 'first' } },
          { id: 'provider-middle', name: 'Middle', api: 'dns_cf', enabled: true, env: { MIDDLE_TOKEN: 'middle' } },
          { id: 'provider-last', name: 'Last', api: 'dns_cf', enabled: true, env: { LAST_TOKEN: 'last' } },
        ],
      },
    });
    renderPage();

    await screen.findByDisplayValue('FIRST_TOKEN');
    const cards = Array.from(document.querySelectorAll<HTMLElement>('.acme-provider-card'));
    expect(cards).toHaveLength(3);
    fireEvent.click(within(cards[1]).getByRole('button', { name: 'common.add' }));
    const middleRows = cards[1].querySelectorAll<HTMLElement>('.acme-env-row');
    const incompleteValue = middleRows[1]?.querySelector<HTMLInputElement>('input[type="password"]');
    expect(incompleteValue).toBeTruthy();
    fireEvent.change(incompleteValue!, { target: { value: 'MIDDLE_EDITED' } });
    fireEvent.click(within(cards[1]).getAllByRole('button', { name: 'common.delete' })[0]);

    await waitFor(() => expect(screen.getByDisplayValue('LAST_TOKEN')).toBeTruthy());
    expect(screen.getByDisplayValue('FIRST_TOKEN')).toBeTruthy();
    expect(screen.queryByDisplayValue('MIDDLE_EDITED')).toBeNull();
  });
});
