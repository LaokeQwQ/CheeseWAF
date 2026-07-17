import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Site } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  createSite: vi.fn(),
  fetchSites: vi.fn(),
}));

const messageMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

const navigateMock = vi.hoisted(() => vi.fn());

vi.mock('@arco-design/web-react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@arco-design/web-react')>();
  return {
    ...actual,
    Message: messageMocks,
  };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return {
    ...actual,
    ...apiMocks,
  };
});

import { APIRequestError } from '../../api/client';
import SitesPage from './SitesPage';
import { normalizeSite } from './siteModel';

function makeSite(id: string, name: string): Site {
  return normalizeSite({
    id,
    name,
    domains: [`${name}.example.com`],
    upstreams: ['127.0.0.1:9000'],
  });
}

function renderSites() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  const invalidateQueries = vi.spyOn(client, 'invalidateQueries');
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SitesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, invalidateQueries };
}

async function completeCreateWizard(name: string) {
  fireEvent.click(screen.getByRole('button', { name: 'sites.create' }));
  fireEvent.change(await screen.findByPlaceholderText('portal.example.com'), { target: { value: name } });
  fireEvent.change(screen.getByPlaceholderText('example.com, www.example.com'), { target: { value: `${name}.example.com` } });
  fireEvent.change(screen.getByPlaceholderText('127.0.0.1:9000, 10.0.0.12:8080'), { target: { value: '127.0.0.1:9000' } });

  for (let step = 0; step < 3; step += 1) {
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));
  }
  await screen.findByRole('button', { name: 'common.finish' });
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchSites.mockResolvedValue([]);
});

afterEach(() => {
  cleanup();
});

describe('SitesPage create failures', () => {
  it.each([
    { code: 'FORBIDDEN', message: '403 site creation is forbidden', status: 403 },
    { code: 'SITE_CONFLICT', message: '409 site configuration conflict', status: 409 },
  ])('keeps the draft and cache unchanged for a $status response', async ({ code, message, status }) => {
    const initial = [makeSite('site-existing', 'existing')];
    apiMocks.fetchSites.mockResolvedValue(initial);
    apiMocks.createSite.mockRejectedValue(new APIRequestError(message, code, status));
    const { client, invalidateQueries } = renderSites();
    await waitFor(() => expect(client.getQueryData(['sites'])).toEqual(initial));

    await completeCreateWizard('new-site');
    fireEvent.click(screen.getByRole('button', { name: 'common.finish' }));

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith(message));
    expect(messageMocks.success).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
    expect(invalidateQueries).not.toHaveBeenCalled();
    expect(apiMocks.fetchSites).toHaveBeenCalledTimes(1);
    expect(client.getQueryData(['sites'])).toEqual(initial);
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(screen.getByText('new-site')).toBeTruthy();
  });
});

describe('SitesPage create success', () => {
  it('invalidates the list and renders the persisted site from a reread', async () => {
    const created = makeSite('site-new', 'new-site');
    const persisted = makeSite('site-new', 'new-site-persisted');
    apiMocks.fetchSites
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([persisted]);
    apiMocks.createSite.mockResolvedValue(created);
    const { client, invalidateQueries } = renderSites();
    await waitFor(() => expect(apiMocks.fetchSites).toHaveBeenCalledTimes(1));

    await completeCreateWizard('new-site');
    fireEvent.click(screen.getByRole('button', { name: 'common.finish' }));

    await waitFor(() => expect(apiMocks.createSite).toHaveBeenCalledTimes(1));
    expect(apiMocks.createSite.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      domains: ['new-site.example.com'],
      name: 'new-site',
      upstreams: ['127.0.0.1:9000'],
    }));
    await waitFor(() => expect(apiMocks.fetchSites).toHaveBeenCalledTimes(2));
    expect((await screen.findAllByText('new-site-persisted')).length).toBeGreaterThan(0);
    expect(client.getQueryData(['sites'])).toEqual([persisted]);
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['sites'] });
    expect(navigateMock).toHaveBeenCalledWith('/sites/site-new');
    expect(messageMocks.success).toHaveBeenCalledWith('sites.created');
    expect(messageMocks.error).not.toHaveBeenCalled();
  });
});

describe('SitesPage query states', () => {
  it('shows the request error and retries without leaving the table loading forever', async () => {
    apiMocks.fetchSites
      .mockRejectedValueOnce(new APIRequestError('site list unavailable', 'SITE_LIST_FAILED', 500))
      .mockResolvedValueOnce([]);
    renderSites();

    expect((await screen.findByRole('alert')).textContent).toContain('site list unavailable');
    expect(document.querySelector('.arco-spin-loading')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));

    await waitFor(() => expect(apiMocks.fetchSites).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });

  it('renders bounded desktop cells and a mobile card for long site values', async () => {
    const longValue = `gateway-${'segment-'.repeat(24)}end`;
    apiMocks.fetchSites.mockResolvedValue([makeSite('site-long', longValue)]);
    renderSites();

    const desktopLink = (await screen.findAllByTitle(longValue)).find((element) => element.classList.contains('site-table-link'));
    expect(desktopLink).toBeTruthy();
    expect(desktopLink?.classList.contains('site-table-link')).toBe(true);
    expect(document.querySelector('.sites-mobile-card')).toBeTruthy();
    expect(document.querySelectorAll('.site-table-text').length).toBe(2);
  });
});

describe('SitesPage wizard validation', () => {
  it('blocks the TLS step until file-mode certificate paths are complete', async () => {
    renderSites();
    fireEvent.click(screen.getByRole('button', { name: 'sites.create' }));
    fireEvent.change(await screen.findByPlaceholderText('portal.example.com'), { target: { value: 'tls-site' } });
    fireEvent.change(screen.getByPlaceholderText('example.com, www.example.com'), { target: { value: 'tls.example.com' } });
    fireEvent.change(screen.getByPlaceholderText('127.0.0.1:9000, 10.0.0.12:8080'), { target: { value: '127.0.0.1:9000' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.next' }));

    const sslLabel = screen.getByText('sites.enableSsl').closest('label');
    expect(sslLabel).toBeTruthy();
    fireEvent.click((sslLabel as HTMLElement).querySelector('.arco-switch') as Element);
    expect((screen.getByRole('button', { name: 'common.next' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByPlaceholderText('/etc/cheesewaf/certs/site.crt'), { target: { value: '/certs/site.crt' } });
    fireEvent.change(screen.getByPlaceholderText('/etc/cheesewaf/certs/site.key'), { target: { value: '/certs/site.key' } });

    expect((screen.getByRole('button', { name: 'common.next' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
