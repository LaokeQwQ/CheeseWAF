import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Site } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  createSite: vi.fn(),
  fetchSites: vi.fn(),
  importNginx: vi.fn(),
}));

const toastMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

const navigateMock = vi.hoisted(() => vi.fn());

vi.mock('sonner', () => ({
  toast: toastMocks,
}));

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

const nginxFixture = [
  'server {',
  '    listen 8080;',
  '    server_name shop.example.com www.shop.example.com;',
  '',
  '    location / {',
  '        proxy_pass http://127.0.0.1:9000;',
  '    }',
  '}',
  'server {',
  '    listen 80;',
  '',
  '    location / {',
  '        proxy_pass http://10.0.0.5:8080;',
  '    }',
  '}',
].join('\n');

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

async function openNginxImport() {
  fireEvent.click(screen.getByRole('button', { name: 'sites.import.action' }));
  await screen.findByRole('dialog');
  return screen.getByRole('textbox') as HTMLTextAreaElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchSites.mockResolvedValue([]);
  apiMocks.createSite.mockResolvedValue(makeSite('site-default', 'default'));
  apiMocks.importNginx.mockResolvedValue([]);
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

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith(message));
    expect(toastMocks.success).not.toHaveBeenCalled();
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
    expect(toastMocks.success).toHaveBeenCalledWith('sites.created');
    expect(toastMocks.error).not.toHaveBeenCalled();
  });
});

describe('SitesPage query states', () => {
  it('shows the request error and retries without leaving the table loading forever', async () => {
    apiMocks.fetchSites
      .mockRejectedValueOnce(new APIRequestError('site list unavailable', 'SITE_LIST_FAILED', 500))
      .mockResolvedValueOnce([]);
    renderSites();

    expect((await screen.findByRole('alert')).textContent).toContain('site list unavailable');
    expect(document.querySelector('.animate-spin')).toBeNull();

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

describe('SitesPage nginx import', () => {
  it('parses the pasted configuration, creates the selected site and refreshes the list', async () => {
    apiMocks.importNginx.mockResolvedValue([
      {
        name: 'shop.example.com',
        domains: ['shop.example.com', 'www.shop.example.com'],
        upstreams: [{ address: 'http://127.0.0.1:9000', weight: 1 }],
        listen_port: 8080,
        waf: { enabled: true, mode: 'block', rewrite: [] },
      },
      {
        name: '',
        domains: [],
        upstreams: [{ address: 'http://10.0.0.5:8080', weight: 1 }],
        listen_port: 80,
      },
    ]);
    apiMocks.createSite.mockResolvedValue(makeSite('site-shop', 'shop.example.com'));
    const { invalidateQueries } = renderSites();
    await waitFor(() => expect(apiMocks.fetchSites).toHaveBeenCalledTimes(1));

    const textarea = await openNginxImport();
    fireEvent.change(textarea, { target: { value: nginxFixture } });
    fireEvent.click(screen.getByRole('button', { name: 'sites.import.parse' }));

    await waitFor(() => expect(apiMocks.importNginx).toHaveBeenCalledTimes(1));
    expect(apiMocks.importNginx.mock.calls[0]?.[0]).toBe(nginxFixture);
    expect(await screen.findByText('sites.import.summary')).toBeTruthy();
    expect(screen.getByText('sites.import.issue.name')).toBeTruthy();
    expect(screen.getByText('sites.import.incompatible')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'sites.import.confirm' }));

    await waitFor(() => expect(apiMocks.createSite).toHaveBeenCalledTimes(1));
    expect(apiMocks.createSite.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      name: 'shop.example.com',
      domains: ['shop.example.com', 'www.shop.example.com'],
      upstreams: ['http://127.0.0.1:9000'],
      listen_port: 8080,
      waf_enabled: true,
      waf_mode: 'block',
      enabled: true,
    }));
    expect(await screen.findByText('sites.import.resultSummary')).toBeTruthy();
    expect(screen.getByText('sites.import.success')).toBeTruthy();
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['sites'] });
    expect(toastMocks.success).toHaveBeenCalledWith('sites.import.imported');
    expect(toastMocks.error).not.toHaveBeenCalled();
  });

  it('keeps the dialog open and reports the backend parse error', async () => {
    apiMocks.importNginx.mockRejectedValue(
      new APIRequestError('nginx configuration exceeds maximum import size', 'NGINX_IMPORT_TOO_LARGE', 400),
    );
    renderSites();

    const textarea = await openNginxImport();
    fireEvent.change(textarea, { target: { value: nginxFixture } });
    fireEvent.click(screen.getByRole('button', { name: 'sites.import.parse' }));

    expect((await screen.findByRole('alert')).textContent).toContain('nginx configuration exceeds maximum import size');
    expect(apiMocks.createSite).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'sites.import.parse' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'common.cancel' })).toBeTruthy();
  });

  it('reports an empty result instead of pretending the import succeeded', async () => {
    apiMocks.importNginx.mockResolvedValue([]);
    renderSites();

    const textarea = await openNginxImport();
    fireEvent.change(textarea, { target: { value: 'upstream backend { server 127.0.0.1:9000; }' } });
    fireEvent.click(screen.getByRole('button', { name: 'sites.import.parse' }));

    expect((await screen.findByRole('alert')).textContent).toContain('sites.import.noServerBlock');
    expect(apiMocks.importNginx).toHaveBeenCalledTimes(1);
    expect(apiMocks.createSite).not.toHaveBeenCalled();
  });

  it('blocks empty or oversized input before calling the import endpoint', async () => {
    renderSites();

    const textarea = await openNginxImport();
    fireEvent.change(textarea, { target: { value: '   \n  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'sites.import.parse' }));
    expect((await screen.findByRole('alert')).textContent).toContain('sites.import.empty');

    fireEvent.change(textarea, { target: { value: `server { ${'x'.repeat((1 << 20) + 1)} }` } });
    fireEvent.click(screen.getByRole('button', { name: 'sites.import.parse' }));
    await waitFor(() => expect(
      (screen.getByRole('alert') as HTMLElement).textContent,
    ).toContain('sites.import.tooLarge'));

    expect(apiMocks.importNginx).not.toHaveBeenCalled();
    expect(apiMocks.createSite).not.toHaveBeenCalled();
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
    fireEvent.click((sslLabel as HTMLElement).querySelector('[role="switch"]') as Element);
    expect((screen.getByRole('button', { name: 'common.next' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(screen.getByPlaceholderText('/etc/cheesewaf/certs/site.crt'), { target: { value: '/certs/site.crt' } });
    fireEvent.change(screen.getByPlaceholderText('/etc/cheesewaf/certs/site.key'), { target: { value: '/certs/site.key' } });

    expect((screen.getByRole('button', { name: 'common.next' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
