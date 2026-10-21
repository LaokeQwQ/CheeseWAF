import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Site } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  deleteSite: vi.fn(),
  fetchACMEProviders: vi.fn(),
  fetchSite: vi.fn(),
  issueSiteACMECertificate: vi.fn(),
  updateSite: vi.fn(),
}));

const toastMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

const navigateMock = vi.hoisted(() => vi.fn());
const scrollIntoView = Element.prototype.scrollIntoView;

const inheritedProtectionControls = [
  ['bot', 'protection.bot'],
  ['ratelimit', 'protection.ratelimit'],
  ['acl', 'protection.acl'],
  ['apisec', 'nav.apisec'],
] as const;

vi.mock('sonner', () => ({
  toast: toastMocks,
}));

vi.mock('react-i18next', () => ({
  initReactI18next: { type: '3rdParty', init: () => undefined },
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
import SiteDetailPage from './SiteDetailPage';
import { normalizeSite } from './siteModel';

function makeSite(name: string): Site {
  return normalizeSite({
    id: 'site-1',
    name,
    domains: ['site.example.com'],
    upstreams: ['127.0.0.1:9000'],
  });
}

function makeInheritedProtectionSite() {
  const site = makeSite('initial-site');
  for (const [key] of inheritedProtectionControls) delete site.advanced.protection[key];
  return site;
}

async function openProtectionTab() {
  await screen.findByDisplayValue('initial-site');
  fireEvent.click(screen.getByText('sites.stepProtection'));
}

function protectionSelect(label: string) {
  return screen.getByRole('combobox', { name: new RegExp(label) });
}

async function selectProtectionValue(label: string, valueLabel: string) {
  fireEvent.click(protectionSelect(label));
  fireEvent.click(await screen.findByRole('option', { name: valueLabel }));
}

function renderSiteDetail() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  const invalidateQueries = vi.spyOn(client, 'invalidateQueries');
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/sites/site-1']}>
        <Routes>
          <Route path="/sites/:id" element={<SiteDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, invalidateQueries };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

async function renameAndSave(name: string) {
  const input = await screen.findByDisplayValue('initial-site');
  fireEvent.change(input, { target: { value: name } });
  fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
  return input as HTMLInputElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  Element.prototype.scrollIntoView = vi.fn();
  apiMocks.fetchACMEProviders.mockResolvedValue([]);
  apiMocks.fetchSite.mockResolvedValue(makeSite('initial-site'));
});

afterEach(() => {
  cleanup();
  Element.prototype.scrollIntoView = scrollIntoView;
});

describe('SiteDetailPage save failures', () => {
  it.each([
    { code: 'FORBIDDEN', message: '403 site update is forbidden', status: 403 },
    { code: 'SITE_CONFLICT', message: '409 site changed concurrently', status: 409 },
  ])('keeps the draft and query cache unchanged for a $status response', async ({ code, message, status }) => {
    const initial = makeSite('initial-site');
    apiMocks.fetchSite.mockResolvedValue(initial);
    apiMocks.updateSite.mockRejectedValue(new APIRequestError(message, code, status));
    const { client, invalidateQueries } = renderSiteDetail();

    const input = await renameAndSave('edited-site');

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith(message));
    expect(apiMocks.updateSite.mock.calls[0]?.[0]).toBe('site-1');
    expect(apiMocks.updateSite.mock.calls[0]?.[1]).toEqual(expect.objectContaining({ name: 'edited-site' }));
    expect(toastMocks.success).not.toHaveBeenCalled();
    expect(invalidateQueries).not.toHaveBeenCalled();
    expect(apiMocks.fetchSite).toHaveBeenCalledTimes(1);
    expect(client.getQueryData(['site', 'site-1'])).toEqual(initial);
    expect(input.value).toBe('edited-site');
    expect(navigateMock).not.toHaveBeenCalled();
  });
});

describe('SiteDetailPage save success', () => {
  it('does not turn inherited protection into overrides when only renaming a site', async () => {
    const initial = makeSite('initial-site');
    for (const key of ['bot', 'ratelimit', 'acl', 'apisec'] as const) delete initial.advanced.protection[key];
    apiMocks.fetchSite.mockResolvedValue(initial);
    apiMocks.updateSite.mockResolvedValue(initial);
    renderSiteDetail();

    await renameAndSave('renamed-site');
    await waitFor(() => expect(apiMocks.updateSite).toHaveBeenCalledTimes(1));
    const protection = JSON.parse(JSON.stringify(apiMocks.updateSite.mock.calls[0]?.[1].advanced.protection));
    for (const key of ['bot', 'ratelimit', 'acl', 'apisec']) expect(protection).not.toHaveProperty(key);
  });

  it('shows inherited modules as inherited instead of guessing their global state', async () => {
    apiMocks.fetchSite.mockResolvedValue(makeInheritedProtectionSite());
    renderSiteDetail();
    await openProtectionTab();

    for (const [, label] of inheritedProtectionControls) {
      expect(protectionSelect(label).textContent).toBe('sites.levelInherit');
    }
    expect(screen.getByRole('switch', { name: 'SQLi' }).getAttribute('aria-checked')).toBe('true');
  });

  it.each(inheritedProtectionControls)('keeps inherited selection when keyboard focus moves for %s', async (_key, label) => {
    apiMocks.fetchSite.mockResolvedValue(makeInheritedProtectionSite());
    renderSiteDetail();
    await openProtectionTab();
    fireEvent.click(protectionSelect(label));
    const inheritedOption = await screen.findByRole('option', { name: 'sites.levelInherit' });
    const enabledOption = screen.getByRole('option', { name: 'common.enabled' });

    await waitFor(() => expect(document.activeElement).toBe(inheritedOption));
    fireEvent.keyDown(inheritedOption, { key: 'ArrowDown' });
    await waitFor(() => expect(document.activeElement).toBe(enabledOption));
    expect(inheritedOption.getAttribute('data-state')).toBe('checked');
    expect(enabledOption.getAttribute('data-state')).toBe('unchecked');
  });

  it('only makes the protection selection the operator changes explicit', async () => {
    const initial = makeInheritedProtectionSite();
    apiMocks.fetchSite.mockResolvedValue(initial);
    apiMocks.updateSite.mockResolvedValue(initial);
    renderSiteDetail();
    await openProtectionTab();
    await selectProtectionValue('protection.acl', 'common.disabled');
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(apiMocks.updateSite).toHaveBeenCalledTimes(1));
    const protection = JSON.parse(JSON.stringify(apiMocks.updateSite.mock.calls[0]?.[1].advanced.protection));
    expect(protection.acl).toBe(false);
    for (const key of ['bot', 'ratelimit', 'apisec']) expect(protection).not.toHaveProperty(key);
  });

  it.each(inheritedProtectionControls.flatMap(([key, label]) => [
    { key, label, value: true, valueLabel: 'common.enabled' },
    { key, label, value: false, valueLabel: 'common.disabled' },
  ]))('saves an explicit $value override only for $key', async ({ key, label, value, valueLabel }) => {
    const initial = makeInheritedProtectionSite();
    apiMocks.fetchSite.mockResolvedValue(initial);
    apiMocks.updateSite.mockResolvedValue(initial);
    renderSiteDetail();
    await openProtectionTab();
    await selectProtectionValue(label, valueLabel);
    expect(protectionSelect(label).textContent).toBe(valueLabel);
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(apiMocks.updateSite).toHaveBeenCalledTimes(1));
    const protection = JSON.parse(JSON.stringify(apiMocks.updateSite.mock.calls[0]?.[1].advanced.protection));
    expect(protection[key]).toBe(value);
    for (const [untouchedKey] of inheritedProtectionControls) {
      if (untouchedKey !== key) expect(protection).not.toHaveProperty(untouchedKey);
    }
  });

  it.each(inheritedProtectionControls.flatMap(([key, label]) => [
    { key, label, value: true, valueLabel: 'common.enabled' },
    { key, label, value: false, valueLabel: 'common.disabled' },
  ]))('restores inheritance from an explicit $value override for $key', async ({ key, label, value, valueLabel }) => {
    const initial = makeInheritedProtectionSite();
    initial.advanced.protection[key] = value;
    apiMocks.fetchSite.mockResolvedValue(initial);
    apiMocks.updateSite.mockResolvedValue(initial);
    renderSiteDetail();
    await openProtectionTab();
    expect(protectionSelect(label).textContent).toBe(valueLabel);
    await selectProtectionValue(label, 'sites.levelInherit');
    expect(protectionSelect(label).textContent).toBe('sites.levelInherit');
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(apiMocks.updateSite).toHaveBeenCalledTimes(1));
    const protection = JSON.parse(JSON.stringify(apiMocks.updateSite.mock.calls[0]?.[1].advanced.protection));
    for (const [inheritedKey] of inheritedProtectionControls) expect(protection).not.toHaveProperty(inheritedKey);
  });

  it('invalidates and rereads the persisted site after saving', async () => {
    const initial = makeSite('initial-site');
    const saved = makeSite('edited-site');
    const persisted = makeSite('edited-site-persisted');
    apiMocks.fetchSite
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(persisted);
    apiMocks.updateSite.mockResolvedValue(saved);
    const { client, invalidateQueries } = renderSiteDetail();

    await renameAndSave('edited-site');

    await waitFor(() => expect(apiMocks.updateSite).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiMocks.fetchSite).toHaveBeenCalledTimes(2));
    expect(await screen.findByDisplayValue('edited-site-persisted')).toBeTruthy();
    expect(client.getQueryData(['site', 'site-1'])).toEqual(persisted);
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['sites'] });
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['site', 'site-1'] });
    expect(toastMocks.success).toHaveBeenCalledWith('sites.saved');
    expect(toastMocks.error).not.toHaveBeenCalled();
  });

  it('shows the persisted semantic sensitivity on the protection tab', async () => {
    apiMocks.fetchSite.mockResolvedValue(normalizeSite({ ...makeSite('initial-site'), paranoia_level: 3 }));
    renderSiteDetail();
    await screen.findByDisplayValue('initial-site');
    fireEvent.click(screen.getByText('sites.stepProtection'));
    expect(screen.getByText('sites.paranoiaLevel')).toBeTruthy();
    expect(screen.getByText('sites.paranoiaDefault')).toBeTruthy();
  });
});

describe('SiteDetailPage query states', () => {
  it('shows a retryable error instead of presenting a failed request as not found', async () => {
    apiMocks.fetchSite
      .mockRejectedValueOnce(new APIRequestError('site detail unavailable', 'SITE_READ_FAILED', 503))
      .mockResolvedValueOnce(makeSite('initial-site'));
    renderSiteDetail();

    expect((await screen.findByRole('alert')).textContent).toContain('site detail unavailable');
    expect(screen.queryByText('sites.notFound')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));

    expect(await screen.findByDisplayValue('initial-site')).toBeTruthy();
    expect(apiMocks.fetchSite).toHaveBeenCalledTimes(2);
  });

  it('shows and retries an ACME provider error inside the TLS workspace', async () => {
    apiMocks.fetchACMEProviders
      .mockRejectedValueOnce(new APIRequestError('provider list unavailable', 'ACME_PROVIDER_FAILED', 503))
      .mockResolvedValueOnce([]);
    renderSiteDetail();
    await screen.findByDisplayValue('initial-site');
    fireEvent.click(screen.getByText('sites.stepTls'));

    expect((await screen.findByRole('alert')).textContent).toContain('provider list unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));

    await waitFor(() => expect(apiMocks.fetchACMEProviders).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });
});

describe('SiteDetailPage mutation locking', () => {
  it('disables the editable workspace while a save response is pending', async () => {
    const pending = deferred<Site>();
    const initial = makeSite('initial-site');
    const saved = makeSite('saved-site');
    apiMocks.fetchSite
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(saved);
    apiMocks.updateSite.mockReturnValue(pending.promise);
    renderSiteDetail();

    const input = await screen.findByDisplayValue('initial-site') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'saved-site' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(document.querySelector('.site-detail-fieldset')?.hasAttribute('disabled')).toBe(true));
    expect(input.matches(':disabled')).toBe(true);

    pending.resolve(saved);
    await waitFor(() => expect(document.querySelector('.site-detail-fieldset')?.hasAttribute('disabled')).toBe(false));
  });
});
