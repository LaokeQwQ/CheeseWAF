import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchIPRules: vi.fn(),
  fetchSites: vi.fn(),
  updateIPTags: vi.fn(),
  updateIPAccessRules: vi.fn(),
  updateIPReputationOverrides: vi.fn(),
  updateThreatIntelProviders: vi.fn(),
  importThreatIntel: vi.fn(),
  syncThreatIntel: vi.fn(),
  testThreatIntelProvider: vi.fn(),
  lookupThreatIntel: vi.fn(),
  exportThreatIntel: vi.fn(),
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
  useTranslation: () => ({
    t: (key: string, opts?: Record<string, unknown>) => (opts ? `${key}:${JSON.stringify(opts)}` : key),
  }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import IPManagePage from './IPManagePage';

const ipRulesFixture = {
  whitelist: ['198.51.100.20'],
  blacklist: ['203.0.113.10'],
  entries: [
    {
      ip: '203.0.113.10',
      list: 'blacklist',
      hits: 12,
      last_seen: '2026-07-01T00:00:00Z',
      reputation: 12,
      tags: ['scanner'],
      stats: { total: 12, blocked: 10, by_type: { sqli: 10 } },
      intel: [
        {
          id: 'ti-1',
          value: '203.0.113.10',
          source: 'abuseipdb',
          severity: 'high',
          action: 'challenge',
          labels: ['bruteforce'],
          confidence: 0.9,
        },
      ],
      access_rules: [],
    },
    {
      ip: '198.51.100.20',
      list: 'whitelist',
      hits: 2,
      last_seen: '2026-07-02T00:00:00Z',
      reputation: 90,
      tags: [],
      stats: { total: 2, blocked: 0, by_type: {} },
      intel: [],
      access_rules: [],
    },
  ],
  tags: {
    '203.0.113.10': ['scanner'],
  },
  access_rules: [
    {
      id: 'rule-block-1',
      name: 'block scanners',
      description: 'manual',
      action: 'block',
      scope: 'global',
      site_id: '',
      path_prefix: '',
      entries: ['203.0.113.10'],
      enabled: true,
    },
  ],
  reputation_overrides: {
    '203.0.113.10': 5,
  },
  providers: [
    {
      id: 'prov-1',
      name: 'AbuseIPDB',
      type: 'abuseipdb',
      endpoint: 'https://api.abuseipdb.com/api/v2/check',
      api_key: 'secret',
      auth_type: 'header',
      format: 'abuseipdb',
      action: 'challenge',
      min_severity: 'high',
      interval: 86_400_000_000_000,
      headers: {},
      notes: '',
      enabled: true,
    },
  ],
  threat_intel: [
    {
      id: 'ti-1',
      value: '203.0.113.10',
      ip: '203.0.113.10',
      source: 'abuseipdb',
      severity: 'high',
      action: 'challenge',
      labels: ['bruteforce'],
      confidence: 0.9,
    },
  ],
  geoip: {
    enabled: false,
    database: '',
    precision_database: '',
    blocked_countries: [],
    country_cidrs: {},
  },
};

function renderPage(initialEntries = ['/ip']) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={initialEntries}>
        <IPManagePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchIPRules.mockResolvedValue(ipRulesFixture);
  apiMocks.fetchSites.mockResolvedValue([
    { id: 'site-1', name: 'demo', domains: ['demo.test'], upstreams: ['127.0.0.1:8080'], enabled: true },
  ]);
  apiMocks.updateIPAccessRules.mockImplementation(async (rules) => rules);
  apiMocks.updateIPReputationOverrides.mockImplementation(async (map) => map);
  apiMocks.updateThreatIntelProviders.mockImplementation(async (items) => items);
  apiMocks.importThreatIntel.mockResolvedValue({ imported: 2, items: [{ ip: '1.2.3.4' }, { ip: '5.6.7.8' }] });
});

afterEach(() => {
  cleanup();
});

describe('IPManagePage', () => {
  it('loads IP entries, tags, reputation, and intel labels', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchIPRules).toHaveBeenCalled());
    expect(await screen.findByText('ip.title')).toBeTruthy();
    expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0);
    expect(screen.getAllByText('198.51.100.20').length).toBeGreaterThan(0);
    expect(screen.getAllByText('scanner').length).toBeGreaterThan(0);
    // Intel chip renders source + action, not raw labels
    expect(screen.getAllByText('abuseipdb').length).toBeGreaterThan(0);
  });

  it('filters entries by search needle across IP and tags', async () => {
    renderPage();
    await waitFor(() => expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0));
    const searchInput = screen.getByPlaceholderText('common.search');
    fireEvent.change(searchInput, { target: { value: 'scanner' } });
    await waitFor(() => {
      expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0);
      expect(screen.queryByText('198.51.100.20')).toBeNull();
    });
  });

  it('applies allow disposition for an IP through access-rule mutation', async () => {
    renderPage();
    await waitFor(() => expect(screen.getAllByText('203.0.113.10').length).toBeGreaterThan(0));
    const allowButtons = screen.getAllByRole('button', { name: 'ip.allow' });
    fireEvent.click(allowButtons[0]);
    await waitFor(() => expect(apiMocks.updateIPAccessRules).toHaveBeenCalled());
    const saved = apiMocks.updateIPAccessRules.mock.calls[0][0] as Array<{ action: string; entries: string[] }>;
    expect(saved.some((rule) => rule.action === 'allow' && rule.entries.includes('203.0.113.10'))).toBe(true);
    expect(messageMocks.success).toHaveBeenCalledWith('ip.accessRulesSaved');
  });

  it('rejects empty access-rule entries when adding a rule', async () => {
    renderPage(['/ip?tab=access']);
    await waitFor(() => expect(apiMocks.fetchIPRules).toHaveBeenCalled());
    expect(screen.getAllByText('ip.accessRules').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'ip.addRule' }));
    await waitFor(() => expect(messageMocks.warning).toHaveBeenCalledWith('ip.entriesRequired'));
    expect(apiMocks.updateIPAccessRules).not.toHaveBeenCalled();
  });

  it('switches to providers tab and shows configured intel provider', async () => {
    renderPage(['/ip?tab=intel']);
    await waitFor(() => expect(apiMocks.fetchIPRules).toHaveBeenCalled());
    await waitFor(() => {
      expect(screen.getAllByDisplayValue('https://api.abuseipdb.com/api/v2/check').length).toBeGreaterThan(0);
    });
    expect(screen.getAllByDisplayValue('AbuseIPDB').length).toBeGreaterThan(0);
  });

  it('imports threat intel IOCs after validation', async () => {
    renderPage(['/ip?tab=import']);
    await waitFor(() => expect(apiMocks.fetchIPRules).toHaveBeenCalled());

    const ioc = screen.getByPlaceholderText('ip.iocPlaceholder');
    fireEvent.change(ioc, { target: { value: '1.2.3.4\n5.6.7.8/32' } });

    const importBtn = await screen.findByRole('button', { name: 'ip.import' });
    await waitFor(() => expect((importBtn as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(importBtn);
    await waitFor(() => expect(apiMocks.importThreatIntel).toHaveBeenCalled());
    const payload = apiMocks.importThreatIntel.mock.calls[0][0] as { contents: string; format: string; source: string };
    expect(payload.contents).toContain('1.2.3.4');
    expect(payload.format).toBe('cidr');
    expect(payload.source).toBe('manual');
  });

  it('blocks invalid CIDR lines on import', async () => {
    renderPage(['/ip?tab=import']);
    await waitFor(() => expect(apiMocks.fetchIPRules).toHaveBeenCalled());
    fireEvent.change(screen.getByPlaceholderText('ip.iocPlaceholder'), { target: { value: 'not-an-ip' } });
    fireEvent.click(await screen.findByRole('button', { name: 'ip.import' }));
    await waitFor(() => expect(messageMocks.warning).toHaveBeenCalled());
    const warned = messageMocks.warning.mock.calls.map((c) => String(c[0]));
    expect(warned.some((msg) => msg.includes('ip.entriesInvalid'))).toBe(true);
    expect(apiMocks.importThreatIntel).not.toHaveBeenCalled();
  });
});
