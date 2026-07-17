import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { TFunction } from 'i18next';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { APIRequestError } from '../../api/client';
import BotChallengePage, { TrendChart } from './BotChallengePage';

const botAPI = vi.hoisted(() => ({ fetchBotChallengeMetrics: vi.fn() }));
const clientAPI = vi.hoisted(() => ({ fetchLogs: vi.fn() }));

vi.mock('../../api/botChallenge', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../api/botChallenge')>(),
  fetchBotChallengeMetrics: botAPI.fetchBotChallengeMetrics,
}));
vi.mock('../../api/client', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../api/client')>(),
  fetchLogs: clientAPI.fetchLogs,
}));
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
    i18n: { resolvedLanguage: 'en-US' },
  }),
}));

const stylesSource = readFileSync(join(process.cwd(), 'src/pages/BotChallenge/BotChallengePage.module.css'), 'utf8');

const translate = ((key: string, values?: Record<string, unknown>) => (
  values ? `${key}:${JSON.stringify(values)}` : key
)) as TFunction;

const metrics = {
  range: '24h',
  bucket: '2h',
  start: '2026-07-13T00:00:00Z',
  end: '2026-07-14T00:00:00Z',
  totals: {
    challenged_people: 37,
    challenges: 42,
    blocked_people: 5,
    blocks: 6,
    captcha_blocks: 4,
    successes: 30,
    failures: 6,
    pass_rate: 30 / 36,
  },
  trend: [],
};

const challengeLog = {
  id: 'event-1',
  trace_id: 'trace-1',
  timestamp: '2026-07-13T10:00:00Z',
  client_ip: '203.0.113.8',
  site_id: 'site-1',
  country: 'US',
  action: 'challenge',
  category: 'bot',
  detector_id: 'bot-policy',
  message: 'automation detected',
  metadata: { captcha_type: 'pow' },
};

function tokenWithScopes(scopes: string[]) {
  const payload = btoa(JSON.stringify({ role: 'api_token', scope: scopes }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `header.${payload}.signature`;
}

function renderPage(scopes: string[]) {
  localStorage.setItem('cheesewaf-token', tokenWithScopes(scopes));
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><BotChallengePage/></MemoryRouter>
    </QueryClientProvider>,
  );
}

function eventPanel() {
  return screen.getByText('botChallenge.events').closest('section') as HTMLElement;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
});

beforeEach(() => {
  vi.clearAllMocks();
  botAPI.fetchBotChallengeMetrics.mockResolvedValue(metrics);
  clientAPI.fetchLogs.mockResolvedValue({ items: [], total: 0 });
});

describe('Bot challenge theme integration', () => {
  it('uses the project theme tokens instead of undefined legacy variables', () => {
    expect(stylesSource).not.toMatch(/--(?:panel-bg|brand-color|fill-color|text-tertiary)\b/);
    expect(stylesSource).toContain('var(--surface)');
    expect(stylesSource).toContain('var(--accent)');
    expect(stylesSource).toContain('var(--surface-soft)');
    expect(stylesSource).toContain('var(--text-muted)');
  });

  it('keeps the mobile range and refresh controls in one flex row', () => {
    expect(stylesSource).toMatch(/\.header\s*>\s*\.actions\s*\{[^}]*display:\s*flex/);
    expect(stylesSource).toMatch(/\.actions\s+:global\(\.arco-select\)\s*\{[^}]*flex:\s*1[^}]*min-width:\s*0/);
  });
});

describe('Bot challenge trend interaction', () => {
  it('exposes each trend bucket to keyboard and touch users', () => {
    render(<TrendChart
      locale={'zh-CN'}
      t={translate}
      points={[{
        time: '2026-07-13T10:00:00Z',
        type: 'all',
        issued: 12,
        successes: 9,
        failures: 2,
        blocks: 1,
      }]}
    />);

    expect(screen.getByRole('group', { name: 'botChallenge.trendAria' })).toBeTruthy();
    const bucket = screen.getByRole('button', { name: /botChallenge\.bucketAria/ });
    expect(bucket.getAttribute('aria-expanded')).toBe('false');
    expect(bucket.tabIndex).toBe(0);

    bucket.focus();
    expect(document.activeElement).toBe(bucket);
    fireEvent.click(bucket);
    expect(bucket.getAttribute('aria-expanded')).toBe('true');
    expect(screen.getByRole('tooltip').getAttribute('data-open')).toBe('true');

    fireEvent.keyDown(bucket, { key: 'Escape' });
    expect(bucket.getAttribute('aria-expanded')).toBe('false');
    expect(screen.getByRole('tooltip').getAttribute('data-open')).toBe('false');
  });
});

describe('Bot challenge event permissions and failures', () => {
  it('keeps metrics visible and shows a permission state when read:logs is absent', async () => {
    renderPage(['read:protection']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect(screen.getByText('botChallenge.eventsPermissionHint')).toBeTruthy();
    expect(clientAPI.fetchLogs).not.toHaveBeenCalled();
  });

  it('loads challenge events when read:logs is present', async () => {
    clientAPI.fetchLogs.mockResolvedValue({ items: [challengeLog], total: 1 });
    renderPage(['read:protection', 'read:logs']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect((await screen.findAllByText('trace-1')).length).toBeGreaterThan(0);
    expect(clientAPI.fetchLogs).toHaveBeenCalledTimes(1);
  });

  it('shows an event error instead of empty data for 401 responses', async () => {
    clientAPI.fetchLogs.mockRejectedValue(new APIRequestError('session expired', 'UNAUTHORIZED', 401));
    renderPage(['read:protection', 'read:logs']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect(await screen.findByText('session expired')).toBeTruthy();
    expect(within(eventPanel()).queryByText('botChallenge.noEvents')).toBeNull();
  });

  it('shows a permission state for 403 responses even when the token lists read:logs', async () => {
    clientAPI.fetchLogs.mockRejectedValue(new APIRequestError('permission denied', 'FORBIDDEN', 403));
    renderPage(['read:protection', 'read:logs']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect(await screen.findByText('botChallenge.eventsPermissionHint')).toBeTruthy();
    expect(within(eventPanel()).queryByText('botChallenge.noEvents')).toBeNull();
  });

  it('shows an event error instead of empty data for 5xx responses', async () => {
    clientAPI.fetchLogs.mockRejectedValue(new APIRequestError('logs unavailable', 'INTERNAL', 503));
    renderPage(['read:protection', 'read:logs']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect(await screen.findByText('logs unavailable')).toBeTruthy();
    expect(within(eventPanel()).queryByText('botChallenge.noEvents')).toBeNull();
  });

  it('shows an event error instead of empty data for network failures', async () => {
    clientAPI.fetchLogs.mockRejectedValue(new Error('network unavailable'));
    renderPage(['read:protection', 'read:logs']);

    expect(await screen.findByText('42')).toBeTruthy();
    expect(await screen.findByText('network unavailable')).toBeTruthy();
    expect(within(eventPanel()).queryByText('botChallenge.noEvents')).toBeNull();
  });
});
