import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ProtectionConfig } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  fetchProtection: vi.fn(),
  updateACLProtection: vi.fn(),
  updateBotProtection: vi.fn(),
  updateIPProtection: vi.fn(),
  updateProtectionPolicy: vi.fn(),
  updateRateLimit: vi.fn(),
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

import { APIRequestError } from '../../api/client';
import ProtectionPage from './ProtectionPage';

const protectionFixture: ProtectionConfig = {
  policy: { web_attack: 'smart', api_security: 'smart', bot_cc: 'smart', threat_intel: 'smart' },
  ip: {
    whitelist: [],
    blacklist: [],
    access_rules: [],
    reputation_overrides: {},
    tags: {},
    threat_intel: [],
    providers: [],
    geoip: { enabled: false, database: '', precision_database: '', blocked_countries: [], country_cidrs: {} },
  },
  ratelimit: { enabled: false, default: { requests: 60, window: '1m', burst: 10 } },
  bot: {
    enabled: false,
    js_challenge: false,
    captcha: false,
    captcha_type: 'pow',
    captcha_types: ['pow'],
    captcha_challenge_ttl: '5m',
    captcha_failure_window: '10m',
    captcha_block_duration: '30m',
    captcha_escalation_types: ['pow'],
    captcha_binding_mode: 'strict_ip_ua',
    captcha_policy_version: 'v1',
    captcha_max_attempts: 5,
    image_captcha_length: 6,
    image_captcha_width: 220,
    image_captcha_height: 86,
    image_captcha_audio_limit: 6,
    slider_captcha_width: 320,
    slider_captcha_height: 150,
    slider_captcha_piece: 42,
    slider_captcha_tolerance: 6,
    slider_captcha_min_drag: '450ms',
    slider_captcha_track_required: true,
    captcha_mobile_type: 'pow',
    challenge_difficulty: 4,
    altcha_max_number: 75000,
    altcha_header_name: 'X-CheeseWAF-Altcha',
    waiting_room: false,
    waiting_room_max_active: 1000,
    waiting_room_ttl: '5m',
    challenge_ttl: '30m',
    cookie_name: 'cheesewaf_js_clearance',
    secret: '',
    path_prefixes: ['/'],
    exempt_path_prefixes: ['/health'],
    allowed_user_agents: [],
    suspicious_user_agents: [],
  },
  acl: {
    enabled: true,
    rules: [{
      id: 'acl-1',
      name: 'ACL fixture',
      method: 'POST',
      path_prefix: '/admin',
      header: '',
      header_value: '',
      action: 'block',
      severity: 'high',
      enabled: true,
    }],
  },
};

function renderProtection() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  render(
    <QueryClientProvider client={client}>
      <ProtectionPage />
    </QueryClientProvider>,
  );
  return client;
}

function desktopACLRow() {
  const match = screen.getAllByText('ACL fixture').find((element) => element.closest('tr'));
  const row = match?.closest('tr');
  if (!row) {
    throw new Error('ACL table row was not rendered');
  }
  return row;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchProtection.mockResolvedValue(structuredClone(protectionFixture));
  apiMocks.updateACLProtection.mockResolvedValue(protectionFixture.acl);
  apiMocks.updateBotProtection.mockResolvedValue(protectionFixture.bot);
  apiMocks.updateIPProtection.mockResolvedValue(protectionFixture.ip);
  apiMocks.updateProtectionPolicy.mockResolvedValue(protectionFixture.policy);
  apiMocks.updateRateLimit.mockResolvedValue(protectionFixture.ratelimit);
});

afterEach(() => cleanup());

describe('ProtectionPage query and ACL interactions', () => {
  it('blocks all policy forms behind a retryable load error', async () => {
    apiMocks.fetchProtection
      .mockRejectedValueOnce(new APIRequestError('protection unavailable', 'PROTECTION_READ_FAILED', 503))
      .mockResolvedValueOnce(structuredClone(protectionFixture));
    renderProtection();

    expect((await screen.findByRole('alert')).textContent).toContain('protection unavailable');
    expect(screen.queryByRole('button', { name: 'common.save' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));

    expect((await screen.findAllByText('ACL fixture')).length).toBeGreaterThan(0);
    expect(apiMocks.fetchProtection).toHaveBeenCalledTimes(2);
  });

  it('persists an ACL enabled switch change', async () => {
    renderProtection();
    await screen.findAllByText('ACL fixture');
    const toggle = desktopACLRow().querySelector('.arco-switch');
    expect(toggle).toBeTruthy();

    fireEvent.click(toggle as Element);

    await waitFor(() => expect(apiMocks.updateACLProtection).toHaveBeenCalledTimes(1));
    expect(apiMocks.updateACLProtection.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      rules: [expect.objectContaining({ id: 'acl-1', enabled: false })],
    }));
  });

  it('keeps the ACL editor and draft open when saving fails', async () => {
    apiMocks.updateACLProtection.mockRejectedValueOnce(new APIRequestError('ACL save failed', 'ACL_WRITE_FAILED', 500));
    renderProtection();
    await screen.findAllByText('ACL fixture');
    fireEvent.click(within(desktopACLRow()).getByRole('button', { name: 'common.edit' }));

    const editor = document.querySelector('.acl-editor-card');
    expect(editor).toBeTruthy();
    const nameInput = within(editor as HTMLElement).getByDisplayValue('ACL fixture') as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'ACL edited draft' } });
    fireEvent.click(within(editor as HTMLElement).getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith('ACL save failed'));
    expect(document.querySelector('.acl-editor-card')).toBeTruthy();
    expect(nameInput.value).toBe('ACL edited draft');
  });
});

describe('ProtectionPage bot form integrity', () => {
  it('preserves unvisited tab values and server-only fields on direct save', async () => {
    const fixture = structuredClone(protectionFixture);
    fixture.bot = {
      ...fixture.bot,
      captcha_challenge_ttl: '120s',
      captcha_failure_window: '300s',
      captcha_block_duration: '600s',
      captcha_escalation_types: ['shape_slider'],
      captcha_binding_mode: 'ip_prefix_ua',
      captcha_policy_version: 'server-v9',
      image_captcha_width: 318,
      slider_captcha_height: 177,
      waiting_room_max_active: 4321,
      cookie_name: 'server_cookie',
      risk_threshold: 91,
    } as ProtectionConfig['bot'] & { risk_threshold: number };
    apiMocks.fetchProtection.mockResolvedValue(fixture);
    apiMocks.updateBotProtection.mockImplementation(async (payload) => payload);
    renderProtection();
    await screen.findAllByText('ACL fixture');

    const botPanel = document.querySelector('.protection-bot-panel');
    expect(botPanel).toBeTruthy();
    fireEvent.click(within(botPanel as HTMLElement).getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(apiMocks.updateBotProtection).toHaveBeenCalledTimes(1));
    expect(apiMocks.updateBotProtection.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      captcha_challenge_ttl: 120_000_000_000,
      captcha_failure_window: 300_000_000_000,
      captcha_block_duration: 600_000_000_000,
      captcha_escalation_types: ['shape_slider'],
      captcha_binding_mode: 'ip_prefix_ua',
      captcha_policy_version: 'server-v9',
      image_captcha_width: 318,
      slider_captcha_height: 177,
      waiting_room_max_active: 4321,
      cookie_name: 'server_cookie',
      risk_threshold: 91,
    }));
  });

  it('keeps legacy image CAPTCHA as a localized selectable value', async () => {
    const fixture = structuredClone(protectionFixture);
    fixture.bot.captcha_type = 'image';
    apiMocks.fetchProtection.mockResolvedValue(fixture);
    renderProtection();

    expect(await screen.findByText('protection.captchaTypeImage')).toBeTruthy();
  });
});
