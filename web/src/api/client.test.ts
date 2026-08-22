import axios from 'axios';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  APIRequestError,
  askAIAssistantStream,
  continueAIApprovalStream,
  fetchAIApproval,
  fetchAIApprovals,
  analyzeEventsStream,
  analyzeLogReferenceStream,
  bootstrapSessionFromLegacyToken,
  captureSetupTokenFromFragment,
  getCSRFToken,
  handleUnauthorizedAuthFailure,
  isSessionInvalidAuthFailure,
  fetchHealth,
  fetchTimeSyncStatus,
  issueCaptchaLabChallenge,
  reselectTimeSync,
  syncTimeNow,
  verifyCaptchaLabChallenge,
  clearNotifications,
  deleteRule,
  deleteSite,
  disableUser2FA,
  enableUser2FA,
  fetchSession,
  fetchSite,
  issueSiteACMECertificate,
  login,
  parseSSEBlock,
  recoverUser2FA,
  refreshSession,
  resetAuthRedirectStateForTest,
  resetSetupTokenForTest,
  setupAdmin,
  setupUser2FA,
  updateRule,
  updateSite,
  updateUser,
  fetchNotifications,
  markAllNotificationsRead,
  logout,
  sanitizeInternalReturnPath,
  setCSRFToken,
  setAuthRedirectLocationForTest,
  updateNotification,
} from './client';
import { apiClient } from './client';
import { queryClient } from '../queryClient';

describe('CAPTCHA Lab API cancellation', () => {
  afterEach(() => vi.restoreAllMocks());

  it('passes the caller signal to challenge issuance', async () => {
    const controller = new AbortController();
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { token: 'token' } } });

    await issueCaptchaLabChallenge('random', controller.signal);

    expect(post).toHaveBeenCalledWith('/captcha/lab/challenges', { type: 'random' }, { signal: controller.signal });
  });

  it('passes the caller signal to verification', async () => {
    const controller = new AbortController();
    const response = { token: 'token', offset: 42 };
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { valid: true } } });

    await verifyCaptchaLabChallenge(response, controller.signal);

    expect(post).toHaveBeenCalledWith('/captcha/lab/verify', response, { signal: controller.signal });
  });
});

describe('first-install setup token', () => {
  let originalAdapter: typeof apiClient.defaults.adapter;

  beforeEach(() => {
    sessionStorage.clear();
    window.history.replaceState({}, '', '/setup');
    originalAdapter = apiClient.defaults.adapter;
  });

  afterEach(() => {
    resetSetupTokenForTest();
    sessionStorage.clear();
    window.history.replaceState({}, '', '/');
    apiClient.defaults.adapter = originalAdapter;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('keeps the fragment token in memory and sends it only on setup mutations', async () => {
    window.history.replaceState({}, '', '/setup#setup_token=fragment-secret');
    sessionStorage.setItem('cheesewaf-setup-token', 'stale-persisted-secret');
    const seenHeaders: Array<string | undefined> = [];
    const adapter = vi.fn(async (config) => {
      seenHeaders.push(config.headers.get('X-CheeseWAF-Setup-Token')?.toString());
      return { data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config };
    });

    await apiClient.post('/setup/probe', {}, { adapter });
    await apiClient.post('/users/user-1/2fa/setup', {}, { adapter });

    expect(seenHeaders).toEqual(['fragment-secret', undefined]);
    expect(sessionStorage.getItem('cheesewaf-setup-token')).toBeNull();
    expect(window.location.hash).toBe('');
  });

  it('loads the setup token from loopback setup_url when the fragment is empty', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        data: { needs_setup: true, setup_url: 'http://127.0.0.1:9443/setup#setup_token=status-secret' },
      }),
    }));
    vi.stubGlobal('fetch', fetchMock);
    const seenHeaders: Array<string | undefined> = [];
    const adapter = vi.fn(async (config) => {
      seenHeaders.push(config.headers.get('X-CheeseWAF-Setup-Token')?.toString());
      return { data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config };
    });

    await apiClient.post('/setup/probe', {}, { adapter });

    expect(seenHeaders).toEqual(['status-secret']);
    expect(sessionStorage.getItem('cheesewaf-setup-token')).toBeNull();
    expect(fetchMock).toHaveBeenCalled();
  });

  it('clears the in-memory setup token only after setup completes successfully', async () => {
    window.history.replaceState({}, '', '/setup#setup_token=one-time-secret');
    const seenHeaders: Array<string | undefined> = [];
    const adapter = vi.fn(async (config) => {
      seenHeaders.push(config.headers.get('X-CheeseWAF-Setup-Token')?.toString());
      return {
        data: { data: { user: { username: 'admin', role: 'admin' } } },
        status: 200,
        statusText: 'OK',
        headers: {},
        config,
      };
    });
    apiClient.defaults.adapter = adapter;
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false })));

    await setupAdmin('admin', 'Correct-Horse-9x!', '127.0.0.1:9443');
    await apiClient.post('/setup/probe', {}, { adapter });

    expect(seenHeaders).toEqual(['one-time-secret', undefined]);
    expect(sessionStorage.getItem('cheesewaf-setup-token')).toBeNull();
  });

  it('retains the in-memory token when setup fails so a retry can reuse it', async () => {
    window.history.replaceState({}, '', '/setup#setup_token=retry-secret');
    captureSetupTokenFromFragment();
    const post = vi.spyOn(apiClient, 'post').mockRejectedValueOnce(new Error('setup unavailable'));

    await expect(setupAdmin('admin', 'Correct-Horse-9x!', '127.0.0.1:9443')).rejects.toThrow('setup unavailable');
    post.mockRestore();

    const seenHeaders: Array<string | undefined> = [];
    const adapter = vi.fn(async (config) => {
      seenHeaders.push(config.headers.get('X-CheeseWAF-Setup-Token')?.toString());
      return { data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config };
    });
    await apiClient.post('/setup/probe', {}, { adapter });

    expect(seenHeaders).toEqual(['retry-secret']);
  });
});

describe('authenticated account cache and request paths', () => {
  let originalAdapter: typeof apiClient.defaults.adapter;

  beforeEach(() => {
    sessionStorage.clear();
    localStorage.clear();
    originalAdapter = apiClient.defaults.adapter;
  });

  afterEach(() => {
    apiClient.defaults.adapter = originalAdapter;
    resetSetupTokenForTest();
    sessionStorage.clear();
    localStorage.clear();
    window.history.replaceState({}, '', '/');
    setCSRFToken('');
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('caches the authenticated subject from login and session responses', async () => {
    const adapter = vi.fn(async (config) => ({
      data: { data: { csrf: 'csrf-token', user: { id: 'account-1', username: 'admin', role: 'admin', scopes: ['read:users'] } } },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    }));
    apiClient.defaults.adapter = adapter;

    await login('admin', 'correct-password');
    expect(sessionStorage.getItem('cheesewaf-account')).toBe(JSON.stringify({ subject: 'account-1', username: 'admin', role: 'admin', scopes: ['read:users'] }));

    await fetchSession();
    expect(sessionStorage.getItem('cheesewaf-account')).toBe(JSON.stringify({ subject: 'account-1', username: 'admin', role: 'admin', scopes: ['read:users'] }));
  });

  it('updates the account cache after refresh and legacy bootstrap responses', async () => {
    const post = vi.spyOn(apiClient, 'post')
      .mockResolvedValueOnce({ data: { data: { user: { id: 'refresh-id', username: 'refreshed', role: 'readonly' } } }, status: 200 })
      .mockResolvedValueOnce({ data: { data: { user: { id: 'bootstrap-id', username: 'migrated', role: 'admin' } } }, status: 200 });

    await refreshSession();
    expect(sessionStorage.getItem('cheesewaf-account')).toBe(JSON.stringify({ subject: 'refresh-id', username: 'refreshed', role: 'readonly', scopes: [] }));

    localStorage.setItem('cheesewaf-token', 'legacy-token');
    await expect(bootstrapSessionFromLegacyToken()).resolves.toBe(true);
    expect(sessionStorage.getItem('cheesewaf-account')).toBe(JSON.stringify({ subject: 'bootstrap-id', username: 'migrated', role: 'admin', scopes: [] }));
    expect(post).toHaveBeenLastCalledWith('/auth/session/bootstrap', {}, { headers: { Authorization: 'Bearer legacy-token' } });
  });

  it('uses exact setup and auth paths when deciding whether to add CSRF', async () => {
    setCSRFToken('csrf-token');
    window.history.replaceState({}, '', '/setup#setup_token=csrf-test-secret');
    captureSetupTokenFromFragment();
    const seenHeaders: Array<string | undefined> = [];
    const adapter = vi.fn(async (config) => {
      seenHeaders.push(config.headers.get('X-CSRF-Token')?.toString());
      return { data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config };
    });

    await apiClient.post('/auth/login', {}, { adapter });
    await apiClient.post('/setup/probe', {}, { adapter });
    await apiClient.post('/auth/login-audit', {}, { adapter });
    await apiClient.post('/setup-notes', {}, { adapter });
    expect(seenHeaders).toEqual([undefined, undefined, 'csrf-token', 'csrf-token']);
  });

  it('encodes every changed client path parameter', async () => {
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: {} } });
    const put = vi.spyOn(apiClient, 'put').mockResolvedValue({ data: { data: {} } });
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: {} } });
    const del = vi.spyOn(apiClient, 'delete').mockResolvedValue({ data: { data: {} } });
    const id = 'a/b?c#d';

    await Promise.all([
      fetchSite(id), updateSite(id, {}), deleteSite(id), issueSiteACMECertificate(id, { provider_id: 'provider', dns_api: 'dns', dns_env: {}, account_email: 'ops@example.test', server: 'production', key_type: 'rsa', auto_renew: true, notify: false }),
      updateUser(id, {}), setupUser2FA(id), enableUser2FA(id, 'secret', '654321'), disableUser2FA(id, 'password', '123456'), recoverUser2FA(id, 'password', 'admin'),
      updateRule(id, {}), deleteRule(id),
    ]);

    expect(get).toHaveBeenCalledWith('/sites/a%2Fb%3Fc%23d');
    expect(put).toHaveBeenCalledWith('/sites/a%2Fb%3Fc%23d', {});
    expect(del).toHaveBeenCalledWith('/sites/a%2Fb%3Fc%23d');
    expect(post).toHaveBeenCalledWith('/sites/a%2Fb%3Fc%23d/acme/issue', expect.anything(), { timeout: 180_000 });
    expect(put).toHaveBeenCalledWith('/users/a%2Fb%3Fc%23d', {});
    expect(post).toHaveBeenCalledWith('/users/a%2Fb%3Fc%23d/2fa/setup');
    expect(post).toHaveBeenCalledWith('/users/a%2Fb%3Fc%23d/2fa/enable', { secret: 'secret', code: '654321' });
    expect(post).toHaveBeenCalledWith('/users/a%2Fb%3Fc%23d/2fa/disable', { password: 'password', code: '123456' });
    expect(post).toHaveBeenCalledWith('/users/a%2Fb%3Fc%23d/2fa/recover', { password: 'password', confirm_username: 'admin' });
    expect(put).toHaveBeenCalledWith('/rules/a%2Fb%3Fc%23d', {});
    expect(del).toHaveBeenCalledWith('/rules/a%2Fb%3Fc%23d');
  });
});

describe('SSE frame parsing', () => {
  it('skips malformed JSON frames without preventing later events', () => {
    expect(parseSSEBlock('event: trace\ndata: {broken')).toBeNull();
    expect(parseSSEBlock('event: done\ndata: {"answer":"complete"}')).toEqual({ event: 'done', data: { answer: 'complete' } });
  });
});

describe('time synchronization API', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses the status and operation endpoints', async () => {
    const status = {
      enabled: true,
      state: 'synchronized',
      offset_ms: 0,
      rtt_ms: 12,
      consecutive_failures: 0,
      total_failures: 0,
      current_time: '2026-07-15T10:00:00Z',
    };
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: status } });
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: status } });

    await expect(fetchTimeSyncStatus()).resolves.toEqual(status);
    await expect(reselectTimeSync()).resolves.toEqual(status);
    await expect(syncTimeNow()).resolves.toEqual(status);

    expect(get).toHaveBeenCalledWith('/system/time-sync');
    expect(post).toHaveBeenNthCalledWith(1, '/system/time-sync/reselect', {});
    expect(post).toHaveBeenNthCalledWith(2, '/system/time-sync/sync', {});
  });
});

describe('shell health API', () => {
  afterEach(() => vi.restoreAllMocks());

  it('rejects when the health connection is interrupted', async () => {
    const connectionError = new Error('connection lost');
    vi.spyOn(axios, 'get').mockRejectedValueOnce(connectionError);

    await expect(fetchHealth()).rejects.toBe(connectionError);
  });

  it('returns structured health after a disconnected request recovers', async () => {
    const get = vi.spyOn(axios, 'get')
      .mockRejectedValueOnce(new Error('connection lost'))
      .mockResolvedValueOnce({
        data: { data: { status: 'ok', uptime_seconds: 42 } },
        status: 200,
      });

    await expect(fetchHealth()).rejects.toThrow('connection lost');
    await expect(fetchHealth()).resolves.toEqual({ status: 'ok', uptime_seconds: 42 });
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('rejects an empty successful health response instead of returning undefined', async () => {
    vi.spyOn(axios, 'get').mockResolvedValueOnce({ data: {}, status: 200 });

    await expect(fetchHealth()).rejects.toEqual(expect.objectContaining<Partial<APIRequestError>>({
      code: 'HEALTH_RESPONSE_INVALID',
      status: 200,
    }));
  });
});

describe('authenticated fetch 401 handling', () => {
  const assign = vi.fn();

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    resetAuthRedirectStateForTest();
    setAuthRedirectLocationForTest({ pathname: '/ai', assign });
    assign.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetAuthRedirectStateForTest();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('clears legacy token, React Query cache, and schedules only one login redirect', () => {
    localStorage.setItem('cheesewaf-token', 'token');
    sessionStorage.setItem('cheesewaf-authed', '1');
    sessionStorage.setItem('cheesewaf-account', '{"subject":"admin-id","username":"admin","role":"admin","scopes":[]}');
    queryClient.setQueryData(['sites'], [{ id: 'site-1' }]);
    expect(queryClient.getQueryData(['sites'])).toEqual([{ id: 'site-1' }]);

    handleUnauthorizedAuthFailure({ pathname: '/ai', search: '?tab=models', hash: '#reasoning', assign });
    handleUnauthorizedAuthFailure({ pathname: '/updates', assign });

    expect(localStorage.getItem('cheesewaf-token')).toBeNull();
    expect(sessionStorage.getItem('cheesewaf-authed')).toBeNull();
    expect(sessionStorage.getItem('cheesewaf-account')).toBeNull();
    expect(queryClient.getQueryData(['sites'])).toBeUndefined();
    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign).toHaveBeenCalledWith('/login?returnTo=%2Fai%3Ftab%3Dmodels%23reasoning');
  });

  it('accepts only same-origin application paths as login return targets', () => {
    expect(sanitizeInternalReturnPath('/logs/cw-123?tab=analysis#details')).toBe('/logs/cw-123?tab=analysis#details');
    expect(sanitizeInternalReturnPath('//evil.example/login')).toBe('/');
    expect(sanitizeInternalReturnPath('https://evil.example/login')).toBe('/');
    expect(sanitizeInternalReturnPath('/login?returnTo=/ai')).toBe('/');
  });

  it('applies the same handling to authenticated SSE fetch failures', async () => {
    localStorage.setItem('cheesewaf-token', 'token');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'UNAUTHORIZED', message: 'Unauthorized' },
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(analyzeLogReferenceStream('trace-1')).rejects.toMatchObject({ status: 401 });
    await expect(analyzeLogReferenceStream('trace-2')).rejects.toMatchObject({ status: 401 });

    expect(localStorage.getItem('cheesewaf-token')).toBeNull();
    expect(assign).toHaveBeenCalledTimes(1);
  });

  it('preserves the active session for business credential failures', async () => {
    localStorage.setItem('cheesewaf-token', 'token');
    sessionStorage.setItem('cheesewaf-authed', '1');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { code: 'INVALID_CREDENTIALS', message: 'invalid current password' },
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    })));

    await expect(analyzeLogReferenceStream('trace-1')).rejects.toMatchObject({ status: 401, code: 'INVALID_CREDENTIALS' });

    expect(localStorage.getItem('cheesewaf-token')).toBe('token');
    expect(sessionStorage.getItem('cheesewaf-authed')).toBe('1');
    expect(assign).not.toHaveBeenCalled();
  });

  it('recognizes only canonical 401 session failures', () => {
    expect(isSessionInvalidAuthFailure(new APIRequestError('expired', 'UNAUTHORIZED', 401))).toBe(true);
    expect(isSessionInvalidAuthFailure(new APIRequestError('bad password', 'INVALID_CREDENTIALS', 401))).toBe(false);
    expect(isSessionInvalidAuthFailure(new APIRequestError('server error', 'UNAUTHORIZED', 500))).toBe(false);
  });

  it('does not publish batch items when the SSE stream ends without done', async () => {
    const encoder = new TextEncoder();
    const item = { log_id: 'log-1', risk: 'high', summary: 'partial', evidence: [], event_type: 'sqli', ai_used: true, recommended_actions: [] };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(encoder.encode(`event: item\ndata: ${JSON.stringify(item)}\n\n`));
        controller.close();
      },
    }), { status: 200, headers: { 'Content-Type': 'text/event-stream' } })));
    const onItem = vi.fn();

    await expect(analyzeEventsStream({ limit: 10 }, onItem)).rejects.toMatchObject({ code: 'AI_EVENTS_ANALYSIS_STREAM_INCOMPLETE' });
    expect(onItem).not.toHaveBeenCalled();
  });
});

describe('logout state contract', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
    localStorage.clear();
    setCSRFToken('');
  });

  it('clears local session state only after server confirmation', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    sessionStorage.setItem('cheesewaf-account', '{"username":"admin"}');
    localStorage.setItem('cheesewaf-token', 'legacy');
    setCSRFToken('csrf-token');
    vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { revoked: true } } });

    await expect(logout()).resolves.toEqual({ revoked: true });

    expect(sessionStorage.getItem('cheesewaf-authed')).toBeNull();
    expect(sessionStorage.getItem('cheesewaf-account')).toBeNull();
    expect(localStorage.getItem('cheesewaf-token')).toBeNull();
    expect(getCSRFToken()).toBe('');
  });

  it('retains local session state when logout cannot reach the server', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    sessionStorage.setItem('cheesewaf-account', '{"username":"admin"}');
    localStorage.setItem('cheesewaf-token', 'legacy');
    setCSRFToken('csrf-token');
    vi.spyOn(apiClient, 'post').mockRejectedValue(new Error('offline'));

    await expect(logout()).rejects.toThrow('offline');

    expect(sessionStorage.getItem('cheesewaf-authed')).toBe('1');
    expect(sessionStorage.getItem('cheesewaf-account')).toBe('{"username":"admin"}');
    expect(localStorage.getItem('cheesewaf-token')).toBe('legacy');
    expect(getCSRFToken()).toBe('csrf-token');
  });
});

describe('AI approval streaming and recovery', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it('flushes a final multibyte assistant event at EOF', async () => {
    const bytes = new TextEncoder().encode(`event: done\ndata: ${JSON.stringify({ answer: '中文と日本語', ai_used: true, log_ids: [], events: 0, blocked: 0, challenge: 0 })}`);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.slice(0, bytes.length - 1));
        controller.enqueue(bytes.slice(bytes.length - 1));
        controller.close();
      },
    }), { status: 200, headers: { 'Content-Type': 'text/event-stream' } })));

    await expect(askAIAssistantStream('test')).resolves.toMatchObject({ answer: '中文と日本語' });
  });

  it('continues an assistant stream after a malformed SSE frame', async () => {
    const reply = { answer: 'complete', ai_used: true, log_ids: [], events: 0, blocked: 0, challenge: 0 };
    const bytes = new TextEncoder().encode(`event: trace\ndata: {broken\n\nevent: done\ndata: ${JSON.stringify(reply)}\n\n`);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }), { status: 200, headers: { 'Content-Type': 'text/event-stream' } })));

    await expect(askAIAssistantStream('test')).resolves.toEqual(reply);
  });

  it('lists and gets recoverable approvals from the server', async () => {
    const get = vi.spyOn(apiClient, 'get')
      .mockResolvedValueOnce({ data: { data: [{ id: 'approval-1', status: 'pending' }] } })
      .mockResolvedValueOnce({ data: { data: { id: 'approval-1', status: 'executing' } } });

    await expect(fetchAIApprovals()).resolves.toMatchObject({ total: 1 });
    await expect(fetchAIApproval('approval-1')).resolves.toMatchObject({ status: 'executing' });
    expect(get).toHaveBeenNthCalledWith(1, '/ai/tools/approvals', { params: undefined });
    expect(get).toHaveBeenNthCalledWith(2, '/ai/tools/approvals/approval-1');
  });

  it('reconciles an interrupted continuation against the server state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(new ReadableStream({
      start(controller) {
        controller.error(new Error('connection lost'));
      },
    }), { status: 200, headers: { 'Content-Type': 'text/event-stream' } })));
    vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: { id: 'approval-1', status: 'executing' } } });

    await expect(continueAIApprovalStream('approval-1', 'continue')).rejects.toMatchObject({
      code: 'AI_APPROVAL_CONTINUE_STATUS_RECONCILED',
      approval: { id: 'approval-1', status: 'executing' },
    });
  });
});

describe('notification API', () => {
  afterEach(() => vi.restoreAllMocks());

  it('uses server-backed user notification endpoints', async () => {
    const request = vi.spyOn(apiClient, 'request').mockResolvedValue({ data: { data: {} } });
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: { items: [], total: 0, filtered_total: 0, unread: 0, page: 2, limit: 8 } } });
    const patch = vi.spyOn(apiClient, 'patch').mockResolvedValue({ data: { data: { id: 'notice/1' } } });
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { updated: 2 } } });
    const remove = vi.spyOn(apiClient, 'delete').mockResolvedValue({ data: { data: { deleted: 2 } } });

    await fetchNotifications({ page: 2, limit: 8, filter: 'unread' });
    await updateNotification('notice/1', { read: true });
    await markAllNotificationsRead();
    await clearNotifications();

    expect(get).toHaveBeenCalledWith('/notifications', { params: { page: 2, limit: 8, filter: 'unread' } });
    expect(patch).toHaveBeenCalledWith('/notifications/notice%2F1', { read: true });
    expect(post).toHaveBeenCalledWith('/notifications/read-all', {});
    expect(remove).toHaveBeenCalledWith('/notifications');
    request.mockRestore();
  });
});

describe('refresh session', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it('refreshes the session on authenticated requests', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { user: { username: 'admin', role: 'admin' } } }, status: 200, statusText: 'OK', headers: {}, config: {} });
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    await apiClient.get('/sites', { adapter });

    expect(post).toHaveBeenCalledWith('/auth/refresh', {});
    expect(adapter).toHaveBeenCalledTimes(1);
  });

  it('does not refresh on login, refresh, logout, setup, or session paths', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    const post = vi.spyOn(apiClient, 'post');
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    await apiClient.get('/auth/session', { adapter });
    await apiClient.get('/auth/login', { adapter });
    await apiClient.get('/auth/logout', { adapter });
    await apiClient.get('/auth/refresh', { adapter });
    await apiClient.get('/setup', { adapter });
    await apiClient.get('/setup/status', { adapter });

    expect(post).not.toHaveBeenCalled();
  });

  it('refreshes on paths that merely contain an exempt path name', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { user: { id: 'admin-id', username: 'admin', role: 'admin' } } }, status: 200, statusText: 'OK', headers: {}, config: {} });
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    await apiClient.get('/setup-notes', { adapter });

    expect(post).toHaveBeenCalledWith('/auth/refresh', {});
    expect(adapter).toHaveBeenCalledTimes(1);
  });

  it('keeps the refresh single-flight across concurrent requests', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    let resolveRefresh: ((value: unknown) => void) | undefined;
    const post = vi.spyOn(apiClient, 'post').mockImplementation(() => new Promise((resolve) => {
      resolveRefresh = resolve;
    }));
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    const first = apiClient.get('/sites', { adapter });
    const second = apiClient.get('/logs', { adapter });
    await Promise.resolve();
    await Promise.resolve();

    expect(post).toHaveBeenCalledTimes(1);

    resolveRefresh?.({ data: { data: { user: { username: 'admin', role: 'admin' } } }, status: 200, statusText: 'OK', headers: {}, config: {} });
    await Promise.all([first, second]);

    expect(adapter).toHaveBeenCalledTimes(2);
  });

  it('swallows refresh failures so the original request still proceeds', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    vi.spyOn(apiClient, 'post').mockRejectedValue(new Error('refresh failed'));
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    await expect(apiClient.get('/sites', { adapter })).resolves.toBeTruthy();
    expect(adapter).toHaveBeenCalledTimes(1);
  });
});


describe('refresh session throttle', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it('skips refresh within 10 minutes after the last successful refresh', async () => {
    sessionStorage.setItem('cheesewaf-authed', '1');
    const post = vi.spyOn(apiClient, 'post').mockResolvedValue({ data: { data: { user: { username: 'admin', role: 'admin' } } }, status: 200, statusText: 'OK', headers: {}, config: {} });
    const adapter = vi.fn(async (config) => ({ data: { data: {} }, status: 200, statusText: 'OK', headers: {}, config }));

    await apiClient.get('/sites', { adapter });
    expect(post).toHaveBeenCalledTimes(1);

    post.mockClear();
    await apiClient.get('/logs', { adapter });
    expect(post).not.toHaveBeenCalled();
  });
});
