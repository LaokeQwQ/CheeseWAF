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
  handleUnauthorizedAuthFailure,
  fetchHealth,
  fetchTimeSyncStatus,
  issueCaptchaLabChallenge,
  reselectTimeSync,
  syncTimeNow,
  verifyCaptchaLabChallenge,
  clearNotifications,
  fetchNotifications,
  markAllNotificationsRead,
  resetAuthRedirectStateForTest,
  sanitizeInternalReturnPath,
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
    resetAuthRedirectStateForTest();
    setAuthRedirectLocationForTest({ pathname: '/ai', assign });
    assign.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetAuthRedirectStateForTest();
    localStorage.clear();
  });

  it('clears the token, React Query cache, and schedules only one login redirect', () => {
    localStorage.setItem('cheesewaf-token', 'token');
    queryClient.setQueryData(['sites'], [{ id: 'site-1' }]);
    expect(queryClient.getQueryData(['sites'])).toEqual([{ id: 'site-1' }]);

    handleUnauthorizedAuthFailure({ pathname: '/ai', search: '?tab=models', hash: '#reasoning', assign });
    handleUnauthorizedAuthFailure({ pathname: '/updates', assign });

    expect(localStorage.getItem('cheesewaf-token')).toBeNull();
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
