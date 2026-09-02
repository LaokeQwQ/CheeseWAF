import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuditEntry, Notification } from '../types/api';
import { buildSearchResults, createRealtimeInvalidationScheduler, navigationForAccount, NotificationPanel, realtimeQueryKeys, shellCapabilities, withStableNotificationKeys } from './MainLayout';

vi.mock('react-i18next', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-i18next')>();
  return {
    ...actual,
    useTranslation: () => ({ t: (key: string) => key }),
  };
});

const noop = vi.fn();
afterEach(cleanup);

function renderPanel(overrides: Partial<React.ComponentProps<typeof NotificationPanel>> = {}) {
  const props: React.ComponentProps<typeof NotificationPanel> = {
    items: [],
    total: 0,
    filteredTotal: 0,
    unread: 0,
    page: 1,
    pageSize: 8,
    filter: 'all',
    loading: false,
    error: false,
    busy: false,
    onRetry: noop,
    onPageChange: noop,
    onFilterChange: noop,
    onOpen: noop,
    onMarkAllRead: noop,
    onClearAll: noop,
    onToggleRead: noop,
    onTogglePin: noop,
    ...overrides,
  };
  return render(<NotificationPanel {...props} />);
}

describe('NotificationPanel', () => {
  it('renders the persisted server notification fields and actions', () => {
    const item: Notification = {
      id: 'notice-1',
      type: 'warning',
      title: 'Certificate expires soon',
      message: 'example.com expires in seven days',
      target: '/sites/site-1',
      read: false,
      pinned: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    const onOpen = vi.fn();
    renderPanel({ items: [item], total: 1, filteredTotal: 1, unread: 1, onOpen });

    expect(screen.getByText(item.title)).toBeTruthy();
    expect(screen.getByText(item.message)).toBeTruthy();
    expect(document.querySelector('.notification-item-warning')).toBeTruthy();
    fireEvent.click(screen.getByText(item.title));
    expect(onOpen).toHaveBeenCalledWith(item);
  });

  it('supports read, unread, pin, mark-all and clear actions', () => {
    const item: Notification = { id: 'notice-1', type: 'info', title: 'Notice', message: 'Message', read: false, pinned: false, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const onToggleRead = vi.fn();
    const onTogglePin = vi.fn();
    const onMarkAllRead = vi.fn();
    const onClearAll = vi.fn();
    renderPanel({ items: [item], total: 1, filteredTotal: 1, unread: 1, onToggleRead, onTogglePin, onMarkAllRead, onClearAll });
    fireEvent.click(screen.getByRole('button', { name: 'shell.markRead' }));
    fireEvent.click(screen.getByRole('button', { name: 'shell.pinNotification' }));
    fireEvent.click(screen.getByText('shell.markAllRead'));
    fireEvent.click(screen.getByText('shell.clearAllNotifications'));
    expect(onToggleRead).toHaveBeenCalledWith(item);
    expect(onTogglePin).toHaveBeenCalledWith(item);
    expect(onMarkAllRead).toHaveBeenCalledTimes(1);
    expect(onClearAll).toHaveBeenCalledTimes(1);
  });

  it('creates stable unique keys for duplicate notification records', () => {
    const item: Notification = { id: 'duplicate', type: 'warning', title: 'Same', message: 'Same', read: false, pinned: false, created_at: '2026-07-13T00:00:00Z', updated_at: '2026-07-13T00:00:00Z' };
    const first = withStableNotificationKeys([item, { ...item }]);
    const second = withStableNotificationKeys([item, { ...item }]);
    expect(new Set(first.map((entry) => entry.notificationKey))).toHaveLength(2);
    expect(first.map((entry) => entry.notificationKey)).toEqual(second.map((entry) => entry.notificationKey));
    expect(first.map((entry) => entry.item)).toEqual([item, item]);
  });

  it('shows a retryable error instead of disguising a failed request as empty', () => {
    const onRetry = vi.fn();
    renderPanel({ error: true, onRetry });

    expect(screen.getByText('shell.notificationLoadFailed')).toBeTruthy();
    expect(screen.queryByText('shell.noNotifications')).toBeNull();
    fireEvent.click(screen.getByText('common.retry'));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

describe('buildSearchResults', () => {
  it('creates stable unique keys for duplicate audit search results', () => {
    const duplicateAudit: AuditEntry = {
      timestamp: '2026-07-13T10:00:00Z',
      user: 'Cheese',
      role: 'admin',
      method: 'GET',
      path: '/api/logs',
      status: 200,
      remote_ip: '127.0.0.1',
      latency_ms: 12,
    };
    const translate = (key: string) => key;

    const first = buildSearchResults('logs', [], [duplicateAudit, { ...duplicateAudit }], [], translate)
      .filter((item) => item.type === 'shell.searchAudit');
    const second = buildSearchResults('logs', [], [duplicateAudit, { ...duplicateAudit }], [], translate)
      .filter((item) => item.type === 'shell.searchAudit');

    expect(first).toHaveLength(2);
    expect(new Set(first.map((item) => item.key)).size).toBe(2);
    expect(first.map((item) => item.key)).toEqual(second.map((item) => item.key));
    expect(first[0].key).not.toMatch(/^\d+$/);
    expect(first[1].key).toContain(':duplicate:1');
  });
});

describe('shell authorization and realtime invalidation', () => {
  it('shows only navigation backed by the account scopes and uses router-aligned system scopes', () => {
    const account = { subject: 'operator-1', username: 'operator', role: 'operator', scopes: ['read:logs', 'read:system'] };
    const keys = navigationForAccount(account).flatMap((group) => group.items.map((item) => item.key));

    expect(keys).toEqual(expect.arrayContaining(['/attack-map', '/logs', '/ssl', '/block-pages', '/updates', '/system']));
    expect(keys).not.toContain('/users');
    expect(keys).not.toContain('/monitor');
  });

  it('gates each shell query and realtime subscription independently', () => {
    const account = { subject: 'auditor-1', username: 'auditor', role: 'custom', scopes: ['read:audit', 'read:users'] };

    expect(shellCapabilities(account)).toEqual({
      version: false,
      recentLogs: false,
      audit: true,
      users: true,
      notifications: false,
      realtime: false,
    });
  });

  it('maps realtime messages to the queries that consume each payload type', () => {
    expect(realtimeQueryKeys('log')).toEqual(expect.arrayContaining([
      ['recent-security-logs'],
      ['dashboard-live-logs'],
      ['attack-map-logs'],
    ]));
    expect(realtimeQueryKeys('alert')).toEqual([['notifications']]);
    expect(realtimeQueryKeys('stats')).toContainEqual(['monitor-summary']);
    expect(realtimeQueryKeys('unknown')).toEqual([]);
  });

  it('coalesces realtime invalidations for one second and flushes each query once', () => {
    const scheduled: Array<() => void> = [];
    const schedule = vi.fn((callback: () => void) => {
      scheduled.push(callback);
      return scheduled.length;
    });
    const invalidate = vi.fn();
    const scheduler = createRealtimeInvalidationScheduler(invalidate, schedule, vi.fn());

    scheduler.enqueue([['logs'], ['notifications']]);
    scheduler.enqueue([['logs']]);

    expect(schedule).toHaveBeenCalledTimes(1);
    expect(schedule).toHaveBeenCalledWith(expect.any(Function), 1_000);
    expect(invalidate).not.toHaveBeenCalled();

    scheduled[0]?.();
    expect(invalidate).toHaveBeenCalledTimes(2);
    expect(invalidate).toHaveBeenCalledWith(['logs']);
    expect(invalidate).toHaveBeenCalledWith(['notifications']);
  });
});
