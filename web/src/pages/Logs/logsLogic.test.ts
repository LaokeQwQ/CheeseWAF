import { describe, expect, it } from 'vitest';
import type { LogEntry } from '../../types/api';
import { filterLogs, isAccessLog, isSecurityEvent, matchViewMode, paginate } from './logsLogic';

function entry(partial: Partial<LogEntry>): LogEntry {
  return {
    id: partial.id ?? '1',
    timestamp: partial.timestamp ?? '2026-07-17T12:00:00Z',
    client_ip: partial.client_ip ?? '1.2.3.4',
    method: partial.method ?? 'GET',
    uri: partial.uri ?? '/',
    action: partial.action ?? 'pass',
    category: partial.category ?? '',
    severity: partial.severity ?? '',
    status_code: partial.status_code ?? 200,
    message: partial.message ?? '',
    trace_id: partial.trace_id ?? '',
    country: partial.country ?? '',
    ...partial,
  } as LogEntry;
}

describe('logsLogic classification', () => {
  it('classifies security by category, action, and status', () => {
    expect(isSecurityEvent(entry({ category: 'sqli' }))).toBe(true);
    expect(isSecurityEvent(entry({ action: 'block' }))).toBe(true);
    expect(isSecurityEvent(entry({ action: 'challenge' }))).toBe(true);
    expect(isSecurityEvent(entry({ status_code: 403 }))).toBe(true);
    expect(isSecurityEvent(entry({ status_code: 429 }))).toBe(true);
    expect(isSecurityEvent(entry({ action: 'pass', status_code: 200 }))).toBe(false);
  });

  it('access mode excludes security events even if action is pass with category', () => {
    const security = entry({ category: 'xss', action: 'log' });
    const access = entry({ action: 'pass', status_code: 200 });
    expect(isAccessLog(security)).toBe(false);
    expect(isAccessLog(access)).toBe(true);
    expect(matchViewMode(security, 'security')).toBe(true);
    expect(matchViewMode(access, 'security')).toBe(false);
    expect(matchViewMode(access, 'access')).toBe(true);
    expect(matchViewMode(security, 'all')).toBe(true);
  });
});

describe('logsLogic filter and pagination', () => {
  const items = [
    entry({ id: 'a', action: 'block', category: 'sqli', uri: '/login', client_ip: '10.0.0.1', trace_id: 'tr-a' }),
    entry({ id: 'b', action: 'pass', uri: '/static/app.js', client_ip: '10.0.0.2', trace_id: 'tr-b' }),
    entry({ id: 'c', action: 'challenge', category: 'bot', uri: '/api', client_ip: '10.0.0.3', message: 'pow' }),
  ];

  it('filters by view mode and search needle across fields', () => {
    expect(filterLogs(items, { search: '', viewMode: 'security' }).map((e) => e.id)).toEqual(['a', 'c']);
    expect(filterLogs(items, { search: '', viewMode: 'access' }).map((e) => e.id)).toEqual(['b']);
    expect(filterLogs(items, { search: 'app.js', viewMode: 'all' }).map((e) => e.id)).toEqual(['b']);
    expect(filterLogs(items, { search: 'tr-a', viewMode: 'all' }).map((e) => e.id)).toEqual(['a']);
    expect(filterLogs(items, { search: '10.0.0.3', viewMode: 'security' }).map((e) => e.id)).toEqual(['c']);
  });

  it('paginates with stable bounds', () => {
    const rows = Array.from({ length: 20 }, (_, i) => entry({ id: String(i + 1) }));
    const page2 = paginate(rows, 2, 8);
    expect(page2.page).toBe(2);
    expect(page2.totalPages).toBe(3);
    expect(page2.pageItems).toHaveLength(8);
    expect(page2.pageStart).toBe(9);
    expect(page2.pageEnd).toBe(16);
    expect(paginate(rows, 99, 8).page).toBe(3);
    expect(paginate([], 1, 8)).toMatchObject({ page: 1, totalPages: 1, pageStart: 0, pageEnd: 0 });
  });
});
