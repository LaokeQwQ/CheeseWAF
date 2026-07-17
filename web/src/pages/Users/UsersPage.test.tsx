import { describe, expect, it } from 'vitest';
import type { AuditEntry } from '../../types/api';
import { pageItems, withStableAuditKeys } from './UsersPage';

const baseEntry: AuditEntry = {
  timestamp: '2026-07-12T16:48:42.1244856Z',
  user: 'Cheese',
  role: 'admin',
  method: 'GET',
  path: '/api/logs',
  status: 200,
  remote_ip: '127.0.0.1',
  latency_ms: 12,
};

describe('withStableAuditKeys', () => {
  it('adds a stable occurrence number when audit records are completely identical', () => {
    const first = withStableAuditKeys([baseEntry, { ...baseEntry }]);
    const second = withStableAuditKeys([baseEntry, { ...baseEntry }]);

    expect(first.map((entry) => entry.auditKey)).toEqual(second.map((entry) => entry.auditKey));
    expect(new Set(first.map((entry) => entry.auditKey))).toHaveLength(2);
    expect(first[0].auditKey).toMatch(/#1$/);
    expect(first[1].auditKey).toMatch(/#2$/);
  });

  it('uses all business fields when distinguishing audit records', () => {
    const entries = withStableAuditKeys([
      baseEntry,
      { ...baseEntry, remote_ip: '127.0.0.2' },
      { ...baseEntry, latency_ms: 13 },
    ]);

    expect(new Set(entries.map((entry) => entry.auditKey))).toHaveLength(3);
    expect(entries.every((entry) => entry.auditKey.endsWith('#1'))).toBe(true);
  });
});

describe('pageItems', () => {
  it('keeps mobile user and audit collections on the requested page', () => {
    const items = Array.from({ length: 21 }, (_, index) => index + 1);
    expect(pageItems(items, 1, 8)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(pageItems(items, 2, 8)).toEqual([9, 10, 11, 12, 13, 14, 15, 16]);
    expect(pageItems(items, 3, 10)).toEqual([21]);
  });
});
