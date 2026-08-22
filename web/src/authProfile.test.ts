import { afterEach, describe, expect, it } from 'vitest';
import { cacheAccount, currentAccount, filterNavigation, hasScope } from './authProfile';

describe('account permissions', () => {
  afterEach(() => sessionStorage.clear());

  it('normalizes and reads the authenticated account cache', () => {
    cacheAccount({ id: ' account-1 ', username: ' admin ', role: 'custom', scopes: [' read:logs ', '', 'read:logs', 'read:users'] });

    expect(currentAccount()).toEqual({
      subject: 'account-1',
      username: 'admin',
      role: 'custom',
      scopes: ['read:logs', 'read:users'],
    });
  });

  it('matches exact, wildcard, administrator, and readonly permissions', () => {
    const profile = { subject: 'operator-1', username: 'operator', role: 'operator', scopes: ['read:logs', 'read:monitor'] };
    expect(hasScope(profile, 'read:logs')).toBe(true);
    expect(hasScope(profile, 'read:users')).toBe(false);
    expect(hasScope({ ...profile, scopes: ['read:*'] }, 'read:users')).toBe(true);
    expect(hasScope({ ...profile, role: 'readonly', scopes: [] }, 'read:audit')).toBe(true);
    expect(hasScope({ ...profile, role: 'admin', scopes: [] }, 'write:system')).toBe(true);
    expect(hasScope(profile, '')).toBe(false);
  });

  it('filters navigation items using the cached role scopes', () => {
    const profile = { subject: 'operator-1', username: 'operator', role: 'operator', scopes: ['read:logs', 'read:monitor'] };
    const groups = [{ items: [{ key: '/logs', requiredScopes: ['read:logs'] }, { key: '/users', requiredScopes: ['read:users'] }] }];
    expect(filterNavigation(groups, profile).flatMap((group) => group.items).map((item) => item.key)).toContain('/logs');
    expect(filterNavigation(groups, profile).flatMap((group) => group.items).map((item) => item.key)).not.toContain('/users');
  });
});
