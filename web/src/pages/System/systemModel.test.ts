import { describe, expect, it } from 'vitest';
import {
  durationToNanoseconds,
  durationToUnitParts,
  durationUnitToNanoseconds,
  fallbackSystem,
  normalizeSystem,
} from './systemModel';

describe('system login branding model', () => {
  it('round-trips copyright and show_product_version through normalizeSystem', () => {
    const normalized = normalizeSystem({
      ...fallbackSystem,
      console: {
        ...fallbackSystem.console,
        login: {
          ...fallbackSystem.console.login,
          copyright: 'Copyright © Custom Ops',
          show_product_version: false,
        },
      },
    });

    expect(normalized.console.login.copyright).toBe('Copyright © Custom Ops');
    expect(normalized.console.login.show_product_version).toBe(false);
  });

  it('falls back to default branding when login branding fields are omitted', () => {
    const normalized = normalizeSystem({
      ...fallbackSystem,
      console: {
        ...fallbackSystem.console,
        login: {
          captcha: fallbackSystem.console.login.captcha,
          security_entry: fallbackSystem.console.login.security_entry,
          background: fallbackSystem.console.login.background,
        } as typeof fallbackSystem.console.login,
      },
    });

    expect(normalized.console.login.copyright).toBe(fallbackSystem.console.login.copyright);
    expect(normalized.console.login.show_product_version).toBe(true);
  });
});

describe('system time synchronization model', () => {
  it('does not invent time synchronization settings for legacy system responses', () => {
    const normalized = normalizeSystem({
      ...fallbackSystem,
      time_sync: undefined,
    } as unknown as Partial<typeof fallbackSystem>);

    expect(normalized.time_sync).toBeUndefined();
  });

  it('converts nanosecond durations to readable exact units', () => {
    expect(durationToUnitParts(durationToNanoseconds('24h'), ['m', 'h', 'd'])).toEqual({ amount: 1, unit: 'd' });
    expect(durationToUnitParts(durationToNanoseconds('30m'), ['m', 'h'])).toEqual({ amount: 30, unit: 'm' });
    expect(durationToUnitParts(durationToNanoseconds('250ms'), ['ms', 's'])).toEqual({ amount: 250, unit: 'ms' });
    expect(durationUnitToNanoseconds('m')).toBe(60 * 1_000_000_000);
  });
});
