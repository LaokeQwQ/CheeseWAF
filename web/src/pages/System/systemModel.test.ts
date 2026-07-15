import { describe, expect, it } from 'vitest';
import {
  durationToNanoseconds,
  durationToUnitParts,
  durationUnitToNanoseconds,
  fallbackSystem,
  normalizeSystem,
} from './systemModel';

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
