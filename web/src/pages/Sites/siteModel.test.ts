import { describe, expect, it } from 'vitest';
import { normalizeParanoiaLevel, normalizeSite } from './siteModel';

describe('normalizeParanoiaLevel', () => {
  it('keeps 0-5 and maps everything else to the default', () => {
    expect(normalizeParanoiaLevel(0)).toBe(0);
    expect(normalizeParanoiaLevel(1)).toBe(1);
    expect(normalizeParanoiaLevel(5)).toBe(5);
    expect(normalizeParanoiaLevel(9)).toBe(3);
    expect(normalizeParanoiaLevel('3')).toBe(3);
    expect(normalizeParanoiaLevel(undefined)).toBe(3);
  });
});

describe('normalizeSite', () => {
  it('defaults a missing paranoia level to 3', () => {
    expect(normalizeSite({ id: 's1' }).paranoia_level).toBe(3);
  });

  it('defaults promote-to-5 seconds to 0 and auto-agree off', () => {
    const site = normalizeSite({ id: 's1' });
    expect(site.advanced.semantic_policy.promote_seconds).toBe(0);
    expect(site.advanced.semantic_policy.auto_agree).toBe(false);
    expect(site.advanced.semantic_policy.fingerprint_deny).toEqual([]);
  });
});
