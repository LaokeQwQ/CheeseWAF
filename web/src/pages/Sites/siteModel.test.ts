import { describe, expect, it } from 'vitest';
import { normalizeParanoiaLevel, normalizeSite } from './siteModel';

describe('normalizeParanoiaLevel', () => {
  it('keeps 1-4 and maps everything else to the default', () => {
    expect(normalizeParanoiaLevel(1)).toBe(1);
    expect(normalizeParanoiaLevel(4)).toBe(4);
    expect(normalizeParanoiaLevel(0)).toBe(2);
    expect(normalizeParanoiaLevel(9)).toBe(2);
    expect(normalizeParanoiaLevel('3')).toBe(3);
    expect(normalizeParanoiaLevel(undefined)).toBe(2);
  });
});

describe('normalizeSite', () => {
  it('defaults a missing paranoia level to 2', () => {
    expect(normalizeSite({ id: 's1' }).paranoia_level).toBe(2);
  });
});
