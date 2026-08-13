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
});
