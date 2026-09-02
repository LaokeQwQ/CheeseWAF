import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const css = readFileSync('src/styles/shadcn.css', 'utf8');

describe('shadcn theme contrast', () => {
  it('uses 3:1-or-higher input borders in both themes', () => {
    expect(css).toContain('--border: oklch(0.65 0 0);');
    expect(css).toContain('--input: oklch(0.65 0 0);');
    expect(css).toContain('--border: oklch(0.60 0 0);');
    expect(css).toContain('--input: oklch(0.60 0 0);');
  });
});
