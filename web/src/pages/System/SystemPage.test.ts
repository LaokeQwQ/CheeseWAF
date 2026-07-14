import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const pageSource = readFileSync(join(process.cwd(), 'src/pages/System/SystemPage.tsx'), 'utf8');
const stylesSource = readFileSync(join(process.cwd(), 'src/pages/System/SystemPage.module.css'), 'utf8');

describe('System page mobile layout', () => {
  it('keeps all four primary tabs visible', () => {
    expect(pageSource).toContain('SystemPage.module.css');
    expect(stylesSource).toContain('@media (max-width: 520px)');
    expect(stylesSource).toContain('flex: 1 1 25%');
    expect(stylesSource).toContain('font-size: 12px');
  });
});
