import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('./npm-audit-gate.mjs', import.meta.url), 'utf8');

test('audits development dependencies without package-wide exemptions', () => {
  assert.doesNotMatch(source, /--omit=dev/);
  assert.doesNotMatch(source, /ALLOWLISTED_PACKAGES/);
});
