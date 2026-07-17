import assert from 'node:assert/strict';
import test from 'node:test';
import { rangeQuantizationTolerance } from './range.mjs';

test('allows only the half-pixel quantization error of a range control', () => {
  assert.equal(rangeQuantizationTolerance(10_000, 300), 17);
  assert.equal(rangeQuantizationTolerance(10_000, 500), 10);
  assert.equal(rangeQuantizationTolerance(100, 400), 1);
});
