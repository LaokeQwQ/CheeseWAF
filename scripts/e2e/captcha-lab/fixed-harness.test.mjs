import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertReport, runFixedHarness } from './fixed-harness.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const types = ['curve_draw', 'curve_slider', 'shape_slider', 'rotate', 'restore_slider', 'angle', 'scratch', 'text_click', 'icon_click'];

test('fixed harness runs every registry and report audit test', { timeout: 60_000 }, async () => {
  const report = await runFixedHarness({ cwd: projectRoot });
  assert.equal(report.length, types.length);
});

test('fixed harness accepts exactly five report fields', () => {
  assert.doesNotThrow(() => assertReport(report()));
  const extra = report();
  extra[0].extra = true;
  assert.throws(() => assertReport(extra), /whitelist/);
  const missing = report();
  delete missing[0].correct_accepted;
  assert.throws(() => assertReport(missing), /whitelist/);
});

function report() {
  return types.map((type) => ({
    type,
    wrong_rejected: true,
    wrong_replay_rejected: true,
    correct_accepted: true,
    correct_replay_rejected: true,
  }));
}
