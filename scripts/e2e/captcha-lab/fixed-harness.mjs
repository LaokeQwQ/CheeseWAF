import path from 'node:path';
import { disposeManagedProcess, spawnManagedProcess } from './process-lifecycle.mjs';

export async function runFixedHarness({ cwd = process.cwd(), timeoutMs = 60_000 } = {}) {
  const managedProcess = spawnManagedProcess('go', ['test', './internal/captcha', '-run', '^TestBehaviorFixedHarness', '-count=1', '-v'], { cwd: path.resolve(cwd), env: harnessEnvironment(process.env), stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const child = managedProcess.child;
  const stdout = [];
  child.stdout.on('data', (chunk) => stdout.push(chunk));
  child.stderr.resume();
  try {
    const result = await managedProcess.wait(timeoutMs, 'fixed CAPTCHA harness timed out');
    if (result.code !== 0) throw new Error(`fixed CAPTCHA harness exited with ${result.code}`);
    const report = parseReport(Buffer.concat(stdout).toString('utf8'));
    assertReport(report);
    return report;
  } finally {
    await disposeManagedProcess(managedProcess, { failureMessage: 'fixed CAPTCHA harness cleanup failed' });
  }
}

export function assertReport(report) {
  const expected = new Set(['curve_draw', 'curve_slider_v1', 'curve_slider_v2', 'curve_slider_v3', 'shape_slider', 'rotate', 'restore_slider', 'angle', 'scratch', 'text_click', 'icon_click']);
  const allowedFields = ['correct_accepted', 'correct_replay_rejected', 'type', 'wrong_rejected', 'wrong_replay_rejected'];
  if (!Array.isArray(report) || report.length !== expected.size) throw new Error('fixed CAPTCHA harness returned an incomplete scenario set');
  for (const item of report) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('fixed CAPTCHA harness returned an invalid report item');
    const fields = Object.keys(item).sort();
    if (fields.length !== allowedFields.length || fields.some((field, index) => field !== allowedFields[index])) {
      throw new Error('fixed CAPTCHA harness returned fields outside the report whitelist');
    }
    if (!expected.delete(item.type)) throw new Error('fixed CAPTCHA harness returned an unexpected scenario');
    for (const field of ['wrong_rejected', 'wrong_replay_rejected', 'correct_accepted', 'correct_replay_rejected']) if (item[field] !== true) throw new Error(`fixed CAPTCHA harness failed ${item.type}/${field}`);
  }
  if (expected.size !== 0) throw new Error('fixed CAPTCHA harness returned an incomplete scenario set');
}

export function parseReport(output) {
  const line = output.split(/\r?\n/).find((item) => item.startsWith('CHEESEWAF_CAPTCHA_HARNESS '));
  if (!line) throw new Error('fixed CAPTCHA harness did not emit a report');
  return JSON.parse(line.slice('CHEESEWAF_CAPTCHA_HARNESS '.length));
}

function harnessEnvironment(env) { return { ...Object.fromEntries(Object.entries(env).filter(([key]) => !/TOKEN|SECRET|PASSWORD|KEY/i.test(key))), CHEESEWAF_CAPTCHA_HARNESS_REPORT: '1' }; }
