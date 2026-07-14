import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { publicIssuePayload, startPrivateHarness } from './private-harness.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const processFixture = fileURLToPath(new URL('./process-fixture.mjs', import.meta.url));
const scenarios = ['curve_draw', 'curve_slider_v1', 'curve_slider_v2', 'curve_slider_v3', 'shape_slider', 'rotate', 'restore_slider', 'angle', 'scratch', 'text_click', 'icon_click'];
const lifecycleTimeoutMs = 500;

test('temporary cleanup failures are explicit and sanitized', async () => {
  const { removeTemporaryDirectory } = await import('./process-lifecycle.mjs');
  const privateDetail = 'PRIVATE_PATH_WITH_CONTROL_ANSWER';
  await assert.rejects(
    removeTemporaryDirectory(privateDetail, {
      failureMessage: 'private CAPTCHA fixture temporary cleanup failed',
      remove: async () => { throw new Error(privateDetail); },
    }),
    (error) => {
      assert.equal(error.message, 'private CAPTCHA fixture temporary cleanup failed');
      assert.equal(error.message.includes(privateDetail), false);
      return true;
    },
  );
});

test('stuck compilation terminates its process tree before removing the binary directory', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { compileMode: 'compile-hang' });
  await assert.rejects(
    startPrivateHarness({ cwd: projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: fixture.processFactory }),
    /compilation timed out/,
  );
  await assertProcessTreeStopped(fixture.pidFile);
  assert.equal(await exists(path.dirname(fixture.binaryPath())), false);
});

test('stuck fixture startup terminates its process tree before removing the binary directory', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { runMode: 'runtime-hang' });
  await assert.rejects(
    startPrivateHarness({ cwd: projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: fixture.processFactory }),
    /startup timed out/,
  );
  await assertProcessTreeStopped(fixture.pidFile);
  assert.equal(await exists(path.dirname(fixture.binaryPath())), false);
});

test('request timeout terminates the fixture process tree and removes the binary directory', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { runMode: 'private-request-hang' });
  const harness = await startPrivateHarness({ cwd: projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: fixture.processFactory });
  await assert.rejects(harness.issue('curve_draw'), /request timed out/);
  await assert.doesNotReject(harness.close());
  await assertProcessTreeStopped(fixture.pidFile);
  assert.equal(await exists(path.dirname(fixture.binaryPath())), false);
});

test('shutdown timeout terminates the fixture process tree and repeated close reports the same failure', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { runMode: 'private-request-hang' });
  const harness = await startPrivateHarness({ cwd: projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: fixture.processFactory });
  await assert.rejects(harness.close(), /process failed/);
  await assert.rejects(harness.close(), /process failed/);
  await assertProcessTreeStopped(fixture.pidFile);
  assert.equal(await exists(path.dirname(fixture.binaryPath())), false);
});

test('normal and repeated close wait for exit and remove the temporary binary', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { runMode: 'private-normal' });
  const harness = await startPrivateHarness({ cwd: projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: fixture.processFactory });
  const binary = fixture.binaryPath();
  assert.equal(await exists(binary), true);
  const firstClose = harness.close();
  assert.equal(harness.close(), firstClose);
  await firstClose;
  await assert.doesNotReject(harness.close());
  assert.equal(await exists(binary), false);
  assert.equal(await exists(path.dirname(binary)), false);
});

test('harness cleanup failure is explicit, repeatable, and sanitized', { timeout: 15_000 }, async (t) => {
  const fixture = await lifecycleFixture(t, { runMode: 'private-normal' });
  const privateDetail = 'CORRECT_ACTION_ANSWER';
  const harness = await startPrivateHarness({
    cwd: projectRoot,
    timeoutMs: lifecycleTimeoutMs,
    processFactory: fixture.processFactory,
    removeTemporary: async () => { throw new Error(`${fixture.binaryPath()} ${privateDetail}`); },
  });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(harness.close(), (error) => {
      assert.equal(error.message, 'private CAPTCHA fixture temporary cleanup failed');
      assert.equal(error.message.includes(privateDetail), false);
      assert.equal(error.message.includes(fixture.binaryPath()), false);
      return true;
    });
  }
});

test('private browser fixture keeps every action plan outside the public payload', { timeout: 60_000 }, async () => {
  const harness = await startPrivateHarness({ cwd: projectRoot });
  try {
    for (const scenario of scenarios) {
      const challenge = await harness.issue(scenario);
      const payload = publicIssuePayload(challenge);
      assertCondition(Object.keys(payload).length === 1 && payload.data === challenge, `${scenario}: public envelope mismatch`);
      assertCondition(!hasControlKey(payload), `${scenario}: public envelope contains control data`);
      for (const variant of ['wrong', 'correct']) {
        const operation = harness.actionFor(challenge, variant);
        assertCondition(['range', 'surface', 'click'].includes(operation.interaction), `${scenario}: operation kind mismatch`);
        assertCondition(operation.action && typeof operation.action === 'object', `${scenario}: operation missing`);
      }
    }
  } finally {
    await harness.close();
  }
});

function hasControlKey(value) {
  const controlKeys = new Set(['interaction', 'correct', 'wrong', 'path', 'at', 'value', 'handle']);
  if (Array.isArray(value)) return value.some(hasControlKey);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => controlKeys.has(key) || hasControlKey(child));
}

function assertCondition(condition, message) {
  if (!condition) throw new Error(message);
}

async function lifecycleFixture(t, { compileMode = 'compile-ok', runMode = 'private-normal' } = {}) {
  const testDirectory = await mkdtemp(path.join(tmpdir(), 'cheesewaf-process-test-'));
  const pidFile = path.join(testDirectory, 'pids.json');
  let binary;
  t.after(async () => {
    await stopRecordedProcessTree(pidFile);
    await rm(testDirectory, { recursive: true, force: true });
    if (binary) await rm(path.dirname(binary), { recursive: true, force: true });
  });
  return {
    pidFile,
    binaryPath: () => {
      assert.ok(binary, 'fixture compiler did not receive a binary path');
      return binary;
    },
    processFactory: {
      compile(output) {
        binary = output;
        return commandFor(compileMode, compileMode === 'compile-ok' ? output : pidFile);
      },
      run() {
        return commandFor(runMode, ...(runMode === 'private-normal' ? [] : [pidFile]));
      },
    },
  };
}

function commandFor(mode, ...args) {
  return { command: process.execPath, args: [processFixture, mode, ...args] };
}

async function assertProcessTreeStopped(pidFile) {
  const pids = await readRecordedPids(pidFile);
  const deadline = Date.now() + 5_000;
  while (pids.some(processIsRunning) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.deepEqual(pids.map(processIsRunning), pids.map(() => false), 'fixture process tree remained alive');
}

async function stopRecordedProcessTree(pidFile) {
  const pids = await readRecordedPids(pidFile, false);
  if (!pids.some(processIsRunning)) return;
  if (process.platform === 'win32') {
    await runTaskkill(pids[0]);
  } else {
    try {
      process.kill(-pids[0], 'SIGKILL');
    } catch {
      for (const pid of pids) {
        try { process.kill(pid, 'SIGKILL'); } catch {}
      }
    }
  }
}

async function readRecordedPids(pidFile, required = true) {
  const deadline = Date.now() + 2_000;
  do {
    try {
      const pids = JSON.parse(await readFile(pidFile, 'utf8'));
      if (Array.isArray(pids) && pids.every(Number.isInteger)) return pids;
    } catch {}
    if (!required) return [];
    await new Promise((resolve) => setTimeout(resolve, 25));
  } while (Date.now() < deadline);
  if (required) assert.fail('fixture did not record its process tree');
  return [];
}

function processIsRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === 'EPERM';
  }
}

function runTaskkill(pid) {
  return new Promise((resolve) => {
    const child = spawn('taskkill.exe', ['/pid', String(pid), '/t', '/f'], {
      stdio: ['ignore', 'ignore', 'ignore'],
      windowsHide: true,
    });
    child.once('error', resolve);
    child.once('close', resolve);
  });
}

async function exists(target) {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}
