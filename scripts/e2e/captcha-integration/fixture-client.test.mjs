import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { startIntegrationFixture } from './fixture-client.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const processFixture = fileURLToPath(new URL('../captcha-lab/process-fixture.mjs', import.meta.url));
const lifecycleTimeoutMs = 500;

test('stuck compilation terminates its process tree before removing the binary directory', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t, { compileMode: 'compile-hang' });
  await assert.rejects(
    startIntegrationFixture({ projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: lifecycle.processFactory }),
    /compilation timed out/,
  );
  await assertProcessTreeStopped(lifecycle.pidFile);
  assert.equal(await exists(path.dirname(lifecycle.binaryPath())), false);
});

test('stuck fixture startup terminates its process tree before removing the binary directory', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t, { runMode: 'runtime-hang' });
  await assert.rejects(
    startIntegrationFixture({ projectRoot, timeoutMs: lifecycleTimeoutMs, processFactory: lifecycle.processFactory }),
    /startup timed out/,
  );
  await assertProcessTreeStopped(lifecycle.pidFile);
  assert.equal(await exists(path.dirname(lifecycle.binaryPath())), false);
});

test('request timeout terminates the fixture process tree and removes the binary directory', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t, { runMode: 'integration-request-hang' });
  const fixture = await startIntegrationFixture({
    projectRoot,
    timeoutMs: lifecycleTimeoutMs,
    processFactory: lifecycle.processFactory,
  });
  await assert.rejects(fixture.loginPlan({ variant: 'correct' }), /request timed out/);
  await assert.doesNotReject(fixture.close());
  await assertProcessTreeStopped(lifecycle.pidFile);
  assert.equal(await exists(path.dirname(lifecycle.binaryPath())), false);
});

test('shutdown timeout terminates the process tree before cleanup and repeated close shares the rejection', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t, { runMode: 'integration-request-hang' });
  let cleanupObserved = false;
  const fixture = await startIntegrationFixture({
    projectRoot,
    timeoutMs: lifecycleTimeoutMs,
    processFactory: lifecycle.processFactory,
    removeTemporary: async (directory, options) => {
      const pids = await readRecordedPids(lifecycle.pidFile);
      assert.deepEqual(pids.map(processIsRunning), pids.map(() => false), 'temporary cleanup ran before process-tree close');
      cleanupObserved = true;
      await rm(directory, options);
    },
  });
  const firstClose = fixture.close();
  assert.equal(fixture.close(), firstClose);
  await assert.rejects(firstClose, /shutdown failed/);
  assert.equal(fixture.close(), firstClose);
  await assert.rejects(fixture.close(), /shutdown failed/);
  assert.equal(cleanupObserved, true);
  await assertProcessTreeStopped(lifecycle.pidFile);
  assert.equal(await exists(path.dirname(lifecycle.binaryPath())), false);
});

test('normal and repeated close share one promise and remove the temporary binary', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t);
  const fixture = await startIntegrationFixture({
    projectRoot,
    timeoutMs: lifecycleTimeoutMs,
    processFactory: lifecycle.processFactory,
  });
  const binary = lifecycle.binaryPath();
  assert.equal(await exists(binary), true);
  const firstClose = fixture.close();
  assert.equal(fixture.close(), firstClose);
  await firstClose;
  assert.equal(fixture.close(), firstClose);
  await assert.doesNotReject(fixture.close());
  assert.equal(await exists(binary), false);
  assert.equal(await exists(path.dirname(binary)), false);
});

test('temporary cleanup failure is fixed, sanitized, and shared by repeated close', { timeout: 15_000 }, async (t) => {
  const lifecycle = await lifecycleFixture(t);
  const privateDetail = 'PRIVATE_FIXTURE_PATH_WITH_CONTROL_ANSWER';
  const fixture = await startIntegrationFixture({
    projectRoot,
    timeoutMs: lifecycleTimeoutMs,
    processFactory: lifecycle.processFactory,
    removeTemporary: async () => { throw new Error(`${lifecycle.binaryPath()} ${privateDetail}`); },
  });
  const firstClose = fixture.close();
  assert.equal(fixture.close(), firstClose);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assert.equal(fixture.close(), firstClose);
    await assert.rejects(firstClose, (error) => {
      assert.equal(error.message, 'CAPTCHA integration fixture temporary cleanup failed');
      assert.equal(error.message.includes(privateDetail), false);
      assert.equal(error.message.includes(lifecycle.binaryPath()), false);
      return true;
    });
  }
});

async function lifecycleFixture(t, { compileMode = 'compile-ok', runMode = 'integration-normal' } = {}) {
  const testDirectory = await mkdtemp(path.join(tmpdir(), 'cheesewaf-integration-process-test-'));
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
        return commandFor(runMode, ...(runMode === 'integration-normal' ? [] : [pidFile]));
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
