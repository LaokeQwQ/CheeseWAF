import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import {
  disposeManagedProcess,
  removeTemporaryDirectory,
  spawnManagedProcess,
  withTimeout,
} from '../captcha-lab/process-lifecycle.mjs';

const PREFIX = 'CHEESEWAF_CAPTCHA_INTEGRATION ';
export function integrationFixtureBuildCommand(binary) {
  return {
    command: 'go',
    args: ['build', '-tags', 'captchae2e', '-o', binary, './scripts/e2e/captcha-integration/fixture'],
  };
}

const defaultProcessFactory = {
  compile: integrationFixtureBuildCommand,
  run: (binary) => ({ command: binary, args: [] }),
};

export async function startIntegrationFixture({
  projectRoot,
  timeoutMs = 90_000,
  processFactory = defaultProcessFactory,
  removeTemporary,
} = {}) {
  if (!projectRoot) throw new Error('CAPTCHA integration project root is required');
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'cheesewaf-captcha-integration-bin-'));
  const binary = path.join(temporaryDirectory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
  const environment = sanitizedEnvironment(process.env);
  const cleanup = onceAsync(() => removeTemporaryDirectory(temporaryDirectory, {
    remove: removeTemporary,
    failureMessage: 'CAPTCHA integration fixture temporary cleanup failed',
  }));
  let compiler;
  try {
    const command = processCommand(processFactory, 'compile', binary);
    compiler = spawnManagedProcess(command.command, command.args, {
      cwd: projectRoot,
      env: environment,
      stdio: ['ignore', 'ignore', 'ignore'],
      windowsHide: true,
    });
    const result = await compiler.wait(timeoutMs, 'CAPTCHA integration fixture compilation timed out');
    if (result.code !== 0) throw new Error('CAPTCHA integration fixture compilation failed');
    await disposeManagedProcess(compiler, {
      timeoutMs,
      failureMessage: 'CAPTCHA integration fixture compiler cleanup failed',
    });
  } catch (error) {
    return failStart(error, compiler, cleanup, timeoutMs, 'CAPTCHA integration fixture compiler cleanup failed');
  }

  let fixtureProcess;
  let client;
  try {
    const command = processCommand(processFactory, 'run', binary);
    fixtureProcess = spawnManagedProcess(command.command, command.args, {
      cwd: projectRoot,
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    fixtureProcess.child.stderr.resume();
    client = new FixtureClient(fixtureProcess, timeoutMs, cleanup);
    const fixture = await client.ready();
    if (fixtureProcess.closed) throw new Error('CAPTCHA integration fixture exited unexpectedly');
    return fixture;
  } catch (error) {
    if (client) {
      await client.disposeAfterFailure();
      throw error;
    }
    return failStart(error, fixtureProcess, cleanup, timeoutMs, 'CAPTCHA integration fixture process cleanup failed');
  }
}

class FixtureClient {
  #process;
  #child;
  #timeoutMs;
  #cleanup;
  #nextID = 0;
  #pending = new Map();
  #readyPromise;
  #readyResolve;
  #readyReject;
  #closed = false;
  #closePromise;
  #disposePromise;
  #backgroundDisposePromise;
  #unexpectedExit = false;

  constructor(managedProcess, timeoutMs, cleanup) {
    this.#process = managedProcess;
    this.#child = managedProcess.child;
    this.#timeoutMs = timeoutMs;
    this.#cleanup = cleanup;
    this.#readyPromise = new Promise((resolve, reject) => {
      this.#readyResolve = resolve;
      this.#readyReject = reject;
    });
    this.#child.once('error', () => this.#fatal('CAPTCHA integration fixture failed to start'));
    this.#child.once('close', () => this.#fatal('CAPTCHA integration fixture exited unexpectedly'));
    const lines = createInterface({ input: this.#child.stdout, crlfDelay: Infinity });
    lines.on('line', (line) => this.#accept(line));
  }

  async ready() {
    const metadata = await withTimeout(this.#readyPromise, this.#timeoutMs, 'CAPTCHA integration fixture startup timed out');
    return {
      ...metadata,
      loginPlan: (fields) => this.#call('login_plan', fields),
      loginDiagnose: (fields) => this.#call('login_diagnose', fields),
      wafPlan: (fields) => this.#call('waf_plan', fields),
      wafDiagnose: (fields) => this.#call('waf_diagnose', fields),
      labPlan: async (fields) => validateLabPlan((await this.#call('lab_plan', fields)).plan),
      close: () => this.close(),
    };
  }

  close() {
    if (!this.#closePromise) this.#closePromise = this.#closeOnce();
    return this.#closePromise;
  }

  async disposeAfterFailure() {
    await this.#dispose();
  }

  async #call(action, fields) {
    try {
      return await this.#request(action, fields);
    } catch (error) {
      await this.#dispose();
      throw error;
    }
  }

  async #closeOnce() {
    if (this.#closed) {
      if (this.#backgroundDisposePromise) {
        const cleanupError = await this.#backgroundDisposePromise;
        if (cleanupError) throw cleanupError;
      } else if (this.#disposePromise) {
        await this.#disposePromise;
      }
      if (this.#unexpectedExit) throw new Error('CAPTCHA integration fixture shutdown failed');
      return;
    }
    this.#closed = true;
    let shutdownFailed = false;
    try {
      await this.#request('shutdown', {}, true);
    } catch {
      shutdownFailed = true;
    } finally {
      endControlInput(this.#child);
    }
    if (!shutdownFailed) {
      try {
        const result = await this.#process.wait(this.#timeoutMs, 'CAPTCHA integration fixture shutdown timed out');
        shutdownFailed = result.code !== 0;
      } catch {
        shutdownFailed = true;
      }
    }
    await this.#dispose();
    if (shutdownFailed) throw new Error('CAPTCHA integration fixture shutdown failed');
  }

  #request(action, fields = {}, allowClosed = false) {
    if (this.#closed && !allowClosed) return Promise.reject(new Error('CAPTCHA integration fixture is closed'));
    const id = ++this.#nextID;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error('CAPTCHA integration fixture request timed out'));
      }, this.#timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#child.stdin.write(`${JSON.stringify({ id, action, ...fields })}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error('CAPTCHA integration fixture control write failed'));
      });
    });
  }

  #accept(line) {
    if (!line.startsWith(PREFIX)) return;
    let reply;
    try {
      reply = JSON.parse(line.slice(PREFIX.length));
    } catch {
      this.#fatal('CAPTCHA integration fixture protocol failed');
      return;
    }
    if (reply.ready === true) {
      if (!validURL(reply.admin_url) || !validURL(reply.waf_url) || !reply.username || !reply.password) {
        this.#readyReject(new Error('CAPTCHA integration fixture metadata was incomplete'));
        return;
      }
      this.#readyResolve({
        adminURL: reply.admin_url,
        wafURL: reply.waf_url,
        username: reply.username,
        password: reply.password,
      });
      return;
    }
    const pending = this.#pending.get(reply.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.#pending.delete(reply.id);
    if (reply.ok === true) pending.resolve(reply);
    else pending.reject(new Error(`CAPTCHA integration fixture rejected request: ${safeCode(reply.error)}`));
  }

  #abort(message) {
    this.#readyReject(new Error(message));
    for (const { reject, timer } of this.#pending.values()) {
      clearTimeout(timer);
      reject(new Error(message));
    }
    this.#pending.clear();
  }

  #fatal(message) {
    this.#abort(message);
    if (this.#closed) return;
    this.#closed = true;
    this.#unexpectedExit = true;
    this.#backgroundDisposePromise = this.#dispose().then(() => null, (error) => error);
  }

  #dispose() {
    if (this.#disposePromise) return this.#disposePromise;
    this.#closed = true;
    this.#abort('CAPTCHA integration fixture is closed');
    endControlInput(this.#child);
    this.#disposePromise = (async () => {
      await disposeManagedProcess(this.#process, {
        timeoutMs: this.#timeoutMs,
        failureMessage: 'CAPTCHA integration fixture process cleanup failed',
      });
      await this.#cleanup();
    })();
    return this.#disposePromise;
  }
}

function sanitizedEnvironment(environment) {
  return {
    ...Object.fromEntries(Object.entries(environment).filter(([key]) => !/TOKEN|SECRET|PASSWORD|KEY/i.test(key))),
  };
}

function validURL(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname);
  } catch {
    return false;
  }
}

function safeCode(value) {
  return /^[a-z_]{1,48}$/i.test(String(value ?? '')) ? String(value) : 'protocol_error';
}

function validateLabPlan(plan) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan) || !plan.action || typeof plan.action !== 'object') {
    throw new Error('CAPTCHA Lab fixture returned an invalid physical plan');
  }
  const { interaction, action } = plan;
  if (interaction === 'range' && Number.isFinite(action.value)) return plan;
  if (interaction === 'surface' && Array.isArray(action.path) && action.path.length > 0 && action.path.every(validPoint)) return plan;
  if (interaction === 'click' && validPoint(action.at)) return plan;
  throw new Error('CAPTCHA Lab fixture returned an invalid physical plan');
}

function validPoint(point) {
  return point && typeof point === 'object' && Number.isFinite(point.x) && Number.isFinite(point.y);
}

function processCommand(processFactory, phase, binary) {
  let command;
  try {
    command = processFactory?.[phase]?.(binary);
  } catch {
    throw new Error('CAPTCHA integration fixture process configuration failed');
  }
  if (!command || typeof command.command !== 'string' || !Array.isArray(command.args)) {
    throw new Error('CAPTCHA integration fixture process configuration failed');
  }
  return command;
}

async function failStart(error, managedProcess, cleanup, timeoutMs, failureMessage) {
  if (managedProcess) {
    await disposeManagedProcess(managedProcess, { timeoutMs, failureMessage });
  }
  await cleanup();
  throw error;
}

function onceAsync(work) {
  let promise;
  return () => {
    if (!promise) promise = Promise.resolve().then(work);
    return promise;
  };
}

function endControlInput(child) {
  if (child.stdin && !child.stdin.destroyed) child.stdin.end();
}
