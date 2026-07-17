import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import {
  disposeManagedProcess,
  removeTemporaryDirectory,
  spawnManagedProcess,
  withTimeout,
} from './process-lifecycle.mjs';

const PREFIX = 'CHEESEWAF_CAPTCHA_BROWSER ';
const PUBLIC_CHALLENGE_FIELDS = ['expires_at', 'presentation', 'token', 'type'];
const defaultProcessFactory = {
  compile: (binary) => ({ command: 'go', args: ['test', '-c', '-o', binary, './internal/captcha'] }),
  run: (binary) => ({
    command: binary,
    args: ['-test.run=^TestBehaviorBrowserHarnessProcess$', '-test.v=true', '-test.count=1'],
  }),
};

export async function startPrivateHarness({
  cwd = process.cwd(),
  timeoutMs = 60_000,
  processFactory = defaultProcessFactory,
  removeTemporary,
} = {}) {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'cheesewaf-captcha-browser-'));
  const binary = path.join(temporaryDirectory, process.platform === 'win32' ? 'captcha-browser-harness.exe' : 'captcha-browser-harness');
  const environment = privateHarnessEnvironment(process.env);
  const cleanup = onceAsync(() => removeTemporaryDirectory(temporaryDirectory, {
    remove: removeTemporary,
    failureMessage: 'private CAPTCHA fixture temporary cleanup failed',
  }));
  let compiler;
  try {
    const command = processCommand(processFactory, 'compile', binary);
    compiler = spawnManagedProcess(command.command, command.args, {
      cwd,
      env: environment,
      stdio: ['ignore', 'ignore', 'ignore'],
      windowsHide: true,
    });
    const result = await compiler.wait(timeoutMs, 'private CAPTCHA fixture compilation timed out');
    if (result.code !== 0) throw new Error('private CAPTCHA fixture compilation failed');
    await disposeManagedProcess(compiler, {
      timeoutMs,
      failureMessage: 'private CAPTCHA fixture compiler cleanup failed',
    });
  } catch (error) {
    return failStart(error, compiler, cleanup, timeoutMs, 'private CAPTCHA fixture compiler cleanup failed');
  }

  let fixtureProcess;
  let harness;
  try {
    const command = processCommand(processFactory, 'run', binary);
    fixtureProcess = spawnManagedProcess(command.command, command.args, {
      cwd,
      env: environment,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    fixtureProcess.child.stderr.resume();
    harness = new PrivateHarness(fixtureProcess, timeoutMs, cleanup);
    await harness.ready();
    if (fixtureProcess.closed) throw new Error('private CAPTCHA fixture process exited unexpectedly');
    return harness;
  } catch (error) {
    if (harness) {
      await harness.disposeAfterFailure();
      throw error;
    }
    return failStart(error, fixtureProcess, cleanup, timeoutMs, 'private CAPTCHA fixture process cleanup failed');
  }
}

export function publicIssuePayload(challenge) {
  assertPublicChallenge(challenge);
  return { data: challenge };
}

export function publicVerifyPayload(outcome) {
  if (outcome.status === 410) {
    return { error: { code: 'CAPTCHA_ALREADY_USED', message: 'behavior CAPTCHA is expired or already used' } };
  }
  return { data: { valid: outcome.valid === true, ...(outcome.type ? { type: outcome.type } : {}) } };
}

class PrivateHarness {
  #process;
  #child;
  #timeoutMs;
  #nextID = 0;
  #pending = new Map();
  #plans = new Map();
  #readyPromise;
  #readyResolve;
  #readyReject;
  #closed = false;
  #cleanup;
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
    this.#child.once('error', () => this.#fatal('private CAPTCHA fixture process failed to start'));
    this.#child.once('close', () => this.#fatal('private CAPTCHA fixture process exited unexpectedly'));
    const lines = createInterface({ input: this.#child.stdout, crlfDelay: Infinity });
    lines.on('line', (line) => this.#acceptLine(line));
  }

  async ready() {
    return withTimeout(this.#readyPromise, this.#timeoutMs, 'private CAPTCHA fixture startup timed out');
  }

  async issue(scenario) {
    try {
      const issued = await this.#request('issue', { scenario });
      if (!issued.challenge || !issued.handle) throw new Error('private CAPTCHA fixture issue reply was incomplete');
      assertPublicChallenge(issued.challenge);
      const planned = await this.#request('plan', { handle: issued.handle });
      assertPrivatePlan(planned.plan);
      this.#plans.set(issued.challenge.token, planned.plan);
      return issued.challenge;
    } catch (error) {
      await this.#dispose();
      throw error;
    }
  }

  actionFor(challenge, variant) {
    const plan = this.#plans.get(challenge?.token);
    if (!plan || (variant !== 'wrong' && variant !== 'correct')) {
      throw new Error('private CAPTCHA fixture action is unavailable');
    }
    return { interaction: plan.interaction, action: plan[variant] };
  }

  async verify(response) {
    try {
      const reply = await this.#request('verify', { response });
      if (reply.status !== 200 && reply.status !== 410) throw new Error('private CAPTCHA fixture verify reply was invalid');
      return {
        status: reply.status,
        valid: reply.result?.valid === true,
        type: reply.result?.type,
        code: reply.code,
      };
    } catch (error) {
      await this.#dispose();
      throw error;
    }
  }

  close() {
    if (!this.#closePromise) this.#closePromise = this.#closeOnce();
    return this.#closePromise;
  }

  async disposeAfterFailure() {
    await this.#dispose();
  }

  async #closeOnce() {
    if (this.#closed) {
      if (this.#backgroundDisposePromise) {
        const cleanupError = await this.#backgroundDisposePromise;
        if (cleanupError) throw cleanupError;
      } else if (this.#disposePromise) {
        await this.#disposePromise;
      }
      if (this.#unexpectedExit) throw new Error('private CAPTCHA fixture process failed');
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
        const result = await this.#process.wait(this.#timeoutMs, 'private CAPTCHA fixture shutdown timed out');
        shutdownFailed = result.code !== 0;
      } catch {
        shutdownFailed = true;
      }
    }
    await this.#dispose();
    if (shutdownFailed) throw new Error('private CAPTCHA fixture process failed');
  }

  #request(action, fields = {}, allowClosed = false) {
    if (this.#closed && !allowClosed) return Promise.reject(new Error('private CAPTCHA fixture is closed'));
    const id = ++this.#nextID;
    const request = JSON.stringify({ id, action, ...fields });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error('private CAPTCHA fixture request timed out'));
      }, this.#timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#child.stdin.write(`${request}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new Error('private CAPTCHA fixture control write failed'));
      });
    });
  }

  #acceptLine(line) {
    if (!line.startsWith(PREFIX)) return;
    let reply;
    try {
      reply = JSON.parse(line.slice(PREFIX.length));
    } catch {
      this.#fatal('private CAPTCHA fixture protocol failed');
      return;
    }
    if (reply.ready === true) {
      this.#readyResolve();
      return;
    }
    const pending = this.#pending.get(reply.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.#pending.delete(reply.id);
    if (reply.ok === true) pending.resolve(reply);
    else pending.reject(new Error(`private CAPTCHA fixture rejected request: ${safeCode(reply.error)}`));
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
    this.#abort('private CAPTCHA fixture is closed');
    endControlInput(this.#child);
    this.#plans.clear();
    this.#disposePromise = (async () => {
      await disposeManagedProcess(this.#process, {
        timeoutMs: this.#timeoutMs,
        failureMessage: 'private CAPTCHA fixture process cleanup failed',
      });
      await this.#cleanup();
    })();
    return this.#disposePromise;
  }
}

function assertPublicChallenge(challenge) {
  if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) {
    throw new Error('private CAPTCHA fixture returned an invalid public challenge');
  }
  const keys = Object.keys(challenge).sort();
  if (keys.length !== PUBLIC_CHALLENGE_FIELDS.length || keys.some((key, index) => key !== PUBLIC_CHALLENGE_FIELDS[index])) {
    throw new Error('private CAPTCHA fixture returned unexpected public challenge fields');
  }
  if (typeof challenge.token !== 'string' || !challenge.token || typeof challenge.type !== 'string' || !challenge.presentation) {
    throw new Error('private CAPTCHA fixture returned an incomplete public challenge');
  }
  if (containsPrivatePlanKey(challenge)) throw new Error('private CAPTCHA fixture exposed control material');
}

function assertPrivatePlan(plan) {
  if (!plan || !['range', 'surface', 'click'].includes(plan.interaction) || !plan.correct || !plan.wrong) {
    throw new Error('private CAPTCHA fixture returned an invalid action plan');
  }
}

function containsPrivatePlanKey(value) {
  const forbidden = new Set(['interaction', 'correct', 'wrong', 'path', 'at', 'value', 'handle']);
  if (Array.isArray(value)) return value.some(containsPrivatePlanKey);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, child]) => forbidden.has(key) || containsPrivatePlanKey(child));
}

function privateHarnessEnvironment(env) {
  return {
    ...Object.fromEntries(Object.entries(env).filter(([key]) => !/TOKEN|SECRET|PASSWORD|KEY/i.test(key))),
    CHEESEWAF_CAPTCHA_BROWSER_HARNESS: '1',
  };
}

function safeCode(value) {
  return /^[a-z_]{1,48}$/i.test(String(value ?? '')) ? String(value) : 'protocol_error';
}

function processCommand(processFactory, phase, binary) {
  let command;
  try {
    command = processFactory?.[phase]?.(binary);
  } catch {
    throw new Error('private CAPTCHA fixture process configuration failed');
  }
  if (!command || typeof command.command !== 'string' || !Array.isArray(command.args)) {
    throw new Error('private CAPTCHA fixture process configuration failed');
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
