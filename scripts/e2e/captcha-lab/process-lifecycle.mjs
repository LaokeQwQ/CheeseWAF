import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_TERMINATION_TIMEOUT_MS = 5_000;
const REMOVE_RETRY_DELAYS_MS = [20, 50, 100, 200];
const RETRYABLE_REMOVE_CODES = new Set(['EACCES', 'EBUSY', 'ENOTEMPTY', 'EPERM']);

export function spawnManagedProcess(command, args, options = {}) {
  const child = spawn(command, args, {
    ...options,
    detached: process.platform !== 'win32',
  });
  return new ManagedProcess(child);
}

export async function removeTemporaryDirectory(directory, {
  remove = rm,
  failureMessage = 'temporary process cleanup failed',
} = {}) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await remove(directory, { recursive: true, force: true });
      return;
    } catch (error) {
      if (!RETRYABLE_REMOVE_CODES.has(error?.code) || attempt >= REMOVE_RETRY_DELAYS_MS.length) {
        throw new Error(failureMessage);
      }
      await delay(REMOVE_RETRY_DELAYS_MS[attempt]);
    }
  }
}

export async function disposeManagedProcess(managedProcess, {
  timeoutMs = DEFAULT_TERMINATION_TIMEOUT_MS,
  failureMessage = 'managed process cleanup failed',
} = {}) {
  try {
    await managedProcess.terminate(timeoutMs);
  } catch {
    throw new Error(failureMessage);
  }
}

class ManagedProcess {
  #child;
  #closed = false;
  #terminationPromise;
  #exitPromise;

  constructor(child) {
    this.#child = child;
    this.#exitPromise = new Promise((resolve) => {
      child.once('close', (code, signal) => {
        this.#closed = true;
        resolve({ code: code ?? 1, signal });
      });
      child.once('error', () => {});
    });
  }

  get child() {
    return this.#child;
  }

  get closed() {
    return this.#closed;
  }

  wait(timeoutMs, message) {
    return withTimeout(this.#exitPromise, timeoutMs, message);
  }

  terminate(timeoutMs = DEFAULT_TERMINATION_TIMEOUT_MS) {
    if (this.#terminationPromise) return this.#terminationPromise;
    this.#terminationPromise = this.#terminate(timeoutMs);
    return this.#terminationPromise;
  }

  async #terminate(timeoutMs) {
    const pid = this.#child.pid;
    if (this.#closed) {
      if (process.platform !== 'win32' && pid && unixProcessGroupExists(pid)) {
        signalUnixProcessGroup(pid, 'SIGKILL', this.#child);
        await waitForUnixProcessGroupExit(pid, timeoutMs);
      }
      return this.#exitPromise;
    }

    if (process.platform === 'win32' && pid) {
      try {
        await terminateWindowsTree(pid, timeoutMs);
      } catch {
        terminateDirectly(this.#child);
      }
    } else if (pid) {
      const graceMs = Math.min(200, Math.max(25, Math.floor(timeoutMs / 4)));
      signalUnixProcessGroup(pid, 'SIGTERM', this.#child);
      await Promise.race([this.#exitPromise, delay(graceMs)]);
      if (unixProcessGroupExists(pid)) signalUnixProcessGroup(pid, 'SIGKILL', this.#child);
    } else {
      terminateDirectly(this.#child);
    }

    try {
      const result = await withTimeout(this.#exitPromise, timeoutMs, 'managed process termination timed out');
      if (process.platform !== 'win32' && pid) await waitForUnixProcessGroupExit(pid, timeoutMs);
      return result;
    } catch {
      terminateDirectly(this.#child);
      throw new Error('managed process termination failed');
    }
  }
}

async function terminateWindowsTree(pid, timeoutMs) {
  const systemRoot = process.env.SystemRoot ?? process.env.WINDIR;
  const command = systemRoot ? path.join(systemRoot, 'System32', 'taskkill.exe') : 'taskkill.exe';
  const killer = spawn(command, ['/pid', String(pid), '/t', '/f'], {
    shell: false,
    stdio: ['ignore', 'ignore', 'ignore'],
    windowsHide: true,
  });
  let result;
  try {
    result = await waitForChild(killer, timeoutMs);
  } catch {
    terminateDirectly(killer);
    await waitForChild(killer, timeoutMs).catch(() => {});
    throw new Error('tree termination command failed');
  }
  if (result.code !== 0) throw new Error('tree termination command failed');
}

function signalUnixProcessGroup(pid, signal, child) {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
    terminateDirectly(child);
  }
}

function unixProcessGroupExists(pid) {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return error?.code === 'EPERM';
  }
}

async function waitForUnixProcessGroupExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (unixProcessGroupExists(pid)) {
    if (Date.now() >= deadline) throw new Error('managed process group termination failed');
    await delay(20);
  }
}

function terminateDirectly(child) {
  try {
    child.kill('SIGKILL');
  } catch {
    // The process may have exited between the tree lookup and the signal.
  }
}

function waitForChild(child, timeoutMs) {
  return withTimeout(new Promise((resolve) => {
    child.once('error', () => resolve({ code: 1 }));
    child.once('close', (code) => resolve({ code: code ?? 1 }));
  }), timeoutMs, 'tree termination command timed out');
}

export function withTimeout(promise, timeoutMs, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function delay(timeoutMs) {
  return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}
