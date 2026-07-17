import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const PRIVATE_PREFIX = 'CHEESEWAF_CAPTCHA_BROWSER ';
const INTEGRATION_PREFIX = 'CHEESEWAF_CAPTCHA_INTEGRATION ';
const scriptPath = fileURLToPath(import.meta.url);
const [mode, ...args] = process.argv.slice(2);

switch (mode) {
  case 'compile-ok':
    await writeFile(args[0], 'temporary fixture binary');
    break;
  case 'compile-hang':
    await hangWithDescendant(args[0]);
    break;
  case 'runtime-hang':
    await hangWithDescendant(args[0]);
    break;
  case 'private-request-hang':
    await runHangingProtocol(PRIVATE_PREFIX, { ok: true, ready: true }, args[0]);
    break;
  case 'private-normal':
    await runNormalProtocol(PRIVATE_PREFIX, { ok: true, ready: true });
    break;
  case 'integration-request-hang':
    await runHangingProtocol(INTEGRATION_PREFIX, integrationReady(), args[0]);
    break;
  case 'integration-normal':
    await runNormalProtocol(INTEGRATION_PREFIX, integrationReady());
    break;
  case 'descendant':
    process.on('SIGTERM', () => {});
    setInterval(() => {}, 1_000);
    break;
  default:
    process.exitCode = 2;
}

async function hangWithDescendant(pidFile) {
  await startDescendant(pidFile);
  await new Promise(() => {});
}

async function runHangingProtocol(prefix, ready, pidFile) {
  await startDescendant(pidFile);
  writeReply(prefix, ready);
  process.stdin.resume();
  await new Promise(() => {});
}

async function runNormalProtocol(prefix, ready) {
  writeReply(prefix, ready);
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      continue;
    }
    if (request.action !== 'shutdown') continue;
    writeReply(prefix, { id: request.id, ok: true });
    return;
  }
}

async function startDescendant(pidFile) {
  const child = spawn(process.execPath, [scriptPath, 'descendant'], {
    stdio: ['ignore', 'ignore', 'ignore'],
    windowsHide: true,
  });
  await new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', reject);
  });
  await writeFile(pidFile, JSON.stringify([process.pid, child.pid]));
}

function integrationReady() {
  return {
    ok: true,
    ready: true,
    admin_url: 'http://127.0.0.1:41001',
    waf_url: 'http://127.0.0.1:41002',
    username: 'fixture-user',
    password: 'fixture-password',
  };
}

function writeReply(prefix, reply) {
  process.stdout.write(`${prefix}${JSON.stringify(reply)}\n`);
}
