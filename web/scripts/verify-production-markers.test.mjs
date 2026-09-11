import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const scriptPath = fileURLToPath(new URL('./verify-production-markers.mjs', import.meta.url));

function runScanner(...targets) {
  return execFileSync(process.execPath, [scriptPath, ...targets], {
    cwd: process.cwd(),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('scans every production file in a directory', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'cheesewaf-marker-test-'));
  try {
    mkdirSync(path.join(root, 'assets'));
    writeFileSync(path.join(root, 'index.html'), '<!doctype html>');
    writeFileSync(path.join(root, 'assets', 'image.bin'), Buffer.from('safe'));
    assert.match(runScanner(root), /Production marker scan passed/);
    writeFileSync(path.join(root, 'assets', 'image.bin'), Buffer.from('code-inspector'));
    assert.throws(() => runScanner(root), /code-inspector/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('prints and scans tar archive members', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'cheesewaf-marker-archive-test-'));
  try {
    const payload = path.join(root, 'payload');
    mkdirSync(payload);
    writeFileSync(path.join(payload, 'app.js'), 'console.log(1);');
    const archive = path.join(root, 'release.tar.gz');
    execFileSync('tar', ['-czf', archive, '-C', root, 'payload']);
    const output = runScanner(archive);
    assert.match(output, /archive member .*payload\/app\.js/);
    writeFileSync(path.join(payload, 'app.js'), 'code-inspector');
    execFileSync('tar', ['-czf', archive, '-C', root, 'payload']);
    assert.throws(() => runScanner(archive), /payload\/app\.js:code-inspector/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('prints and scans zip archive members', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'cheesewaf-marker-zip-test-'));
  try {
    const payload = path.join(root, 'payload');
    mkdirSync(payload);
    writeFileSync(path.join(payload, 'app.js'), 'console.log(1);');
    const archive = path.join(root, 'release.zip');
    execFileSync('zip', ['-qr', archive, 'payload'], { cwd: root });
    const output = runScanner(archive);
    assert.match(output, /archive member .*payload\/app\.js/);
    writeFileSync(path.join(payload, 'app.js'), 'codex-acp');
    execFileSync('zip', ['-qr', archive, 'payload'], { cwd: root });
    assert.throws(() => runScanner(archive), /payload\/app\.js:codex-acp/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
