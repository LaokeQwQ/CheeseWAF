#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const FORBIDDEN_PRODUCTION_MARKERS = ['agent-eyes', 'code-inspector', 'codex-acp'];

function checkContents(displayPath, contents) {
  const text = Buffer.from(contents).toString('utf8').toLowerCase();
  const marker = FORBIDDEN_PRODUCTION_MARKERS.find((candidate) => text.includes(candidate));
  if (marker) {
    throw new Error('Development-only Agent tooling leaked into production output: ' + displayPath + ':' + marker);
  }
}

function listArchiveMembers(archivePath, kind) {
  const args = kind === 'tar' ? ['-tzf', archivePath] : ['-Z1', archivePath];
  const command = kind === 'tar' ? 'tar' : 'unzip';
  return execFileSync(command, args, { encoding: 'utf8' })
    .split(/\r?\n/)
    .filter((member) => member && !member.endsWith('/'));
}

function scanArchive(filePath) {
  const kind = filePath.endsWith('.tar.gz') ? 'tar' : 'zip';
  const members = listArchiveMembers(filePath, kind);
  const extractionRoot = mkdtempSync(path.join(os.tmpdir(), 'cheesewaf-marker-scan-'));
  console.log('Scanning archive ' + filePath + ': ' + members.length + ' file members');
  try {
    for (const member of members) {
      const normalized = member.replace(/\\/g, '/');
      if (normalized.startsWith('/') || normalized.split('/').includes('..')) {
        throw new Error('Unsafe archive member path: ' + filePath + ':' + member);
      }
    }
    if (kind === 'tar') {
      execFileSync('tar', ['-xzf', filePath, '-C', extractionRoot, '--']);
    } else {
      execFileSync('unzip', ['-q', filePath, '-d', extractionRoot]);
    }
    for (const member of members) {
      const displayPath = filePath + ':' + member;
      console.log('  archive member ' + displayPath);
      const extractedPath = path.join(extractionRoot, member);
      if (lstatSync(extractedPath).isFile()) {
        checkContents(displayPath, readFileSync(extractedPath));
      }
    }
  } finally {
    rmSync(extractionRoot, { recursive: true, force: true });
  }
}

function scanDirectory(directoryPath) {
  for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
    const entryPath = path.join(directoryPath, entry.name);
    if (entry.isDirectory()) {
      scanDirectory(entryPath);
    } else if (entry.isFile()) {
      scanFile(entryPath);
    }
  }
}

function scanFile(filePath) {
  const stat = lstatSync(filePath);
  if (stat.isDirectory()) {
    scanDirectory(filePath);
    return;
  }
  if (!stat.isFile()) {
    return;
  }
  if (filePath.endsWith('.tar.gz') || filePath.endsWith('.zip')) {
    scanArchive(filePath);
    return;
  }
  checkContents(filePath, readFileSync(filePath));
}

export function scanProductionMarkers(paths) {
  const targets = paths.length > 0 ? paths : ['dist'];
  for (const target of targets) {
    scanFile(path.resolve(target));
  }
  return targets.length;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    scanProductionMarkers(process.argv.slice(2));
    console.log('Production marker scan passed.');
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
