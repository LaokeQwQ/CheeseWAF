import assert from 'node:assert/strict';
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { scanProductionTree } from './verify-production-boundaries.mjs';

function withArtifactTree(run) {
  const root = mkdtempSync(path.join(tmpdir(), 'cheesewaf-web-artifact-'));
  try {
    run(root);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
}

test('accepts a regular production tree', () => {
  withArtifactTree((root) => {
    mkdirSync(path.join(root, 'assets'));
    writeFileSync(path.join(root, 'index.html'), '<!doctype html>');
    writeFileSync(path.join(root, 'assets', 'app.js'), 'export {};');
    assert.equal(scanProductionTree(root), 2);
  });
});

test('rejects source and dependency directories at any depth', () => {
  for (const forbidden of ['node_modules', 'public', 'scripts', 'src']) {
    withArtifactTree((root) => {
      const directory = path.join(root, 'nested', forbidden);
      mkdirSync(directory, { recursive: true });
      writeFileSync(path.join(directory, 'leak.js'), 'development-only');
      assert.throws(() => scanProductionTree(root), /development-only path/);
    });
  }
});

test('rejects links and empty artifact trees', () => {
  withArtifactTree((root) => {
    assert.throws(() => scanProductionTree(root), /contains no files/);
  });
  withArtifactTree((root) => {
    writeFileSync(path.join(root, 'target.js'), 'target');
    symlinkSync('target.js', path.join(root, 'linked.js'));
    assert.throws(() => scanProductionTree(root), /symbolic link/);
  });
  withArtifactTree((root) => {
    writeFileSync(path.join(root, 'target.js'), 'target');
    linkSync(path.join(root, 'target.js'), path.join(root, 'linked.js'));
    assert.throws(() => scanProductionTree(root), /hard link/);
  });
});
