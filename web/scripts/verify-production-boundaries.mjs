import { existsSync, lstatSync, readdirSync } from 'node:fs';
import path from 'node:path';

const FORBIDDEN_SEGMENTS = new Set(['.git', 'coverage', 'node_modules', 'public', 'scripts', 'src']);

function validateRelativePath(relativePath) {
  const segments = relativePath.split(path.sep).filter(Boolean).map((segment) => segment.toLowerCase());
  const forbidden = segments.find((segment) => FORBIDDEN_SEGMENTS.has(segment));
  if (forbidden) {
    throw new Error(`development-only path in production artifact: ${relativePath}`);
  }
}

export function scanProductionTree(rootDirectory) {
  const root = path.resolve(rootDirectory);
  if (!existsSync(root) || !lstatSync(root).isDirectory()) {
    throw new Error(`production artifact directory does not exist: ${root}`);
  }

  let seen = 0;
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      const relative = path.relative(root, candidate);
      validateRelativePath(relative);

      const metadata = lstatSync(candidate);
      if (metadata.isSymbolicLink()) {
        throw new Error(`symbolic link in production artifact tree: ${relative}`);
      }
      if (metadata.isDirectory()) {
        visit(candidate);
        continue;
      }
      if (!metadata.isFile()) {
        throw new Error(`special file in production artifact tree: ${relative}`);
      }
      if (metadata.nlink > 1) {
        throw new Error(`hard link in production artifact tree: ${relative}`);
      }
      seen += 1;
    }
  };

  visit(root);
  if (seen === 0) {
    throw new Error(`production artifact directory contains no files: ${root}`);
  }
  return seen;
}
