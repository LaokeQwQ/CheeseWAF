import { readFileSync, readdirSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import path from 'node:path';

const distDir = path.resolve('dist');
const html = readFileSync(path.join(distDir, 'index.html'), 'utf8');
const preloadPaths = [...html.matchAll(/<link\s+rel="modulepreload"[^>]+href="([^"]+)"/g)].map((match) => match[1]);
const forbiddenPreloads = preloadPaths.filter((asset) =>
  /three|visualization|qrcode|attack|map|AIPage|IPManage|BlockPages/i.test(asset),
);

if (forbiddenPreloads.length > 0) {
  throw new Error(`Non-critical chunks leaked into the initial preload graph: ${forbiddenPreloads.join(', ')}`);
}

const preloadBytes = preloadPaths.reduce((total, asset) => {
  const filePath = path.join(distDir, asset.replace(/^\//, ''));
  return total + gzipSync(readFileSync(filePath)).byteLength;
}, 0);
const preloadBudget = 20 * 1024;
if (preloadBytes > preloadBudget) {
  throw new Error(`Initial modulepreload budget exceeded: ${preloadBytes} bytes > ${preloadBudget} bytes`);
}

const cssAssets = readdirSync(path.join(distDir, 'assets')).filter((file) => file.endsWith('.css'));
const themeAssets = cssAssets.filter((file) => /^(light|dark|black-gold|blue-white|pink-white|miku-green)-/.test(file));
const normalizeAssetPath = (value) => value.replace(/\\/g, '/').replace(/^\//, '');
const htmlCSSPaths = [...html.matchAll(/<link\s+rel="stylesheet"[^>]+href="([^"]+)"/g)].map((match) =>
  normalizeAssetPath(match[1]),
);
const runtimeInitialCSSPaths = cssAssets
  .filter((file) => /^(global|vendor-arco-)/.test(file))
  .map((file) => normalizeAssetPath(path.posix.join('assets', file)));
const initialCSSPaths = [...new Set([...htmlCSSPaths, ...runtimeInitialCSSPaths])];
const initialCSSBytes = initialCSSPaths.reduce(
  (total, asset) => total + gzipSync(readFileSync(path.join(distDir, asset))).byteLength,
  0,
);
const largestThemeBytes = Math.max(
  0,
  ...themeAssets.map((file) => gzipSync(readFileSync(path.join(distDir, 'assets', file))).byteLength),
);
const initialCSSWithThemeBytes = initialCSSBytes + largestThemeBytes;
const initialCSSBudget = 105 * 1024;
if (initialCSSWithThemeBytes > initialCSSBudget) {
  throw new Error(`Initial CSS budget exceeded: ${initialCSSWithThemeBytes} bytes > ${initialCSSBudget} bytes`);
}
if (themeAssets.length !== 6) {
  throw new Error(`Expected six independently loadable theme stylesheets, found ${themeAssets.length}`);
}
if (themeAssets.some((file) => statSync(path.join(distDir, 'assets', file)).size > 8 * 1024)) {
  throw new Error('A theme stylesheet exceeded the 8 KiB uncompressed budget');
}

console.log(
  `Build budgets OK: ${preloadPaths.length} initial preloads / ${(preloadBytes / 1024).toFixed(2)} KiB gzip; ${(initialCSSWithThemeBytes / 1024).toFixed(2)} KiB initial CSS gzip including the largest theme; ${themeAssets.length} lazy theme stylesheets.`,
);
