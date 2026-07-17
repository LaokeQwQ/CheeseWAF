import { readFileSync, readdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import path from 'node:path';

const distDir = path.resolve('dist');
const html = readFileSync(path.join(distDir, 'index.html'), 'utf8');
const cssAssets = readdirSync(path.join(distDir, 'assets')).filter((f) => f.endsWith('.css'));
const themeAssets = cssAssets.filter((f) => /^(light|dark|black-gold|blue-white|pink-white|miku-green)-/.test(f));
const htmlCSSPaths = [...html.matchAll(/<link\s+rel="stylesheet"[^>]+href="([^"]+)"/g)].map((m) => m[1].replace(/^\//, ''));
const runtimeInitialCSSPaths = cssAssets
  .filter((f) => /^(global|vendor-arco-)/.test(f))
  .map((f) => path.join('assets', f));
const initialCSSPaths = [...new Set([...htmlCSSPaths, ...runtimeInitialCSSPaths])];
let initial = 0;
for (const asset of initialCSSPaths) {
  const bytes = gzipSync(readFileSync(path.join(distDir, asset))).byteLength;
  initial += bytes;
  console.log(asset, bytes);
}
const largestTheme = Math.max(0, ...themeAssets.map((f) => gzipSync(readFileSync(path.join(distDir, 'assets', f))).byteLength));
console.log('theme_max', largestTheme);
console.log('total', initial + largestTheme, 'budget', 105 * 1024);
