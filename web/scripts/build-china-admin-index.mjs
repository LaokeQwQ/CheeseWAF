#!/usr/bin/env node
/**
 * Build-time extractor: public/map/aux/china_aux.geojson.gz (~8MB, full
 * geometry) → public/map/aux/china_admin_index.json ([{code,name}] only).
 *
 * The runtime only needs a code→name lookup to resolve admin codes from
 * region names; shipping the full aux geometry for that is wasteful.
 * Run via `npm run build:china-admin-index` (also wired into `prebuild`).
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const sourcePath = path.join(projectRoot, 'public', 'map', 'aux', 'china_aux.geojson.gz');
const outputPath = path.join(projectRoot, 'public', 'map', 'aux', 'china_admin_index.json');

/** Mirror of chinaFeatureAdcode in src/pages/AttackMap/chinaBoundaries.ts. */
function featureAdcode(properties) {
  const props = properties ?? {};
  const gb = typeof props.gb === 'string' && props.gb.length >= 8 ? props.gb.slice(3) : '';
  const adcode = typeof props.adcode === 'string' || typeof props.adcode === 'number' ? String(props.adcode) : '';
  return gb || adcode;
}

const raw = gunzipSync(readFileSync(sourcePath));
const collection = JSON.parse(raw.toString('utf-8'));
const features = Array.isArray(collection?.features) ? collection.features : [];

const byCode = new Map();
for (const feature of features) {
  const code = featureAdcode(feature?.properties);
  const name = String(feature?.properties?.name ?? '').trim();
  if (!/^\d{6}$/.test(code) || !name || byCode.has(code)) continue;
  byCode.set(code, name);
}

const entries = Array.from(byCode, ([code, name]) => ({ code, name }))
  .sort((a, b) => a.code.localeCompare(b.code));

mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(entries));

const { size } = await import('node:fs').then((fs) => fs.statSync(outputPath));
console.log(`china_admin_index.json: ${entries.length} entries, ${(size / 1024).toFixed(1)} KiB -> ${path.relative(projectRoot, outputPath)}`);
if (size > 300 * 1024) {
  console.error(`error: output exceeds 300 KiB budget (${(size / 1024).toFixed(1)} KiB)`);
  process.exitCode = 1;
}
