/**
 * Playwright smoke: offline MapLibre attack map (no WebBridge, no online tiles).
 *
 * Usage:
 *   CHEESEWAF_TOKEN=... node scripts/playwright-attack-map-osm.mjs
 */
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..', '..');
const outDir = join(root, 'output', 'playwright', 'attack-map-osm');
const base = process.env.ATTACK_MAP_BASE || 'http://127.0.0.1:4173';
const token = process.env.CHEESEWAF_TOKEN || '';

mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const report = { base, steps: [], ok: true, offlineBlockedHosts: [] };

function step(name, data = {}) {
  report.steps.push({ name, ...data, at: new Date().toISOString() });
  console.log(JSON.stringify({ name, ...data }));
}

// Block third-party map CDNs / tile hosts — basemap must stay usable offline.
const blockedHostHints = [
  'openstreetmap.org',
  'openfreemap.org',
  'mapbox.com',
  'maptiler.com',
  'cartocdn.com',
  'tile.',
  'tiles.',
];

await page.route('**/*', async (route) => {
  const url = route.request().url();
  let host = '';
  try {
    host = new URL(url).hostname;
  } catch {
    await route.continue();
    return;
  }
  const isLocal = host === '127.0.0.1' || host === 'localhost';
  const isBlocked = !isLocal && blockedHostHints.some((hint) => host.includes(hint) || url.includes(hint));
  if (isBlocked) {
    report.offlineBlockedHosts.push(host);
    await route.abort();
    return;
  }
  await route.continue();
});

try {
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  if (token) {
    await page.evaluate((value) => localStorage.setItem('cheesewaf-token', value), token);
  }
  await page.goto(`${base}/attack-map`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
  step('open', { path: new URL(page.url()).pathname });

  const map = page.locator('[data-testid="osm-attack-map"]');
  await map.waitFor({ state: 'visible', timeout: 45_000 });
  await page.waitForTimeout(2000);

  const engine = await map.getAttribute('data-map-engine');
  const offline = await map.getAttribute('data-map-offline');
  const mapMode = await map.getAttribute('data-map-mode');
  const canvasCount = await page.locator('.maplibregl-canvas').count();
  step('map-ready', { engine, offline, mapMode, canvasCount });

  if (engine !== 'maplibre-offline' || offline !== 'true' || canvasCount < 1) {
    report.ok = false;
  }

  await page.screenshot({ path: join(outDir, 'attack-map-2d-offline.png') });

  // China mode: district-level offline pack (world-atlas + china-map-echarts)
  await page.goto(`${base}/attack-map?mode=china`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
  const chinaMap = page.locator('[data-testid="osm-attack-map"]');
  await chinaMap.waitFor({ state: 'visible', timeout: 45_000 });
  await page.waitForTimeout(4000);
  const chinaMode = await chinaMap.getAttribute('data-map-mode');
  const chinaEngine = await chinaMap.getAttribute('data-map-engine');
  const chinaOffline = await chinaMap.getAttribute('data-map-offline');
  const chinaCanvas = await page.locator('.maplibregl-canvas').count();
  const credit = ((await page.locator('.map-basemap-credit').first().textContent()) || '').trim();
  step('china', { chinaMode, chinaEngine, chinaOffline, chinaCanvas, credit });
  if (chinaMode !== 'china' || chinaEngine !== 'maplibre-offline' || chinaOffline !== 'true' || chinaCanvas < 1) {
    report.ok = false;
  }
  if (!/offline/i.test(credit) || !/china-map-echarts|world-atlas/i.test(credit)) {
    report.ok = false;
  }
  await page.screenshot({ path: join(outDir, 'attack-map-china-offline.png') });

  // Confirm no successful requests to blocked tile CDNs (route.abort list)
  const uniqueBlocked = [...new Set(report.offlineBlockedHosts)];
  step('blocked-hosts', { count: uniqueBlocked.length, hosts: uniqueBlocked.slice(0, 20) });
  // Basemap must not depend on external tiles — any blocked host is OK (aborted),
  // failure would be a broken map (already covered by canvas/engine checks).
} catch (error) {
  report.ok = false;
  report.error = String(error?.stack || error);
  step('error', { error: report.error });
  try {
    await page.screenshot({ path: join(outDir, 'error.png'), fullPage: true });
  } catch {
    // ignore
  }
} finally {
  writeFileSync(join(outDir, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}

process.exitCode = report.ok ? 0 : 1;
