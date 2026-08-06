/**
 * Playwright re-verify: sites table headers, users pageSize, empty/layout pages.
 * Usage: CHEESEWAF_TOKEN=... node scripts/playwright-console-layout.mjs
 */
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '..', '..', 'output', 'playwright', 'console-layout');
const base = process.env.ATTACK_MAP_BASE || process.env.UI_BASE || 'http://127.0.0.1:4173';
const token = process.env.CHEESEWAF_TOKEN || '';
mkdirSync(outDir, { recursive: true });

const report = { ok: true, steps: [] };
const step = (name, data = {}) => {
  report.steps.push({ name, ...data });
  console.log(JSON.stringify({ name, ...data }));
};

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

async function go(path) {
  await page.goto(`${base}${path}`, { waitUntil: 'domcontentloaded', timeout: 45000 });
  await page.waitForTimeout(900);
}

try {
  await go('/login');
  if (token) {
    await page.evaluate((v) => localStorage.setItem('cheesewaf-token', v), token);
  }

  // Sites
  await go('/sites');
  await page.waitForTimeout(1200);
  const sitesHeaderWrap = await page.evaluate(() => {
    // Dual: native table headers + Arco-compat adapters that still emit .arco-table-th
    const ths = [...document.querySelectorAll(
      '.sites-table thead th, .sites-table table th, .sites-table [role="columnheader"], .sites-table .arco-table-th',
    )];
    return ths.map((th) => {
      const style = getComputedStyle(th);
      return {
        text: (th.textContent || '').trim(),
        whiteSpace: style.whiteSpace,
        clientHeight: th.clientHeight,
        scrollHeight: th.scrollHeight,
        wraps: th.scrollHeight > th.clientHeight + 2,
      };
    });
  });
  const sitesWraps = sitesHeaderWrap.filter((h) => h.wraps && h.text);
  step('sites-headers', { count: sitesHeaderWrap.length, wraps: sitesWraps });
  if (sitesWraps.length > 0) report.ok = false;
  await page.screenshot({ path: join(outDir, 'sites.png') });

  // Users pagination size
  await go('/users');
  await page.waitForTimeout(1200);
  const pagination = await page.evaluate(() => {
    // Dual: Arco-compat pagination/select views + native select/combobox/button page-size controls
    const select = document.querySelector([
      '.users-page .arco-pagination .arco-select-view',
      '.users-page .arco-table-pagination .arco-select-view',
      '.users-page .arco-pagination select',
      '.users-page .arco-table-pagination select',
      '.users-page nav select',
      '.users-page [class*="pagination"] select',
      '.users-page [class*="pagination"] [role="combobox"]',
      '.users-page select',
      '.users-page [role="combobox"]',
    ].join(', '));
    if (!select) return { found: false };
    const rect = select.getBoundingClientRect();
    const text = (select.textContent || select.value || '').trim();
    return {
      found: true,
      width: Math.round(rect.width),
      text,
      truncated: rect.width < 96 || /…|\.\.\./.test(text),
    };
  });
  step('users-page-size', pagination);
  if (pagination.found && pagination.width < 96) report.ok = false;
  // open size dropdown if present (Arco adapters and native select/combobox)
  const sizeTrigger = page.locator([
    '.users-page .arco-pagination .arco-select-view',
    '.users-page .arco-table-pagination .arco-select-view',
    '.users-page .arco-pagination select',
    '.users-page .arco-table-pagination select',
    '.users-page nav select',
    '.users-page [class*="pagination"] select',
    '.users-page [class*="pagination"] [role="combobox"]',
    '.users-page select',
    '.users-page [role="combobox"]',
  ].join(', ')).first();
  if (await sizeTrigger.count()) {
    await sizeTrigger.click();
    await page.waitForTimeout(400);
    const popup = page.locator([
      '.arco-select-popup',
      '.arco-trigger-popup',
      '[role="listbox"]',
      '[data-radix-select-viewport]',
      '[data-slot="select-content"]',
    ].join(', ')).last();
    const visible = await popup.isVisible().catch(() => false);
    const popupBox = visible ? await popup.boundingBox() : null;
    step('users-page-size-popup', { visible, height: popupBox?.height ?? 0 });
    if (!visible || (popupBox && popupBox.height < 40)) report.ok = false;
    await page.screenshot({ path: join(outDir, 'users-pagesize.png') });
    await page.keyboard.press('Escape');
  }

  // Icon/button alignment sample (Arco-compat .arco-btn* + native primary buttons)
  const iconAlign = await page.evaluate(() => {
    const btn = document.querySelector([
      '.page-header .arco-btn-primary',
      '.users-page .arco-btn-primary',
      '.page-header button.arco-btn',
      '.users-page button.arco-btn',
      '.page-header button[data-variant="default"]',
      '.page-header button[data-variant="primary"]',
      '.users-page button[data-variant="default"]',
      '.users-page button[data-variant="primary"]',
      '.page-header button',
      '.users-page .page-header button',
    ].join(', '));
    if (!btn) return { found: false };
    const svg = btn.querySelector('svg, .arco-icon, .arco-btn-icon svg, .arco-btn-icon');
    const span = btn.querySelector('span');
    if (!svg || !span) return { found: true, hasSvg: !!svg };
    const br = btn.getBoundingClientRect();
    const sr = svg.getBoundingClientRect();
    const tr = span.getBoundingClientRect();
    const svgMid = sr.top + sr.height / 2;
    const textMid = tr.top + tr.height / 2;
    return {
      found: true,
      hasSvg: true,
      delta: Math.abs(svgMid - textMid),
      btnHeight: br.height,
    };
  });
  step('icon-text-align', iconAlign);
  if (iconAlign.found && iconAlign.hasSvg && iconAlign.delta > 4) report.ok = false;

  // Empty-ish pages smoke
  for (const path of ['/ip', '/ssl', '/edge', '/updates', '/cluster', '/operations', '/system']) {
    await go(path);
    const metrics = await page.evaluate(() => {
      const surface = document.querySelector('.page-surface');
      const overflowX = document.documentElement.scrollWidth - document.documentElement.clientWidth;
      const panels = document.querySelectorAll('.page-surface .table-panel, .page-surface .panel, .page-surface .system-card, .page-surface .system-fieldset').length;
      return {
        hasSurface: !!surface,
        overflowX,
        panels,
        title: document.querySelector('.page-header h1')?.textContent?.trim() || '',
      };
    });
    step(`page-${path}`, metrics);
    if (metrics.overflowX > 8) report.ok = false;
    await page.screenshot({ path: join(outDir, `${path.replace(/\//g, '_') || 'root'}.png`) });
  }
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
