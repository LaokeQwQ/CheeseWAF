/**
 * Layout / UI smoke used when Agent Eyes has no active selection.
 * Usage: UI_BASE=http://127.0.0.1:5173 CHEESEWAF_TOKEN=... node scripts/playwright-agent-eyes-layout.mjs
 */
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const out = join(__dirname, '..', '..', 'output', 'playwright', 'agent-eyes-layout');
const base = process.env.UI_BASE || process.env.ATTACK_MAP_BASE || 'http://127.0.0.1:5173';
const token = process.env.CHEESEWAF_TOKEN || '';
const eyesBase = process.env.AGENT_EYES_BASE || 'http://127.0.0.1:5678';

mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const report = { base, eyesBase, pages: [], ok: true, agentEyes: null };

try {
  const r = await fetch(`${eyesBase}/context/selected`, { headers: { Accept: 'application/json' } });
  report.agentEyes = await r.json();
} catch (error) {
  report.agentEyes = { error: String(error) };
}

async function audit(path, name) {
  const res = await page.goto(`${base}${path}`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
  await page.waitForTimeout(1400);
  const metrics = await page.evaluate(() => {
    const issues = [];
    const overflow = [];
    for (const el of document.querySelectorAll('body *')) {
      const style = getComputedStyle(el);
      if (style.display === 'none' || style.visibility === 'hidden') continue;
      if (style.position === 'fixed' || style.position === 'sticky') continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right > window.innerWidth + 4 || rect.left < -4) {
        const cls = typeof el.className === 'string' ? el.className.slice(0, 100) : el.tagName;
        overflow.push({
          cls,
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          tag: el.tagName,
          text: (el.textContent || '').trim().slice(0, 40),
        });
        if (overflow.length > 15) break;
      }
    }

    const buttons = [...document.querySelectorAll('button, .arco-btn')].slice(0, 40).map((button) => {
      const icon = button.querySelector('svg, .arco-icon, .arco-btn-icon svg, .arco-btn-icon');
      if (!icon) return null;
      const iconRect = icon.getBoundingClientRect();
      const textNode = [...button.querySelectorAll('span')].find(
        (span) => !span.classList.contains('arco-btn-icon') && (span.textContent || '').trim(),
      );
      if (!textNode) return null;
      const textRect = textNode.getBoundingClientRect();
      const delta = Math.abs(iconRect.top + iconRect.height / 2 - (textRect.top + textRect.height / 2));
      return {
        text: (button.textContent || '').trim().slice(0, 40),
        delta: Math.round(delta * 10) / 10,
        misalign: delta > 3.5,
      };
    }).filter(Boolean);

    const footer = document.querySelector('.auth-footer');
    let footerInfo = null;
    if (footer) {
      const footerRect = footer.getBoundingClientRect();
      const style = getComputedStyle(footer);
      footerInfo = {
        text: (footer.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 160),
        textAlign: style.textAlign,
        width: Math.round(footerRect.width),
        left: Math.round(footerRect.left),
      };
    }

    const toolbar = document.querySelector('.auth-toolbar');
    let toolbarInfo = null;
    if (toolbar) {
      const toolbarRect = toolbar.getBoundingClientRect();
      toolbarInfo = {
        top: Math.round(toolbarRect.top),
        rightGap: Math.round(window.innerWidth - toolbarRect.right),
        width: Math.round(toolbarRect.width),
      };
    }

    const eyesHints = [...document.querySelectorAll('[id], [class]')]
      .filter((el) => {
        const id = el.id || '';
        const cls = typeof el.className === 'string' ? el.className : '';
        return /inspector|agent-eyes|code-insp/i.test(`${id} ${cls}`);
      })
      .slice(0, 8)
      .map((el) => ({
        id: el.id,
        cls: typeof el.className === 'string' ? el.className.slice(0, 80) : '',
      }));

    const hScroll = document.documentElement.scrollWidth > document.documentElement.clientWidth + 2;
    if (hScroll) issues.push('page-horizontal-scroll');
    if (overflow.length) issues.push('elements-overflow-x');
    const misalignedButtons = buttons.filter((item) => item.misalign);
    if (misalignedButtons.length) issues.push('icon-text-misalign');

    const empties = [...document.querySelectorAll('.arco-empty, .page-empty, .empty-state, .map-empty')].map((el) => {
      const rect = el.getBoundingClientRect();
      return {
        cls: typeof el.className === 'string' ? el.className.slice(0, 80) : el.tagName,
        height: Math.round(rect.height),
        width: Math.round(rect.width),
      };
    });

    return {
      path: location.pathname,
      title: document.title,
      issues,
      overflow: overflow.slice(0, 8),
      misalignedButtons: misalignedButtons.slice(0, 8),
      footerInfo,
      toolbarInfo,
      hScroll,
      eyesHints,
      empties,
      bodyPreview: (document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 240),
    };
  });

  await page.screenshot({ path: join(out, `${name}.png`), fullPage: true });
  report.pages.push({ name, path, status: res?.status(), ...metrics });
  if (metrics.issues.length) report.ok = false;
  console.log(JSON.stringify({
    name,
    status: res?.status(),
    issues: metrics.issues,
    footer: metrics.footerInfo,
    toolbar: metrics.toolbarInfo,
    overflowN: metrics.overflow.length,
    misalign: metrics.misalignedButtons.length,
  }));
}

try {
  await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded', timeout: 45_000 });
  if (token) {
    await page.evaluate((value) => localStorage.setItem('cheesewaf-token', value), token);
  }
  await audit('/login', 'login');
  await audit('/sites', 'sites');
  await audit('/users', 'users');
  await audit('/attack-map', 'attack-map');
  await audit('/system', 'system');
} catch (error) {
  report.ok = false;
  report.error = String(error?.stack || error);
  console.error(report.error);
  try {
    await page.screenshot({ path: join(out, 'error.png'), fullPage: true });
  } catch {
    // ignore
  }
} finally {
  writeFileSync(join(out, 'report.json'), JSON.stringify(report, null, 2));
  await browser.close();
}

process.exitCode = report.ok ? 0 : 1;
