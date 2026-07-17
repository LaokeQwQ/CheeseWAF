import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_SCENARIOS = ['curve_draw', 'curve_slider', 'shape_slider', 'rotate', 'restore_slider', 'angle', 'scratch', 'text_click', 'icon_click'];
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

export async function loadConfig(argv = process.argv.slice(2), env = process.env) {
  const cli = parseArgs(argv);
  const fileConfig = cli.config ? JSON.parse(await readFile(path.resolve(cli.config), 'utf8')) : {};
  const baseURL = cli.baseURL ?? env.CAPTCHA_E2E_BASE_URL ?? fileConfig.baseURL;
  const token = cli.token ?? env.CAPTCHA_E2E_TOKEN ?? fileConfig.token;
  if (!baseURL) throw new Error('Missing baseURL. Use --base-url, CAPTCHA_E2E_BASE_URL, or a config file.');
  if (!token) throw new Error('Missing token. Use --token, CAPTCHA_E2E_TOKEN, or a config file.');
  const projectRoot = path.resolve(fileConfig.projectRoot ?? PROJECT_ROOT);
  return {
    baseURL: new URL(baseURL).toString().replace(/\/$/, ''), token,
    labPath: cli.labPath ?? fileConfig.labPath ?? '/captcha-lab',
    issuePath: fileConfig.issuePath ?? '/api/captcha/lab/challenges', verifyPath: fileConfig.verifyPath ?? '/api/captcha/lab/verify',
    headless: cli.headed ? false : fileConfig.headless ?? true,
    artifactsDir: path.resolve(projectRoot, fileConfig.artifactsDir ?? 'output/playwright/captcha-lab'),
    timeoutMs: Number(fileConfig.timeoutMs ?? 20_000), replacementDelayMs: Number(fileConfig.replacementDelayMs ?? 1_000), replacementToleranceMs: Number(fileConfig.replacementToleranceMs ?? 650),
    profiles: fileConfig.profiles ?? [{ name: 'desktop', viewport: { width: 1440, height: 960 }, isMobile: false }, { name: 'mobile', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }],
    themes: fileConfig.themes ?? ['light', 'dark'], locales: fileConfig.locales ?? ['zh-CN', 'en-US'],
    reducedMotions: fileConfig.reducedMotions ?? ['no-preference', 'reduce'],
    scenarios: normalizeScenarios(cli.scenarios ?? fileConfig.scenarios ?? DEFAULT_SCENARIOS), dryRun: cli.dryRun === true,
    projectRoot,
    fixedHarness: fileConfig.fixedHarness ?? true,
    fixedHarnessTimeoutMs: Number(fileConfig.fixedHarnessTimeoutMs ?? 60_000),
    browserHarnessTimeoutMs: Number(fileConfig.browserHarnessTimeoutMs ?? 60_000),
  };
}

function normalizeScenarios(value) { const entries = Array.isArray(value) ? value : String(value).split(','); return entries.map((entry) => typeof entry === 'string' ? { type: entry.trim() } : entry).filter((entry) => entry.type); }
function parseArgs(argv) { const result = {}; for (let i = 0; i < argv.length; i += 1) { const arg = argv[i]; if (arg === '--headed') { result.headed = true; continue; } if (arg === '--dry-run') { result.dryRun = true; continue; } const [key, inline] = arg.split('=', 2); const value = inline ?? argv[++i]; if (key === '--config') result.config = value; else if (key === '--base-url') result.baseURL = value; else if (key === '--token') result.token = value; else if (key === '--lab-path') result.labPath = value; else if (key === '--scenarios') result.scenarios = value; else throw new Error(`Unknown argument: ${arg}`); } return result; }
