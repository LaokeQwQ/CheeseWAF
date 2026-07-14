import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startIntegrationFixture } from './fixture-client.mjs';
import { runLoginFlow } from './login-flow.mjs';
import { loadChromium, startWebRuntime } from './runtime.mjs';
import { runWAFFlow } from './waf-flow.mjs';

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const TIMEOUT_MS = 30_000;
const HEADLESS = !process.argv.includes('--headed');
const PROFILE_FILTER = argumentValue('--profile');
const PROFILES = [
  {
    name: 'desktop', mobile: false, viewport: { width: 1366, height: 900 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36 captcha-e2e/desktop',
  },
  {
    name: 'mobile', mobile: true, viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
    userAgent: 'Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36 captcha-e2e/mobile',
  },
].filter((profile) => !PROFILE_FILTER || profile.name === PROFILE_FILTER);

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('Usage: node scripts/e2e/captcha-integration/run.mjs [--headed] [--profile desktop|mobile]');
  process.exit(0);
}
if (PROFILE_FILTER && PROFILES.length === 0) throw new Error('Unknown CAPTCHA integration profile');

let fixture;
let webRuntime;
let browser;
let failures = 0;
try {
  fixture = await startIntegrationFixture({ projectRoot: PROJECT_ROOT });
  webRuntime = await startWebRuntime({ projectRoot: PROJECT_ROOT, apiTarget: fixture.adminURL });
  const chromium = await loadChromium(PROJECT_ROOT);
  browser = await chromium.launch({ headless: HEADLESS });

  for (const profile of PROFILES) {
    const context = await browser.newContext({
      viewport: profile.viewport,
      deviceScaleFactor: profile.deviceScaleFactor,
      isMobile: profile.isMobile,
      hasTouch: profile.hasTouch,
      userAgent: profile.userAgent,
      locale: 'en-US',
      colorScheme: 'light',
    });
    const page = await context.newPage();
    page.setDefaultTimeout(TIMEOUT_MS);
    let phase = 'login';
    try {
      await runLoginFlow({
        page, context, profile, fixture, webBaseURL: webRuntime.baseURL,
        userAgent: profile.userAgent, timeoutMs: TIMEOUT_MS,
      });
      console.log(`PASS ${profile.name}/login`);
      phase = 'waf';
      await runWAFFlow({ page, context, profile, fixture, userAgent: profile.userAgent, timeoutMs: TIMEOUT_MS });
      console.log(`PASS ${profile.name}/waf`);
    } catch (error) {
      failures += 1;
      console.error(`FAIL ${profile.name}/${phase}/${safeStage(error)}`);
      if (process.env.CAPTCHA_E2E_DEBUG === '1') console.error(safeErrorMessage(error));
    } finally {
      await context.close();
    }
  }
} finally {
  if (browser) await browser.close();
  if (webRuntime) await webRuntime.close();
  if (fixture) await fixture.close();
}

if (failures > 0) process.exitCode = 1;

function argumentValue(name) {
  const inline = process.argv.find((argument) => argument.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function safeStage(error) {
  const message = error instanceof Error ? error.message : String(error);
  if (/login/i.test(message)) return 'login';
  if (/WAF|protected|clearance/i.test(message)) return 'waf';
  if (/fixture/i.test(message)) return 'fixture';
  if (/timed out|Timeout/i.test(message)) return 'timeout';
  return 'integration';
}

function safeErrorMessage(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/https?:\/\/[^\s)]+/gi, '<url>')
    .replace(/[A-Za-z0-9_-]{80,}/g, '<opaque>')
    .replace(/\b(?:password|token|cookie|receipt|secret|credential)\b[^\n]*/gi, '<redacted>');
}
