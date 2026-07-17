import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';
import { loadConfig } from './config.mjs';
import { observeBrowser } from './browser-events.mjs';
import { observeCaptchaAPI, unwrapData } from './api-observer.mjs';
import { expectFailureReplacement, expectStatus, expectSuccessFrozen, replayExpect410 } from './assertions.mjs';
import { prepareLab, selectScenario } from './lab-page.mjs';
import { solveScenario } from './interactions/index.mjs';
import { runFixedHarness } from './fixed-harness.mjs';
import { startPrivateHarness } from './private-harness.mjs';
import { attachPrivateFixture } from './private-fixture.mjs';

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('Usage: npm run e2e:captcha -- [--config FILE] [--base-url URL] [--token TOKEN] [--scenarios LIST] [--headed] [--dry-run]');
  process.exit(0);
}

const config = await loadConfig();
if (config.dryRun) {
  console.log(JSON.stringify({ baseURL: config.baseURL, labPath: config.labPath, profiles: config.profiles.map((item) => item.name), themes: config.themes, locales: config.locales, reducedMotions: config.reducedMotions, scenarios: config.scenarios }, null, 2));
  process.exit(0);
}
if (config.fixedHarness) {
  const fixed = await runFixedHarness({ cwd: config.projectRoot, timeoutMs: config.fixedHarnessTimeoutMs });
  console.log('PASS fixed-harness/' + fixed.map((item) => item.type).join(','));
}

await mkdir(config.artifactsDir, { recursive: true });
const privateHarness = await startPrivateHarness({ cwd: config.projectRoot, timeoutMs: config.browserHarnessTimeoutMs });
let browser;
let failures = 0;
try {
  browser = await chromium.launch({ headless: config.headless });
  for (const profile of config.profiles) for (const theme of config.themes) for (const locale of config.locales) for (const reducedMotion of config.reducedMotions) {
    const context = await browser.newContext({ ...profile, locale, colorScheme: theme, reducedMotion });
    const page = await context.newPage();
    let fixture;
    try {
      fixture = await attachPrivateFixture(page, privateHarness, config);
      const events = observeBrowser(page, config);
      const api = observeCaptchaAPI(page, config);
      await prepareLab(page, config, { locale, theme });
      await api.nextIssue(0);
      for (const scenario of config.scenarios) {
        const label = [profile.name, theme, locale, `motion=${reducedMotion}`, scenario.type].join('/');
        try {
          await runScenario({ page, api, fixture, config, scenario });
          console.log('PASS ' + label);
        } catch (error) {
          failures += 1;
          await captureRedactedFailure(page, path.join(config.artifactsDir, safe(label) + '-failure.png'));
          console.error(`FAIL ${label} stage=${failureStage(error)}`);
        }
      }
      events.assertClean([profile.name, theme, locale, `motion=${reducedMotion}`].join('/'));
    } finally {
      await fixture?.detach().catch(() => {});
      await context.close();
    }
  }
} finally {
  await browser?.close();
  await privateHarness.close();
}
if (failures) process.exitCode = 1;

async function runScenario({ page, api, fixture, config, scenario }) {
  const issueIndex = api.issueCount();
  const verifyIndex = api.verifyCount();
  await stage('select', () => selectScenario(page, scenario.type));
  const firstRecord = await stage('wrong_issue', () => api.nextIssue(issueIndex));
  const first = unwrapData(firstRecord);
  await stage('wrong_interaction', () => solveScenario(page, first, fixture.actionFor(first, 'wrong')));
  const failed = await stage('wrong_verify', () => api.nextVerify(verifyIndex));
  if (failed.status !== 200 || unwrapData(failed)?.valid !== false) throw new ScenarioFailure('wrong_result');
  await stage('failure_state', () => expectStatus(page, 'failure'));
  await stage('wrong_replay', () => replayExpect410(fixture.replay, failed.request));
  const replacement = await stage('replacement', () => expectFailureReplacement(api, issueIndex + 1, first.token, failed.recordedAt, config));
  const replacementChallenge = unwrapData(replacement);
  const successIndex = api.verifyCount();
  await stage('correct_interaction', () => solveScenario(page, replacementChallenge, fixture.actionFor(replacementChallenge, 'correct')));
  const success = await stage('correct_verify', () => api.nextVerify(successIndex));
  if (success.status !== 200 || unwrapData(success)?.valid !== true) throw new ScenarioFailure('correct_result');
  await stage('correct_replay', () => replayExpect410(fixture.replay, success.request));
  await stage('success_freeze', () => expectSuccessFrozen(page, api, api.issueCount(), config));
}

class ScenarioFailure extends Error {
  constructor(stageName) {
    super(`CAPTCHA browser stage failed: ${stageName}`);
    this.stageName = stageName;
  }
}

async function stage(stageName, work) {
  try {
    return await work();
  } catch {
    throw new ScenarioFailure(stageName);
  }
}

function failureStage(error) {
  return /^[a-z_]{1,40}$/.test(error?.stageName ?? '') ? error.stageName : 'runner';
}

async function captureRedactedFailure(page, outputPath) {
  const shell = page.locator('section[data-status]');
  await page.screenshot({ path: outputPath, fullPage: true, mask: [shell], maskColor: '#111827', animations: 'disabled' }).catch(() => {});
}

function safe(value) {
  return value.replace(/[^a-z0-9._-]+/gi, '-');
}
