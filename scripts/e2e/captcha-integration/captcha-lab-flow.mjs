import { strict as assert } from 'node:assert';
import { observeBrowser } from '../captcha-lab/browser-events.mjs';
import { observeCaptchaAPI, unwrapData } from '../captcha-lab/api-observer.mjs';
import {
  expectFailureReplacement,
  expectStatus,
  expectSuccessFrozen,
  replayExpect410,
} from '../captcha-lab/assertions.mjs';
import { selectScenario } from '../captcha-lab/lab-page.mjs';
import { solveScenario } from '../captcha-lab/interactions/index.mjs';

export const CAPTCHA_LAB_SCENARIOS = Object.freeze([
  'curve_draw',
  'curve_slider',
  'shape_slider',
  'rotate',
  'restore_slider',
  'angle',
  'scratch',
  'text_click',
  'icon_click',
]);

export const CAPTCHA_LAB_CONFIG = Object.freeze({
  issuePath: '/api/captcha/lab/challenges',
  verifyPath: '/api/captcha/lab/verify',
  timeoutMs: 30_000,
  replacementDelayMs: 1_000,
  replacementToleranceMs: 650,
  successFreezeMs: 1_250,
});

const scenarioHelpers = {
  selectScenario,
  solveScenario,
  expectFailureReplacement,
  expectStatus,
  expectSuccessFrozen,
  replayExpect410,
  unwrapData,
};

export async function runCaptchaLabFlow({ page, fixture, webBaseURL, bearerToken, timeoutMs = CAPTCHA_LAB_CONFIG.timeoutMs }) {
  if (!page || !fixture?.labPlan || !webBaseURL || !bearerToken) {
    throw new Error('CAPTCHA Lab integration inputs are incomplete');
  }
  const config = { ...CAPTCHA_LAB_CONFIG, timeoutMs };
  const browser = observeBrowser(page, config);
  const api = observeCaptchaAPI(page, config);
  const replay = (requestBody) => replayCaptchaLabRequest({
    adminURL: fixture.adminURL,
    bearerToken,
    requestBody,
  });

  await page.goto(new URL('/captcha-lab', webBaseURL).toString(), { waitUntil: 'domcontentloaded', timeout: timeoutMs });
  await page.locator('#captcha-lab-title').waitFor({ state: 'visible', timeout: timeoutMs });
  await api.nextIssue(0);

  for (const type of CAPTCHA_LAB_SCENARIOS) {
    await runCaptchaLabScenario({ page, api, fixture, config, scenario: { type }, replay });
    console.log(`PASS desktop/light/en-US/motion=no-preference/${type}/real-handler`);
  }
  browser.assertClean('desktop/light/en-US/motion=no-preference/real-handler');
  return { scenarios: CAPTCHA_LAB_SCENARIOS.length };
}

export async function runCaptchaLabScenario({ page, api, fixture, config, scenario, replay }, helpers = scenarioHelpers) {
  const issueIndex = api.issueCount();
  const verifyIndex = api.verifyCount();
  await stage('select', () => helpers.selectScenario(page, scenario.type));
  const firstRecord = await stage('wrong_issue', () => api.nextIssue(issueIndex));
  const first = helpers.unwrapData(firstRecord);
  assertChallenge(first, scenario.type);
  const wrongPlan = await stage('wrong_plan', () => fixture.labPlan({ challenge: first, variant: 'wrong' }));
  await stage('wrong_interaction', () => helpers.solveScenario(page, first, wrongPlan));
  const failed = await stage('wrong_verify', () => api.nextVerify(verifyIndex));
  if (failed.status !== 200 || helpers.unwrapData(failed)?.valid !== false) throw new ScenarioFailure('wrong_result');
  await stage('failure_state', () => helpers.expectStatus(page, 'failure'));
  await stage('wrong_replay', () => helpers.replayExpect410(replay, failed.request));

  const replacement = await stage('replacement', () => helpers.expectFailureReplacement(api, issueIndex + 1, first.token, failed.recordedAt, config));
  const second = helpers.unwrapData(replacement);
  assertChallenge(second, scenario.type);
  const successIndex = api.verifyCount();
  const correctPlan = await stage('correct_plan', () => fixture.labPlan({ challenge: second, variant: 'correct' }));
  await stage('correct_interaction', () => helpers.solveScenario(page, second, correctPlan));
  const succeeded = await stage('correct_verify', () => api.nextVerify(successIndex));
  if (succeeded.status !== 200 || helpers.unwrapData(succeeded)?.valid !== true) throw new ScenarioFailure('correct_result');
  await stage('correct_replay', () => helpers.replayExpect410(replay, succeeded.request));
  await stage('success_freeze', () => helpers.expectSuccessFrozen(page, api, api.issueCount(), config));
}

export async function replayCaptchaLabRequest({ adminURL, bearerToken, requestBody }) {
  if (!adminURL || !bearerToken || !requestBody || typeof requestBody !== 'object') {
    throw new Error('CAPTCHA Lab replay inputs are incomplete');
  }
  const response = await fetch(new URL(CAPTCHA_LAB_CONFIG.verifyPath, adminURL), {
    method: 'POST',
    headers: {
      authorization: `Bearer ${bearerToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });
  let body;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return { status: response.status, code: body?.error?.code ?? body?.code };
}

class ScenarioFailure extends Error {
  constructor(stageName) {
    super(`CAPTCHA Lab real Handler stage failed: ${stageName}`);
    this.stageName = stageName;
  }
}

async function stage(stageName, work) {
  try {
    return await work();
  } catch (error) {
    if (error instanceof ScenarioFailure) throw error;
    throw new ScenarioFailure(stageName);
  }
}

function assertChallenge(challenge, expectedType) {
  if (!challenge || challenge.type !== expectedType || typeof challenge.token !== 'string' || !challenge.token) {
    throw new ScenarioFailure('challenge_shape');
  }
}
