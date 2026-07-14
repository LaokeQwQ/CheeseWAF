import { monitorBrowser, responseData, responseMatches } from './browser-monitor.mjs';
import { dragLoginSlider } from './interactions.mjs';

const LOGIN_ISSUE_PATH = '/api/auth/captcha';
const LOGIN_VERIFY_PATH = '/api/auth/captcha/verify';
const LOGIN_PATH = '/api/auth/login';
const REPLACEMENT_MIN_MS = 850;
const REPLACEMENT_MAX_MS = 1_900;

export async function runLoginFlow({ page, context, profile, fixture, webBaseURL, userAgent, timeoutMs }) {
  const monitor = monitorBrowser(page, {
    allowHTTPError: (response) => new URL(response.url()).pathname === LOGIN_VERIFY_PATH && response.status() === 401,
  });
  await page.goto(`${webBaseURL}/login`, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
  const firstIssuePromise = waitForAPI(page, LOGIN_ISSUE_PATH, 200, timeoutMs, 'initial issue');
  await page.locator('input[autocomplete="username"]').fill(fixture.username);
  await page.locator('input[autocomplete="current-password"]').fill(fixture.password);
  const firstIssue = await firstIssuePromise;

  if (profile.mobile) {
    await runMobileLogin({ page, issue: firstIssue, timeoutMs });
  } else {
    await runDesktopLogin({ page, context, fixture, userAgent, monitor, timeoutMs, firstIssue });
  }

  const storedToken = await page.evaluate(() => localStorage.getItem('cheesewaf-token'));
  assertCondition(typeof storedToken === 'string' && storedToken.length > 20, 'login did not persist an authenticated session');
  monitor.assertClean(`${profile.name}/login`);
}

async function runDesktopLogin({ page, context, fixture, userAgent, monitor, timeoutMs, firstIssue }) {
  const firstChallenge = loginSlider(await responseData(firstIssue));
  await page.locator('.auth-captcha-gate.auth-captcha-state-ready').click();
  await page.locator('.auth-captcha-widget').waitFor({ state: 'visible' });

  const verifyCountBeforeClose = monitor.count('POST', LOGIN_VERIFY_PATH);
  await page.locator('.auth-captcha-widget-foot button').last().click();
  await page.locator('.auth-captcha-widget').waitFor({ state: 'hidden' });
  assertCondition(monitor.count('POST', LOGIN_VERIFY_PATH) === verifyCountBeforeClose, 'closing login CAPTCHA submitted a verification');

  const reopenedIssuePromise = waitForAPI(page, LOGIN_ISSUE_PATH, 200, timeoutMs, 'reopen issue');
  await page.locator('.auth-captcha-gate.auth-captcha-state-ready').click();
  const reopenedIssue = await reopenedIssuePromise;
  const wrongChallenge = loginSlider(await responseData(reopenedIssue));
  assertCondition(wrongChallenge.token !== firstChallenge.token, 'closing login CAPTCHA did not discard the challenge');
  await page.locator('.auth-slider-thumb[role="slider"]').waitFor({ state: 'visible' });

  const clientCookie = await loginClientCookie(context, fixture.adminURL);
  const wrongPlan = await fixture.loginPlan({
    token: wrongChallenge.token,
    cookie: clientCookie.value,
    user_agent: userAgent,
    variant: 'wrong',
  });
  const wrongResponsePromise = waitForAPI(page, LOGIN_VERIFY_PATH, undefined, timeoutMs, 'wrong verification');
  await dragLoginSlider(page, wrongPlan.x, wrongChallenge.track_width, wrongPlan.duration_ms);
  const wrongResponse = await wrongResponsePromise;
  const failedAt = Date.now();
  assertCondition(wrongResponse.status() === 401, 'login CAPTCHA wrong answer was accepted');
  await page.locator('.auth-captcha-widget.auth-captcha-state-invalid').waitFor({ state: 'visible' });

  const replacementResponse = await waitForAPI(page, LOGIN_ISSUE_PATH, 200, timeoutMs, 'replacement issue');
  const replacementDelay = Date.now() - failedAt;
  assertCondition(replacementDelay >= REPLACEMENT_MIN_MS && replacementDelay <= REPLACEMENT_MAX_MS, 'login CAPTCHA replacement delay is outside its contract');
  const correctChallenge = loginSlider(await responseData(replacementResponse));
  assertCondition(correctChallenge.token !== wrongChallenge.token, 'login CAPTCHA failure reused the consumed challenge');
  await page.locator('.auth-captcha-widget.auth-captcha-state-ready').waitFor({ state: 'visible', timeout: timeoutMs });
  await page.locator('.auth-slider-thumb[role="slider"]').waitFor({ state: 'visible' });

  const refreshedCookie = await loginClientCookie(context, fixture.adminURL);
  const correctPlan = await fixture.loginPlan({
    token: correctChallenge.token,
    cookie: refreshedCookie.value,
    user_agent: userAgent,
    variant: 'correct',
  });
  const verifySuccessPromise = waitForAPI(page, LOGIN_VERIFY_PATH, undefined, timeoutMs, 'successful verification');
  await dragLoginSlider(page, correctPlan.x, correctChallenge.track_width, correctPlan.duration_ms);
  const verifySuccess = await verifySuccessPromise;
  if (verifySuccess.status() !== 200) {
    const submitted = safePostData(verifySuccess.request())?.slider;
    if (!submitted || typeof submitted.track !== 'string') throw new Error('login slider physical track was incomplete');
    if (submitted.token !== correctChallenge.token) throw new Error('login CAPTCHA DOM did not activate the replacement challenge');
    if (Math.abs(Number(submitted.x) - Number(correctPlan.x)) > Number(correctChallenge.tolerance ?? 6)) {
      throw new Error('login slider physical target drifted outside tolerance');
    }
    let points;
    try {
      points = JSON.parse(submitted.track);
    } catch {
      throw new Error('login slider physical track was malformed');
    }
    if (!Array.isArray(points) || points.length < 3) throw new Error('login slider physical track was incomplete');
    const diagnosis = await fixture.loginDiagnose({
      token: submitted.token,
      cookie: refreshedCookie.value,
      user_agent: userAgent,
      x: submitted.x,
      drag_ms: submitted.drag_ms,
      track: submitted.track,
    });
    throw new Error(`login slider rejection category: ${safeDiagnosis(diagnosis.diagnosis)}`);
  }
  const verification = await responseData(verifySuccess);
  assertCondition(verification.valid === true && typeof verification.receipt === 'string' && verification.receipt.length > 20, 'login CAPTCHA did not issue a receipt');
  await page.locator('.auth-captcha-widget.auth-captcha-state-verified').waitFor({ state: 'visible' });
  await page.locator('.auth-slider-success[role="status"]').waitFor({ state: 'visible' });
  assertCondition(await page.locator('.auth-slider-thumb[role="slider"]').count() === 0, 'verified login CAPTCHA remained interactive');
  assertCondition(await page.locator('.auth-captcha-gate.auth-captcha-state-verified').isDisabled(), 'verified login CAPTCHA gate was not frozen');

  await page.locator('.auth-captcha-widget').waitFor({ state: 'hidden', timeout: timeoutMs });
  const loginResponsePromise = waitForAPI(page, LOGIN_PATH, 200, timeoutMs, 'receipt login');
  await page.getByRole('button', { name: /sign in|log in|登录/i }).click();
  const loginResponse = await loginResponsePromise;
  const loginResult = await responseData(loginResponse);
  assertCondition(typeof loginResult.token === 'string' && loginResult.token.length > 20, 'receipt-backed login did not return a session');
}

async function runMobileLogin({ page, issue, timeoutMs }) {
  const challenge = await responseData(issue);
  assertCondition(challenge.mode === 'pow' && challenge.challenge?.signature, 'mobile login did not select the PoW fallback');
  await page.locator('.auth-captcha-gate.auth-captcha-state-verified').waitFor({ state: 'visible', timeout: timeoutMs });
  assertCondition(await page.locator('.auth-captcha-gate.auth-captcha-state-verified').isDisabled(), 'mobile login CAPTCHA gate was not frozen');
  const loginResponsePromise = waitForAPI(page, LOGIN_PATH, 200, timeoutMs, 'mobile login');
  await page.getByRole('button', { name: /sign in|log in|登录/i }).click();
  const loginResponse = await loginResponsePromise;
  const result = await responseData(loginResponse);
  assertCondition(typeof result.token === 'string' && result.token.length > 20, 'mobile PoW login did not return a session');
}

function loginSlider(payload) {
  const slider = payload?.slider;
  if (!slider || typeof slider.token !== 'string' || slider.token.length < 20 || !Number.isFinite(slider.track_width)) {
    throw new Error('login CAPTCHA issue response did not contain a usable slider');
  }
  return slider;
}

async function loginClientCookie(context, url) {
  const cookies = await context.cookies(url);
  const cookie = cookies.find((item) => item.name === 'cw_captcha_client');
  if (!cookie?.value) throw new Error('login CAPTCHA client binding cookie is missing');
  return cookie;
}

function assertCondition(condition, message) {
  if (!condition) throw new Error(message);
}

async function waitForAPI(page, pathname, status, timeoutMs, label) {
  try {
    return await page.waitForResponse(responseMatches(pathname, { method: 'POST', status }), { timeout: timeoutMs });
  } catch {
    throw new Error(`login ${label} timed out`);
  }
}

function safePostData(request) {
  try {
    return request.postDataJSON();
  } catch {
    return undefined;
  }
}

function safeDiagnosis(value) {
  return ['binding', 'target', 'timing', 'track', 'proof_state'].includes(value) ? value : 'unknown';
}
