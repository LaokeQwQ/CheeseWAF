import { monitorBrowser, responseMatches } from './browser-monitor.mjs';
import { dragWAFShape } from './interactions.mjs';

const VERIFY_PATH = '/.well-known/cheesewaf/challenge/v1/verify';
const PROTECTED_PATH = '/admin/protected';
const REPLACEMENT_MIN_MS = 850;
const REPLACEMENT_MAX_MS = 1_900;

export async function runWAFFlow({ page, context, profile, fixture, userAgent, timeoutMs }) {
  const monitor = monitorBrowser(page, {
    allowHTTPError: (response) => {
      const pathname = new URL(response.url()).pathname;
      return (pathname === PROTECTED_PATH && response.status() === 403)
        || (pathname === VERIFY_PATH && response.status() === 401);
    },
  });

  const firstDocument = await page.goto(`${fixture.wafURL}${PROTECTED_PATH}`, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
  assertCondition(firstDocument?.status() === 403, 'WAF protected resource did not issue a challenge');
  await assertWAFChallengeReady(page);
  const wrongPlan = await fixture.wafPlan({ user_agent: userAgent, variant: 'wrong' });

  await dragWAFShape(page, wrongPlan.x, wrongPlan.y, wrongPlan.duration_ms);
  const wrongVerifyPromise = page.waitForResponse(responseMatches(VERIFY_PATH, { method: 'POST', status: 401 }), { timeout: timeoutMs });
  await page.locator('#verify').click();
  await wrongVerifyPromise;
  const failedAt = Date.now();
  await page.locator('#status.bad').waitFor({ state: 'visible' });
  assertCondition(await page.locator('#verify').isDisabled(), 'failed WAF challenge did not freeze its controls');

  const replacementDocument = await page.waitForResponse(
    (response) => responseMatches(PROTECTED_PATH, { method: 'GET', status: 403 })(response) && response.request().resourceType() === 'document',
    { timeout: timeoutMs },
  );
  await replacementDocument.finished();
  const replacementDelay = Date.now() - failedAt;
  assertCondition(replacementDelay >= REPLACEMENT_MIN_MS && replacementDelay <= REPLACEMENT_MAX_MS, 'WAF challenge replacement delay is outside its contract');
  await assertWAFChallengeReady(page);
  const correctPlan = await fixture.wafPlan({ user_agent: userAgent, variant: 'correct' });
  assertCondition(correctPlan.generation > wrongPlan.generation, 'WAF challenge failure reused the consumed challenge');

  await dragWAFShape(page, correctPlan.x, correctPlan.y, correctPlan.duration_ms);
  const verifyRequestPromise = page.waitForRequest(
    (request) => new URL(request.url()).pathname === VERIFY_PATH && request.method() === 'POST',
    { timeout: timeoutMs },
  );
  const verifySuccessPromise = page.waitForResponse(
    responseMatches(VERIFY_PATH, { method: 'POST' }),
    { timeout: timeoutMs },
  );
  const protectedSuccessPromise = page.waitForResponse(
    (response) => responseMatches(PROTECTED_PATH, { method: 'GET' })(response) && response.request().resourceType() === 'document',
    { timeout: timeoutMs },
  );
  await page.locator('#verify').click();
  const [verifyRequest, verifySuccess] = await Promise.all([verifyRequestPromise, verifySuccessPromise]);
  const submitted = safePostData(verifyRequest);
  const protectedSuccess = await protectedSuccessPromise;
  if (verifySuccess.status() !== 200) {
    const point = submitted?.point;
    const track = Array.isArray(submitted?.track) ? submitted.track : [];
    const dx = Number.isFinite(point?.x) ? Number(point.x) - Number(correctPlan.x) : 'missing';
    const dy = Number.isFinite(point?.y) ? Number(point.y) - Number(correctPlan.y) : 'missing';
    const diagnosis = submitted ? await fixture.wafDiagnose({ user_agent: userAgent, response: submitted }) : { diagnosis: 'incomplete' };
    throw new Error(`WAF correct verification rejected: status=${verifySuccess.status()} diagnosis=${safeDiagnosis(diagnosis.diagnosis)} dx=${dx} dy=${dy} duration=${Number(submitted?.duration_ms) || 0} points=${track.length}`);
  }
  assertCondition(protectedSuccess.status() === 200, 'WAF clearance did not release the protected resource');
  await protectedSuccess.finished();
  const protectedPayload = JSON.parse(await page.locator('body').innerText());
  assertCondition(protectedPayload?.protected === true && protectedPayload?.challenge === 'passed', 'WAF clearance did not release the protected resource');

  const cookies = await context.cookies(fixture.wafURL);
  const clearance = cookies.find((cookie) => cookie.name === 'cw_integration_clearance');
  assertCondition(clearance?.httpOnly === true && clearance.value.length > 20, 'WAF clearance cookie was not issued as HttpOnly');
  assertCondition(monitor.count('POST', VERIFY_PATH) === 2, 'WAF challenge verification count was unexpected');
  monitor.assertClean(`${profile.name}/waf`);
}

function safeDiagnosis(value) {
  return ['binding_mismatch', 'incorrect', 'expired', 'invalid_response', 'invalid_token', 'proof_state', 'incomplete'].includes(value) ? value : 'unknown';
}

async function assertWAFChallengeReady(page) {
  await page.locator('#stage').waitFor({ state: 'visible' });
  await page.locator('#challenge-piece:not(.hidden)').waitFor({ state: 'visible' });
  await page.locator('#interaction-overlay').waitFor({ state: 'visible' });
  await page.locator('#verify:not([disabled])').waitFor({ state: 'visible' });
}

function assertCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function safePostData(request) {
  try {
    const parsed = request.postDataJSON();
    if (parsed && typeof parsed === 'object') return parsed;
  } catch {
    // Fall through to the raw request body.
  }
  try {
    return JSON.parse(request.postData() ?? '');
  } catch {
    return undefined;
  }
}
