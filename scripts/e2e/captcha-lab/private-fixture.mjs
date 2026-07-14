import { publicIssuePayload, publicVerifyPayload } from './private-harness.mjs';

export async function attachPrivateFixture(page, harness, config) {
  const matcher = (url) => {
    const pathname = new URL(url).pathname;
    return pathname === config.issuePath || pathname === config.verifyPath;
  };
  const handler = async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    try {
      if (pathname === config.issuePath) {
        const request = parseBody(route.request().postData());
        const challenge = await harness.issue(request.type);
        await fulfillJSON(route, 200, publicIssuePayload(challenge));
        return;
      }
      const response = parseBody(route.request().postData());
      const outcome = await harness.verify(response);
      await fulfillJSON(route, outcome.status, publicVerifyPayload(outcome));
    } catch {
      await fulfillJSON(route, 500, { error: { code: 'CAPTCHA_FIXTURE_FAILED', message: 'CAPTCHA fixture request failed' } });
    }
  };
  await page.route(matcher, handler);
  return {
    actionFor: (challenge, variant) => harness.actionFor(challenge, variant),
    replay: (request) => harness.verify(request),
    detach: () => page.unroute(matcher, handler),
  };
}

function parseBody(raw) {
  if (!raw) throw new Error('CAPTCHA fixture request body is missing');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('CAPTCHA fixture request body is invalid');
  return parsed;
}

function fulfillJSON(route, status, body) {
  return route.fulfill({
    status,
    contentType: 'application/json; charset=utf-8',
    headers: { 'Cache-Control': 'no-store' },
    body: JSON.stringify(body),
  });
}
