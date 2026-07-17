import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  CAPTCHA_LAB_CONFIG,
  CAPTCHA_LAB_SCENARIOS,
  replayCaptchaLabRequest,
  runCaptchaLabScenario,
} from './captcha-lab-flow.mjs';

test('real Handler flow is exactly nine non-PoW desktop scenarios', () => {
  assert.deepEqual(CAPTCHA_LAB_SCENARIOS, [
    'curve_draw', 'curve_slider', 'shape_slider', 'rotate', 'restore_slider',
    'angle', 'scratch', 'text_click', 'icon_click',
  ]);
  assert.equal(CAPTCHA_LAB_CONFIG.replacementDelayMs, 1_000);
  assert.equal(CAPTCHA_LAB_CONFIG.successFreezeMs, 1_250);
});

test('scenario orchestration keeps plans private and reuses lifecycle helpers', async () => {
  const calls = [];
  const first = challenge('token-a', 'rotate');
  const second = challenge('token-b', 'rotate');
  const failed = { status: 200, body: { data: { valid: false } }, request: { token: first.token }, recordedAt: 100 };
  const succeeded = { status: 200, body: { data: { valid: true } }, request: { token: second.token }, recordedAt: 1_200 };
  const issues = [{ body: { data: first } }, { body: { data: second }, recordedAt: 1_100 }];
  const verifies = [failed, succeeded];
  let verifyCount = 0;
  const api = {
    issueCount: () => 0,
    verifyCount: () => verifyCount,
    nextIssue: async (index) => issues[index],
    nextVerify: async (index) => {
      verifyCount = Math.max(verifyCount, index + 1);
      return verifies[index];
    },
  };
  const fixture = {
    async labPlan(input) {
      calls.push(['plan', input.challenge.token, input.variant]);
      return { interaction: 'range', action: { value: input.variant === 'wrong' ? 9000 : 4321 } };
    },
  };
  const helpers = {
    selectScenario: async (_page, type) => calls.push(['select', type]),
    solveScenario: async (_page, issued, plan) => calls.push(['solve', issued.token, plan.action.value]),
    expectStatus: async (_page, status) => calls.push(['status', status]),
    replayExpect410: async (replay, body) => {
      calls.push(['replay', body.token]);
      await replay(body);
    },
    expectFailureReplacement: async () => issues[1],
    expectSuccessFrozen: async () => calls.push(['freeze']),
    unwrapData: (record) => record?.body?.data ?? record?.body,
  };
  await runCaptchaLabScenario({
    page: {}, api, fixture, config: CAPTCHA_LAB_CONFIG, scenario: { type: 'rotate' },
    replay: async (body) => ({ status: 410, code: body.token === first.token || body.token === second.token ? 'CAPTCHA_ALREADY_USED' : 'bad' }),
  }, helpers);
  assert.deepEqual(calls, [
    ['select', 'rotate'],
    ['plan', 'token-a', 'wrong'],
    ['solve', 'token-a', 9000],
    ['status', 'failure'],
    ['replay', 'token-a'],
    ['plan', 'token-b', 'correct'],
    ['solve', 'token-b', 4321],
    ['replay', 'token-b'],
    ['freeze'],
  ]);
});

test('Node replay uses the real administrator bearer and verify endpoint', async () => {
  let observed;
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed = {
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
    };
    response.writeHead(410, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: { code: 'CAPTCHA_ALREADY_USED' } }));
  });
  await listen(server);
  const address = server.address();
  try {
    const result = await replayCaptchaLabRequest({
      adminURL: `http://127.0.0.1:${address.port}`,
      bearerToken: 'real-session-token',
      requestBody: { token: 'sealed-token', duration_ms: 200 },
    });
    assert.deepEqual(result, { status: 410, code: 'CAPTCHA_ALREADY_USED' });
    assert.deepEqual(observed, {
      method: 'POST',
      url: '/api/captcha/lab/verify',
      authorization: 'Bearer real-session-token',
      body: { token: 'sealed-token', duration_ms: 200 },
    });
  } finally {
    await close(server);
  }
});

test('browser flow source has no answer bridge or request interception', async () => {
  const source = await readFile(fileURLToPath(new URL('./captcha-lab-flow.mjs', import.meta.url)), 'utf8');
  for (const forbidden of ['page.route', 'page.evaluate', 'addInitScript', 'localStorage', 'exposeBinding']) {
    assert.equal(source.includes(forbidden), false, `browser flow contains ${forbidden}`);
  }
});

test('npm CAPTCHA E2E gate runs the nine-scenario real Router CLI', async () => {
  const packageJSON = JSON.parse(await readFile(fileURLToPath(new URL('../../../web/package.json', import.meta.url)), 'utf8'));
  const command = packageJSON.scripts?.['e2e:captcha'];
  assert.equal(typeof command, 'string');
  const integrationCLI = 'node ../scripts/e2e/captcha-integration/run.mjs --profile desktop';
  assert.equal(command.split(integrationCLI).length - 1, 1, 'real Router CLI must run exactly once');
});

function challenge(token, type) {
  return { token, type, expires_at: '2030-01-01T00:00:00Z', presentation: {} };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
