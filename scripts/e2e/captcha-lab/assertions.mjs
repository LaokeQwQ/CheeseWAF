import { strict as assert } from 'node:assert';

export async function expectFailureReplacement(api, afterIssueIndex, failedToken, failedAt, config) {
  const replacement = await api.nextIssue(afterIssueIndex);
  const elapsed = replacement.recordedAt - failedAt;
  assert.ok(elapsed >= config.replacementDelayMs - 80, `replacement arrived too early: ${elapsed}ms`);
  assert.ok(elapsed <= config.replacementDelayMs + config.replacementToleranceMs, `replacement arrived too late: ${elapsed}ms`);
  const nextToken = replacement.body?.data?.token ?? replacement.body?.token;
  assert.ok(nextToken && nextToken !== failedToken, 'failure must issue a different token');
  return replacement;
}

export async function expectSuccessFrozen(page, api, issueCount, config) {
  const shell = await expectStatus(page, 'success');
  const sliders = shell.getByRole('slider');
  for (let index = 0; index < await sliders.count(); index += 1) {
    assert.equal(await sliders.nth(index).isDisabled(), true, 'range control must be disabled after success');
  }
  const surfaces = shell.locator('[aria-disabled]');
  for (let index = 0; index < await surfaces.count(); index += 1) {
    assert.equal(await surfaces.nth(index).getAttribute('aria-disabled'), 'true', 'surface control must be disabled after success');
  }
  const shellRefresh = shell.locator('button[title]').first();
  if (await shellRefresh.count()) assert.equal(await shellRefresh.isDisabled(), true, 'challenge refresh must be disabled after success');
  await page.waitForTimeout(config.replacementDelayMs + 250);
  assert.equal(api.issueCount(), issueCount, 'success must not auto-refresh the challenge');
}

export async function expectStatus(page, status) {
  const shell = page.locator(`section[data-status="${status}"]`).first();
  await shell.waitFor({ state: 'visible' });
  return shell;
}

export async function replayExpect410(replay, requestBody) {
  assert.ok(requestBody && typeof requestBody === 'object' && typeof requestBody.token === 'string', 'replay request was not captured');
  const outcome = await replay(requestBody);
  assert.equal(outcome.status, 410, 'replay status must be 410');
  assert.equal(outcome.code, 'CAPTCHA_ALREADY_USED', 'replay must return CAPTCHA_ALREADY_USED');
}
