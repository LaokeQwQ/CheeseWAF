import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareLab } from './lab-page.mjs';

test('prepareLab seeds the persisted application language and theme', async () => {
  const values = new Map();
  const previousStorage = globalThis.localStorage;
  globalThis.localStorage = { setItem: (key, value) => values.set(key, value) };
  let navigated;
  const page = {
    async addInitScript(script, input) { script(input); },
    async goto(url) { navigated = url; },
    locator(selector) {
      assert.equal(selector, '#captcha-lab-title');
      return { waitFor: async () => {} };
    },
  };
  try {
    await prepareLab(page, {
      baseURL: 'http://127.0.0.1:4173',
      labPath: '/captcha-lab',
      token: 'test-session',
    }, { locale: 'en-US', theme: 'dark' });
  } finally {
    globalThis.localStorage = previousStorage;
  }
  assert.equal(navigated, 'http://127.0.0.1:4173/captcha-lab');
  assert.equal(values.get('cheesewaf-token'), 'test-session');
  assert.equal(values.get('i18nextLng'), 'en-US');
  assert.deepEqual(JSON.parse(values.get('cheesewaf-ui')), {
    state: { language: 'en-US', sidebarCollapsed: false, theme: 'dark' },
    version: 0,
  });
  assert.equal(values.has('cheesewaf-language'), false);
  assert.equal(values.has('cheesewaf-theme'), false);
});
