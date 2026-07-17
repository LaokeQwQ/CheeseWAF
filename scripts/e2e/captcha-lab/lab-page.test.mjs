import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from './config.mjs';
import { prepareLab } from './lab-page.mjs';

test('captcha lab defaults to both normal and reduced motion', async () => {
  const config = await loadConfig([
    '--base-url', 'http://127.0.0.1:4173',
    '--token', 'test-session',
  ], {});
  assert.deepEqual(config.reducedMotions, ['no-preference', 'reduce']);
});

test('prepareLab seeds the persisted application language and theme', async () => {
  const values = new Map();
  const previousStorage = globalThis.localStorage;
  globalThis.localStorage = { setItem: (key, value) => values.set(key, value) };
  let navigated;
  const page = {
    async addInitScript(script, input) { script(input); },
    async goto(url) { navigated = url; },
    async waitForFunction() {},
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

test('prepareLab verifies the navigated page theme, language, and visible localized title', async (t) => {
  const cases = [
    {
      locale: 'zh-CN',
      theme: 'blackGold',
      expected: { theme: 'black-gold', lang: 'zh-CN', title: '\u4eba\u673a\u9a8c\u8bc1\u5b9e\u9a8c\u5ba4' },
    },
    {
      locale: 'en-US',
      theme: 'blueWhite',
      expected: { theme: 'blue-white', lang: 'en', title: 'Captcha Lab' },
    },
  ];

  for (const item of cases) await t.test(`${item.locale}/${item.theme}`, async () => {
    let navigated = false;
    let assertionRuns = 0;
    const page = {
      async addInitScript() {},
      async goto() { navigated = true; },
      locator(selector) {
        assert.equal(selector, '#captcha-lab-title');
        return { waitFor: async () => {} };
      },
      async waitForFunction(predicate, expected) {
        assert.equal(navigated, true, 'DOM assertions must run after navigation');
        assert.deepEqual(expected, item.expected);
        assert.equal(evaluateReadiness(predicate, expected, { ...expected, visible: true }), true);
        assert.equal(evaluateReadiness(predicate, expected, { ...expected, theme: 'light', visible: true }), false);
        assert.equal(evaluateReadiness(predicate, expected, { ...expected, lang: 'fr', visible: true }), false);
        assert.equal(evaluateReadiness(predicate, expected, { ...expected, title: 'Wrong title', visible: true }), false);
        assert.equal(evaluateReadiness(predicate, expected, { ...expected, visible: false }), false);
        assertionRuns += 1;
      },
    };

    await prepareLab(page, {
      baseURL: 'http://127.0.0.1:4173',
      labPath: '/captcha-lab',
      token: 'test-session',
    }, { locale: item.locale, theme: item.theme });

    assert.equal(assertionRuns, 1);
  });
});

function evaluateReadiness(predicate, expected, actual) {
  const previousDocument = globalThis.document;
  const previousGetComputedStyle = globalThis.getComputedStyle;
  const title = {
    textContent: actual.title,
    getClientRects: () => (actual.visible ? [{}] : []),
  };
  globalThis.document = {
    documentElement: { dataset: { theme: actual.theme }, lang: actual.lang },
    querySelector: (selector) => (selector === '#captcha-lab-title' ? title : null),
  };
  globalThis.getComputedStyle = () => ({
    display: actual.visible ? 'block' : 'none',
    visibility: actual.visible ? 'visible' : 'hidden',
  });
  try {
    return predicate(expected);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
    if (previousGetComputedStyle === undefined) delete globalThis.getComputedStyle;
    else globalThis.getComputedStyle = previousGetComputedStyle;
  }
}
