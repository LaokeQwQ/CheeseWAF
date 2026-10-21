import { act, cleanup, render, waitFor } from '@testing-library/react';
import { createInstance } from 'i18next';
import { I18nextProvider, initReactI18next } from 'react-i18next';
import { afterEach, describe, expect, it, vi } from 'vitest';
import enUS from '../../i18n/locales/en-US';
import zhCN from '../../i18n/locales/zh-CN';
import { CapLoginCaptcha } from './CapLoginCaptcha';

vi.mock('cap-widget', () => ({}));

const challenge = {
  challenge_id: 'challenge',
  api_endpoint: 'https://cap.example.test/api/',
  wasm_url: 'https://cap.example.test/cap.wasm',
  hashwx_url: 'https://cap.example.test/hashwx.wasm',
};

const attributes = [
  ['initial-state', 'capInitialState'],
  ['verifying-label', 'capVerifyingLabel'],
  ['solved-label', 'capSolvedLabel'],
  ['error-label', 'capErrorLabel'],
  ['verify-aria-label', 'capVerifyAriaLabel'],
  ['verifying-aria-label', 'capVerifyingAriaLabel'],
  ['verified-aria-label', 'capVerifiedAriaLabel'],
  ['error-aria-label', 'capErrorAriaLabel'],
] as const;

afterEach(() => {
  cleanup();
  delete window.CAP_CUSTOM_WASM_URL;
  delete window.CAP_CUSTOM_HASHWX_URL;
});

async function translations(resources: Record<string, { translation: object }>) {
  const instance = createInstance();
  await instance.use(initReactI18next).init({
    lng: 'en-US',
    fallbackLng: 'en-US',
    resources,
    interpolation: { escapeValue: false },
  });
  return instance;
}

async function mountedWidget() {
  return waitFor(() => {
    const widget = document.querySelector('cap-widget');
    if (!widget) throw new Error('Cap widget was not mounted');
    return widget;
  });
}

describe('Cap login widget translations', () => {
  it('reads all visible and accessible labels from dictionary keys, including fallback languages', async () => {
    const labels = Object.fromEntries(attributes.map(([, key]) => [key, `translated ${key}`]));
    const instance = await translations({ 'en-US': { translation: { login: labels } } });
    render(
      <I18nextProvider i18n={instance}>
        <CapLoginCaptcha challenge={challenge} locale="fr-FR" onSolve={vi.fn()} onError={vi.fn()} />
      </I18nextProvider>,
    );

    const widget = await mountedWidget();
    for (const [attribute, key] of attributes) {
      expect(widget.getAttribute(`data-cap-i18n-${attribute}`)).toBe(labels[key]);
    }
  });

  it('keeps the current copy and refreshes the widget safely when its locale changes', async () => {
    const instance = await translations({ 'en-US': { translation: enUS }, 'zh-CN': { translation: zhCN } });
    const onSolve = vi.fn();
    const onError = vi.fn();
    const content = (locale: string) => (
      <I18nextProvider i18n={instance}>
        <CapLoginCaptcha challenge={challenge} locale={locale} onSolve={onSolve} onError={onError} />
      </I18nextProvider>
    );
    const view = render(content('en-US'));
    const previous = await mountedWidget();
    const english = [
      "I'm a human", 'Verifying...', 'You are human', 'Error. Try again.',
      'Click to verify you are human', 'Verifying that you are human',
      'Verification complete, you may continue', 'Verification failed, please try again',
    ];
    attributes.forEach(([attribute], index) => {
      expect(previous.getAttribute(`data-cap-i18n-${attribute}`)).toBe(english[index]);
    });

    view.rerender(content('zh-CN'));
    const current = await waitFor(() => {
      const widget = document.querySelector('cap-widget');
      if (!widget || widget === previous) throw new Error('Localized widget was not refreshed');
      return widget;
    });
    const chinese = [
      '点击验证你是人类', '正在验证...', '验证通过', '验证失败，请重试',
      '点击验证你是人类', '正在验证你是人类', '验证成功，可以继续', '验证失败，请重试',
    ];
    attributes.forEach(([attribute], index) => {
      expect(current.getAttribute(`data-cap-i18n-${attribute}`)).toBe(chinese[index]);
    });

    await act(async () => {
      previous.dispatchEvent(new CustomEvent('solve', { detail: { token: 'stale-token' } }));
      current.dispatchEvent(new CustomEvent('solve', { detail: { token: 'current-token' } }));
    });
    expect(onSolve).toHaveBeenCalledExactlyOnceWith('current-token');
    expect(onError).not.toHaveBeenCalled();
    view.unmount();
    expect(document.querySelector('cap-widget')).toBeNull();
    expect(window.CAP_CUSTOM_WASM_URL).toBeUndefined();
    expect(window.CAP_CUSTOM_HASHWX_URL).toBeUndefined();
  });
});
