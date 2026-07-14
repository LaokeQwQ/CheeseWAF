import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import type { LoginCAPTCHAResponse, LoginOptions } from '../../types/api';

const api = vi.hoisted(() => ({
  APIRequestError: class APIRequestError extends Error {
    constructor(public code: string) {
      super(code);
    }
  },
  fetchLoginCaptcha: vi.fn(),
  fetchLoginOptions: vi.fn(),
  login: vi.fn(),
  verifyLoginCaptcha: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  ...api,
  sanitizeInternalReturnPath: (value?: string | null) => value || '/',
}));

const translate = (key: string, values?: Record<string, unknown>) => values ? `${key}:${JSON.stringify(values)}` : key;

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: translate,
  }),
}));

import LoginPage from './LoginPage';

const options: LoginOptions = {
  captcha: {
    enabled: true,
    mode: 'slider',
    slider: { width: 320, height: 150, piece_size: 42, tolerance: 6, min_drag_ms: 100, pow_enabled: false },
  },
  background: { enabled: false, type: 'auto', url: '' },
};

function captcha(token: string, image = `data:image/png;base64,${token}`): LoginCAPTCHAResponse {
  return {
    enabled: true,
    mode: 'slider',
    slider: { width: 320, height: 150, piece_size: 42, track_width: 278, target_y: 40, tolerance: 6, min_drag_ms: 100, image, piece: image, token },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}

let mobileMediaListener: (() => void) | undefined;

class LoadedImageMock {
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private value = '';

  set src(value: string) {
    this.value = value;
    if (value) queueMicrotask(() => this.onload?.());
  }

  get src() {
    return this.value;
  }
}

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal('Image', LoadedImageMock);
  api.fetchLoginCaptcha.mockReset();
  api.fetchLoginOptions.mockReset().mockResolvedValue(options);
  api.login.mockReset();
  api.verifyLoginCaptcha.mockReset();
  let mobile = false;
  mobileMediaListener = undefined;
  vi.spyOn(window, 'matchMedia').mockImplementation((query: string) => {
    const mobileQuery = query.includes('max-width');
    return {
      get matches() { return mobileQuery ? mobile : false; },
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn((_name: string, listener: EventListenerOrEventListenerObject) => {
        if (!mobileQuery) return;
        mobileMediaListener = () => {
          mobile = true;
          typeof listener === 'function' ? listener(new Event('change')) : listener.handleEvent(new Event('change'));
        };
      }),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    };
  });
});

afterEach(() => {
  vi.useRealTimers();
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderLogin() {
  return render(<MemoryRouter><LoginPage /></MemoryRouter>);
}

function fillUsername() {
  fireEvent.change(screen.getByRole('textbox', { name: 'login.username' }), { target: { value: 'Cheese' } });
}

async function verifyCaptcha(receipt = 'captcha-receipt') {
  api.verifyLoginCaptcha.mockResolvedValueOnce({ valid: true, receipt });
  const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
  fireEvent.click(gate);
  const slider = await screen.findByRole('slider');
  fireEvent.keyDown(slider, { key: 'End' });
  fireEvent.keyDown(slider, { key: 'Enter' });
  await waitFor(() => expect(api.verifyLoginCaptcha).toHaveBeenCalledTimes(1));
  await screen.findByText('login.captchaWidgetVerified');
}

describe('Login slider keyboard controls', () => {
  async function openSlider() {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('keyboard-token'));
    renderLogin();
    fillUsername();
    const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    return screen.findByRole('slider');
  }

  it('supports coarse page steps and one-pixel arrow adjustment with synchronized ARIA values', async () => {
    const slider = await openSlider();

    expect(slider.getAttribute('aria-valuemin')).toBe('0');
    expect(slider.getAttribute('aria-valuemax')).toBe('278');
    expect(slider.getAttribute('aria-valuenow')).toBe('0');

    fireEvent.keyDown(slider, { key: 'PageUp' });
    expect(slider.getAttribute('aria-valuenow')).toBe('28');

    fireEvent.keyDown(slider, { key: 'ArrowRight' });
    expect(slider.getAttribute('aria-valuenow')).toBe('29');

    fireEvent.keyDown(slider, { key: 'ArrowLeft' });
    expect(slider.getAttribute('aria-valuenow')).toBe('28');

    fireEvent.keyDown(slider, { key: 'PageDown' });
    expect(slider.getAttribute('aria-valuenow')).toBe('0');
  });

  it('clamps fine and coarse keyboard movement to the advertised ARIA boundaries', async () => {
    const slider = await openSlider();

    fireEvent.keyDown(slider, { key: 'ArrowLeft' });
    fireEvent.keyDown(slider, { key: 'PageDown' });
    expect(slider.getAttribute('aria-valuenow')).toBe('0');

    fireEvent.keyDown(slider, { key: 'End' });
    fireEvent.keyDown(slider, { key: 'ArrowRight' });
    fireEvent.keyDown(slider, { key: 'PageUp' });
    expect(slider.getAttribute('aria-valuenow')).toBe('278');
    expect(slider.getAttribute('aria-valuemin')).toBe('0');
    expect(slider.getAttribute('aria-valuemax')).toBe('278');

    fireEvent.keyDown(slider, { key: 'Home' });
    expect(slider.getAttribute('aria-valuenow')).toBe('0');
  });
});

describe('Login CAPTCHA request isolation', () => {
  it('ignores a stale issued challenge that resolves after the replacement', async () => {
    const oldIssue = deferred<LoginCAPTCHAResponse>();
    const currentIssue = deferred<LoginCAPTCHAResponse>();
    api.fetchLoginCaptcha.mockReturnValueOnce(oldIssue.promise).mockReturnValueOnce(currentIssue.promise);
    renderLogin();
	fillUsername();
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1));

    expect(mobileMediaListener).toBeTypeOf('function');
    await act(async () => { mobileMediaListener?.(); });
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2));
    currentIssue.resolve(captcha('current-token', 'data:image/png;base64,current'));
    const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    await screen.findByRole('img', { name: 'login.sliderImage' });
    const image = document.querySelector('.auth-slider-image') as HTMLImageElement;
    expect(image.src).toContain('current');

    oldIssue.resolve(captcha('old-token', 'data:image/png;base64,obsolete'));
    await Promise.resolve();
    expect(image.src).toContain('current');
  });

  it('does not let an obsolete verification set receipt or close the replacement challenge', async () => {
    const oldVerify = deferred<{ valid: boolean; receipt: string }>();
    api.fetchLoginCaptcha.mockResolvedValueOnce(captcha('old-token')).mockResolvedValueOnce(captcha('current-token'));
    api.verifyLoginCaptcha.mockReturnValueOnce(oldVerify.promise);
    renderLogin();
	fillUsername();
    const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    const slider = await screen.findByRole('slider');
    fireEvent.keyDown(slider, { key: 'End' });
    fireEvent.keyDown(slider, { key: 'Enter' });
    await waitFor(() => expect(api.verifyLoginCaptcha).toHaveBeenCalledTimes(1));

    expect(mobileMediaListener).toBeTypeOf('function');
    await act(async () => { mobileMediaListener?.(); });
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole('slider')).toBeTruthy();
    oldVerify.resolve({ valid: true, receipt: 'obsolete-receipt' });
    await Promise.resolve();

    expect(screen.queryByText('login.captchaWidgetVerified')).toBeNull();
    expect(screen.getByRole('dialog')).toBeTruthy();
  });
});

describe('Login CAPTCHA username binding', () => {
  it('does not issue a challenge until a valid username remains stable', async () => {
    vi.useFakeTimers();
    api.fetchLoginCaptcha.mockResolvedValue(captcha('stable-username-token'));
    renderLogin();

    await act(async () => { await Promise.resolve(); });
    const username = screen.getByRole('textbox', { name: 'login.username' });
    fireEvent.change(username, { target: { value: 'ab' } });
    await act(async () => { await vi.advanceTimersByTimeAsync(500); });
    expect(api.fetchLoginCaptcha).not.toHaveBeenCalled();

    fireEvent.change(username, { target: { value: 'Che' } });
    await act(async () => { await vi.advanceTimersByTimeAsync(200); });
    fireEvent.change(username, { target: { value: 'Cheese' } });
    await act(async () => { await vi.advanceTimersByTimeAsync(299); });
    expect(api.fetchLoginCaptcha).not.toHaveBeenCalled();

    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1);
  });

  it('does not start CAPTCHA work or expose translation keys for an invalid username submission', async () => {
    renderLogin();
    await waitFor(() => expect(api.fetchLoginOptions).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByRole('textbox', { name: 'login.username' }), { target: { value: 'ab' } });
    fireEvent.change(screen.getByLabelText('login.password'), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'login.submit' }));

    await waitFor(() => expect(document.body.textContent).toContain('Enter a valid username.'));
    expect(document.body.textContent).not.toContain('login.usernameRequired');
    expect(api.fetchLoginCaptcha).not.toHaveBeenCalled();
    expect(api.login).not.toHaveBeenCalled();
  });

  it('only shows the CAPTCHA gate while the username has content', async () => {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('username-gate-token'));
    renderLogin();

    await waitFor(() => expect(api.fetchLoginOptions).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('button', { name: /login\.captchaState/ })).toBeNull();
    expect(document.body.textContent).not.toContain('login.usernameRequired');

    const username = screen.getByRole('textbox', { name: 'login.username' });
    fireEvent.change(username, { target: { value: 'Cheese' } });
    expect(await screen.findByRole('button', { name: /login\.captchaState\.ready/ })).toBeTruthy();

    fireEvent.change(username, { target: { value: '' } });
    expect(screen.queryByRole('button', { name: /login\.captchaState/ })).toBeNull();
    expect(document.body.textContent).not.toContain('login.usernameRequired');
  });

  it('selects PoW when the viewport switches to mobile and aborts the desktop issue', async () => {
    const desktopIssue = deferred<LoginCAPTCHAResponse>();
    api.fetchLoginCaptcha
      .mockReturnValueOnce(desktopIssue.promise)
      .mockResolvedValueOnce({ enabled: true, mode: 'pow', challenge: 'mobile-challenge' });
    renderLogin();
    fillUsername();

    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1));
    const desktopSignal = api.fetchLoginCaptcha.mock.calls[0]?.[1] as AbortSignal;
    expect(desktopSignal.aborted).toBe(false);
    expect(mobileMediaListener).toBeTypeOf('function');

    await act(async () => { mobileMediaListener?.(); });
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2));

    expect(desktopSignal.aborted).toBe(true);
    expect(api.fetchLoginCaptcha.mock.calls[1]?.[0]).toBe('pow');
    expect(api.fetchLoginCaptcha.mock.calls[1]?.[1]).toBeInstanceOf(AbortSignal);
  });

  it('stops an in-progress PoW calculation when the username is cleared', async () => {
    const digest = vi.fn(async () => new Uint8Array(32).buffer);
    vi.stubGlobal('crypto', { subtle: { digest } });
    api.fetchLoginCaptcha.mockResolvedValue({
      enabled: true,
      mode: 'pow',
      challenge: {
        algorithm: 'SHA-256',
        challenge: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        salt: 'abortable-pow',
        signature: 'signature',
        max_number: 100000,
      },
    });
    renderLogin();
    expect(mobileMediaListener).toBeTypeOf('function');
    await act(async () => { mobileMediaListener?.(); });
    fillUsername();

    await waitFor(() => expect(digest).toHaveBeenCalled());
    fireEvent.change(screen.getByRole('textbox', { name: 'login.username' }), { target: { value: '' } });
    await act(async () => { await Promise.resolve(); });
    const stoppedAt = digest.mock.calls.length;
    await new Promise((resolve) => window.setTimeout(resolve, 20));

    expect(digest).toHaveBeenCalledTimes(stoppedAt);
    expect(screen.queryByRole('button', { name: /login\.captchaState/ })).toBeNull();
  });

  it('cancels the CAPTCHA session and destroys the dialog when it closes', async () => {
    const replacement = deferred<LoginCAPTCHAResponse>();
    api.fetchLoginCaptcha
      .mockResolvedValueOnce(captcha('dialog-token'))
      .mockReturnValueOnce(replacement.promise);
    renderLogin();
    fillUsername();

    const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    await screen.findByRole('dialog');
    fireEvent.click(screen.getByRole('button', { name: 'login.captchaRefresh' }));
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2));
    const signal = api.fetchLoginCaptcha.mock.calls[1]?.[1] as AbortSignal;

    fireEvent.click(screen.getByRole('button', { name: 'login.captchaModalClose' }));

    expect(signal.aborted).toBe(true);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('waits exactly one second before replacing a failed challenge', async () => {
    vi.useFakeTimers();
    api.fetchLoginCaptcha
      .mockResolvedValueOnce(captcha('failed-token'))
      .mockResolvedValueOnce(captcha('replacement-token'));
    api.verifyLoginCaptcha.mockRejectedValueOnce(new Error('invalid'));
    renderLogin();
    await act(async () => { await Promise.resolve(); });
    fillUsername();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
      await Promise.resolve();
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(1);
    });

    const gate = screen.getByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    const slider = screen.getByRole('slider');
    fireEvent.keyDown(slider, { key: 'End' });
    fireEvent.keyDown(slider, { key: 'Enter' });
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1);

    await act(async () => { await vi.advanceTimersByTimeAsync(999); });
    expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2);
  });

  it('keeps the verified CAPTCHA gate locked and does not open it again', async () => {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('locked-token'));
    renderLogin();
    fillUsername();
    await verifyCaptcha('locked-receipt');

    const gate = screen.getByRole('button', { name: /login\.captchaState\.verified/ }) as HTMLButtonElement;
    expect(gate.disabled).toBe(true);
    expect(screen.getByRole('dialog')).toBeTruthy();
    fireEvent.click(gate);
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(1);
  });

  it('binds the current username into the CAPTCHA verification payload', async () => {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('payload-token'));
    renderLogin();
    fillUsername();

    await verifyCaptcha();

    expect(api.verifyLoginCaptcha).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'slider', username: 'Cheese' }),
      expect.any(AbortSignal),
    );
  });

  it('invalidates a verified receipt when the username changes', async () => {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('receipt-token'));
    renderLogin();
    fillUsername();
    await verifyCaptcha('bound-receipt');

    fireEvent.change(screen.getByRole('textbox', { name: 'login.username' }), { target: { value: 'Cheese-2' } });

    expect(screen.queryByText('login.captchaWidgetVerified')).toBeNull();
    expect(screen.getByRole('button', { name: /login\.captchaState\.loading/ })).toBeTruthy();
    expect(await screen.findByRole('button', { name: /login\.captchaState\.ready/ })).toBeTruthy();
  });

  it('ignores a pending verification when the username changes', async () => {
    const pendingVerify = deferred<{ valid: boolean; receipt: string }>();
    api.fetchLoginCaptcha.mockResolvedValue(captcha('pending-username-token'));
    api.verifyLoginCaptcha.mockReturnValueOnce(pendingVerify.promise);
    renderLogin();
    fillUsername();

    const gate = await screen.findByRole('button', { name: /login\.captchaState\.ready/ });
    fireEvent.click(gate);
    const slider = await screen.findByRole('slider');
    fireEvent.keyDown(slider, { key: 'End' });
    fireEvent.keyDown(slider, { key: 'Enter' });
    await waitFor(() => expect(api.verifyLoginCaptcha).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByRole('textbox', { name: 'login.username' }), { target: { value: 'Cheese-2' } });

    expect(screen.getByRole('button', { name: /login\.captchaState\.loading/ })).toBeTruthy();
    pendingVerify.resolve({ valid: true, receipt: 'stale-username-receipt' });
    await act(async () => { await pendingVerify.promise; });

    expect(screen.queryByText('login.captchaWidgetVerified')).toBeNull();
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await screen.findByRole('button', { name: /login\.captchaState\.ready/ })).toBeTruthy();
  });

  it('refreshes the CAPTCHA after a TWO_FA_REQUIRED login response', async () => {
    api.fetchLoginCaptcha
      .mockResolvedValueOnce(captcha('consumed-token'))
      .mockResolvedValueOnce(captcha('replacement-token'));
    api.login.mockRejectedValueOnce(new api.APIRequestError('TWO_FA_REQUIRED'));
    renderLogin();
    fillUsername();
    await verifyCaptcha('consumed-receipt');

    fireEvent.change(screen.getByLabelText('login.password'), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'login.submit' }));

    await waitFor(() => expect(api.login).toHaveBeenCalledTimes(1));
    expect(api.login.mock.calls[0]?.[3]).toEqual(expect.objectContaining({ receipt: 'consumed-receipt' }));
    await waitFor(() => expect(api.fetchLoginCaptcha).toHaveBeenCalledTimes(2));
    expect(screen.getByRole('button', { name: /login\.captchaState\.ready/ })).toBeTruthy();
    expect(screen.queryByText('login.captchaWidgetVerified')).toBeNull();
  });

  it('keeps a stable hook order when a successful login stores the session token', async () => {
    api.fetchLoginCaptcha.mockResolvedValue(captcha('successful-login-token'));
    api.login.mockResolvedValue({ token: 'session-token', user: { username: 'Cheese', role: 'admin' } });
    renderLogin();
    fillUsername();
    await verifyCaptcha('successful-login-receipt');

    fireEvent.change(screen.getByLabelText('login.password'), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'login.submit' }));

    await waitFor(() => expect(api.login).toHaveBeenCalledTimes(1));
    expect(localStorage.getItem('cheesewaf-token')).toBe('session-token');
  });
});
