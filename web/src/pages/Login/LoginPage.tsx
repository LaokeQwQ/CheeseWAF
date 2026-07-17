import { Button, Form, Input, Message as ArcoMessage, Modal, Select } from '@arco-design/web-react';
import '../../styles/arco-components';
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Languages, LockKeyhole, MoveRight, RefreshCcw, ShieldCheck, SunMoon, UserRound, X } from 'lucide-react';
import { APIRequestError, fetchLoginCaptcha, fetchLoginOptions, login, sanitizeInternalReturnPath, verifyLoginCaptcha } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';
import type {
  LoginCAPTCHAChallenge,
  LoginCAPTCHAPayload,
  LoginCAPTCHAResponse,
  LoginOptions,
  LoginSliderCAPTCHAChallenge,
} from '../../types/api';

const ALLOWED_LANGUAGES: readonly Language[] = ['zh-CN', 'en-US'];

function isThemeName(value: unknown): value is ThemeName {
  return themeOptions.some((option) => option.value === value);
}

function isLanguage(value: unknown): value is Language {
  return typeof value === 'string' && (ALLOWED_LANGUAGES as readonly string[]).includes(value);
}

type CAPTCHAState = 'loading' | 'ready' | 'solving' | 'checking' | 'verified' | 'invalid' | 'disabled' | 'error';
type LoginCAPTCHAMode = 'slider' | 'pow';
const LOGIN_USERNAME_MIN_LENGTH = 3;
const CAPTCHA_USERNAME_DEBOUNCE_MS = 300;
const CAPTCHA_RETRY_DELAY_MS = 1000;

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const setTheme = useAppStore((state) => state.setTheme);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [username, setUsername] = useState('');
  const [options, setOptions] = useState<LoginOptions | null>(null);
  const [challenge, setChallenge] = useState<LoginCAPTCHAChallenge | null>(null);
  const [powPayload, setPowPayload] = useState<LoginCAPTCHAPayload | null>(null);
  const [activeCaptchaMode, setActiveCaptchaMode] = useState<LoginCAPTCHAMode>('slider');
  const [slider, setSlider] = useState<LoginSliderCAPTCHAChallenge | null>(null);
  const [sliderX, setSliderX] = useState(0);
  const [sliderDone, setSliderDone] = useState(false);
  const [sliderPayload, setSliderPayload] = useState<LoginCAPTCHAPayload['slider'] | null>(null);
  const [captchaReceipt, setCaptchaReceipt] = useState<string | null>(null);
  const [sliderDragging, setSliderDragging] = useState(false);
  const [lastSliderDragMs, setLastSliderDragMs] = useState<number | null>(null);
  const [captchaState, setCaptchaState] = useState<CAPTCHAState>('loading');
  const [captchaModalOpen, setCaptchaModalOpen] = useState(false);
  const [loadMs, setLoadMs] = useState<number | null>(null);
  const [sliderTrack, setSliderTrack] = useState<Array<{ x: number; y: number; t: number; type: 'down' | 'move' | 'up' }>>([]);
  const mobileCaptcha = useMobileCaptchaMode();
  const dragRef = useRef<{ pointerId: number; originX: number; startX: number; startedAt: number } | null>(null);
  const trackRef = useRef<HTMLDivElement | null>(null);
  const sliderImageRef = useRef<HTMLImageElement | null>(null);
  const captchaCloseTimerRef = useRef<number | null>(null);
  const captchaRefreshTimerRef = useRef<number | null>(null);
  const captchaIssueSequenceRef = useRef(0);
  const captchaVerifySequenceRef = useRef(0);
  const usernameRef = useRef(username);
  const captchaUsernameRef = useRef('');
  const captchaUsernameTimerRef = useRef<number | null>(null);
  const captchaIssueControllerRef = useRef<AbortController | null>(null);
  const captchaVerifyControllerRef = useRef<AbortController | null>(null);
  const captchaPowControllerRef = useRef<AbortController | null>(null);
  const backgroundVideoRef = useRef<HTMLVideoElement | null>(null);
  const token = localStorage.getItem('cheesewaf-token');
  const stateFrom = (location.state as { from?: string } | null)?.from;
  const queryFrom = new URLSearchParams(location.search).get('returnTo');
  const from = sanitizeInternalReturnPath(queryFrom ?? stateFrom);

  const resetSliderMotion = useCallback(() => {
    dragRef.current = null;
    setSliderX(0);
    setSliderDragging(false);
  }, []);

  const resetSlider = useCallback(() => {
    resetSliderMotion();
    setSliderDone(false);
    setSliderPayload(null);
    setCaptchaReceipt(null);
    setLastSliderDragMs(null);
    setSliderTrack([]);
  }, [resetSliderMotion]);

  const cancelCaptchaWork = useCallback((clearChallenge = false) => {
    if (captchaUsernameTimerRef.current != null) {
      window.clearTimeout(captchaUsernameTimerRef.current);
      captchaUsernameTimerRef.current = null;
    }
    if (captchaCloseTimerRef.current != null) {
      window.clearTimeout(captchaCloseTimerRef.current);
      captchaCloseTimerRef.current = null;
    }
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
      captchaRefreshTimerRef.current = null;
    }
    captchaIssueControllerRef.current?.abort();
    captchaIssueControllerRef.current = null;
    captchaVerifyControllerRef.current?.abort();
    captchaVerifyControllerRef.current = null;
    captchaPowControllerRef.current?.abort();
    captchaPowControllerRef.current = null;
    captchaIssueSequenceRef.current += 1;
    captchaVerifySequenceRef.current += 1;
    if (clearChallenge) {
      captchaUsernameRef.current = '';
      setChallenge(null);
      setPowPayload(null);
      setSlider(null);
      resetSlider();
    }
  }, [resetSlider]);

  const handleUsernameChange = useCallback((value: string) => {
    if (value === username) {
      return;
    }
    usernameRef.current = value;
    cancelCaptchaWork(true);
    setCaptchaModalOpen(false);
    setCaptchaState(options?.captcha.enabled && isLoginUsernameReady(value) ? 'loading' : options?.captcha.enabled ? 'ready' : 'disabled');
    setUsername(value);
  }, [cancelCaptchaWork, options?.captcha.enabled, username]);

  const applyCaptchaResponse = useCallback(async (response: Awaited<ReturnType<typeof fetchLoginCaptcha>>, activeOptions: LoginOptions | null, signal?: AbortSignal) => {
    if (!response.enabled) {
      setChallenge(null);
      setPowPayload(null);
      setActiveCaptchaMode('slider');
      setSlider(null);
      resetSlider();
      setCaptchaState('disabled');
      return;
    }
    const nextMode = resolveCAPTCHAMode(activeOptions, response.mode);
    const sliderMode = nextMode === 'slider';
    const needsPow = loginCAPTCHARequiresPow(activeOptions, nextMode, response);
    if (needsPow && !response.challenge) {
      throw new Error(t('login.captchaUnavailable'));
    }
    if (sliderMode && !response.slider) {
      throw new Error(t('login.captchaUnavailable'));
    }
    if (response.slider) {
      await preloadCaptchaImages(response.slider, signal);
    }
    if (signal?.aborted) {
      throw requestAbortError();
    }
    setActiveCaptchaMode(nextMode);
    setChallenge(response.challenge ?? null);
    setPowPayload(null);
    setSlider(response.slider ?? null);
    resetSlider();
    setCaptchaState('ready');
  }, [resetSlider, t]);

  const refreshCaptcha = useCallback(async (clearFeedback = true, requestedUsername = normalizeLoginUsername(usernameRef.current)) => {
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
      captchaRefreshTimerRef.current = null;
    }
    if (captchaCloseTimerRef.current != null) {
      window.clearTimeout(captchaCloseTimerRef.current);
      captchaCloseTimerRef.current = null;
    }
    if (!isLoginUsernameReady(requestedUsername) || normalizeLoginUsername(usernameRef.current) !== requestedUsername) {
      return;
    }
    captchaVerifyControllerRef.current?.abort();
    captchaVerifyControllerRef.current = null;
    captchaVerifySequenceRef.current += 1;
    const sequence = ++captchaIssueSequenceRef.current;
    const controller = new AbortController();
    captchaIssueControllerRef.current?.abort();
    captchaIssueControllerRef.current = controller;
    captchaPowControllerRef.current?.abort();
    captchaPowControllerRef.current = null;
    if (options && !options.captcha.enabled) {
      setCaptchaState('disabled');
      setChallenge(null);
      setPowPayload(null);
      setSlider(null);
      resetSlider();
      return;
    }
    setCaptchaState('loading');
    if (clearFeedback) {
      setError('');
      setSuccess('');
    }
    try {
      const response = await fetchLoginCaptcha(mobileCaptcha ? 'pow' : undefined, controller.signal);
      if (controller.signal.aborted || sequence !== captchaIssueSequenceRef.current) {
        return;
      }
      captchaUsernameRef.current = requestedUsername;
      await applyCaptchaResponse(response, options, controller.signal);
      if (controller.signal.aborted || sequence !== captchaIssueSequenceRef.current || normalizeLoginUsername(usernameRef.current) !== requestedUsername) {
        return;
      }
    } catch (err) {
      if (isRequestAbort(err) || sequence !== captchaIssueSequenceRef.current) {
        return;
      }
      if (captchaUsernameRef.current === requestedUsername) {
        captchaUsernameRef.current = '';
      }
      setCaptchaState('error');
      setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
    } finally {
      if (captchaIssueControllerRef.current === controller) {
        captchaIssueControllerRef.current = null;
      }
    }
  }, [applyCaptchaResponse, mobileCaptcha, options, resetSlider, t]);

  useEffect(() => {
    let cancelled = false;
    const started = performance.now();
    async function bootstrap() {
      try {
        const nextOptions = normalizeLoginOptions(await fetchLoginOptions());
        if (cancelled) {
          return;
        }
        setOptions(nextOptions);
        if (!nextOptions.captcha.enabled) {
          setChallenge(null);
          setPowPayload(null);
          setSlider(null);
          resetSlider();
          setCaptchaState('disabled');
        }
      } catch (err) {
        if (!cancelled) {
          setCaptchaState('error');
        }
      } finally {
        if (!cancelled) {
          setLoadMs(Math.round(performance.now() - started));
        }
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
      captchaIssueControllerRef.current?.abort();
      captchaIssueSequenceRef.current += 1;
    };
  }, [resetSlider]);

  useEffect(() => {
    if (!options?.captcha.enabled) {
      return undefined;
    }
    const requestedUsername = normalizeLoginUsername(username);
    cancelCaptchaWork(true);
    if (!isLoginUsernameReady(requestedUsername)) {
      setCaptchaState('ready');
      return undefined;
    }
    setCaptchaState('loading');
    captchaUsernameTimerRef.current = window.setTimeout(() => {
      captchaUsernameTimerRef.current = null;
      void refreshCaptcha(true, requestedUsername);
    }, CAPTCHA_USERNAME_DEBOUNCE_MS);
    return () => cancelCaptchaWork(true);
  }, [cancelCaptchaWork, mobileCaptcha, options?.captcha.enabled, refreshCaptcha, username]);

  useEffect(() => () => cancelCaptchaWork(true), [cancelCaptchaWork]);

  useEffect(() => {
    const currentUsername = normalizeLoginUsername(username);
    if (!options?.captcha.enabled || !challenge || !isLoginUsernameReady(currentUsername) || captchaUsernameRef.current !== currentUsername || !loginCAPTCHARequiresPow(options, activeCaptchaMode)) {
      return undefined;
    }
    const currentChallenge = challenge;
    const currentMode = activeCaptchaMode;
    const controller = new AbortController();
    captchaPowControllerRef.current?.abort();
    captchaPowControllerRef.current = controller;
    async function solvePow() {
      try {
        setCaptchaState('solving');
        const number = await solveSHA256(currentChallenge.salt, currentChallenge.challenge, currentChallenge.max_number, controller.signal);
        if (controller.signal.aborted || captchaUsernameRef.current !== normalizeLoginUsername(usernameRef.current)) {
          return;
        }
        setPowPayload({
          mode: currentMode,
          algorithm: currentChallenge.algorithm,
          challenge: currentChallenge.challenge,
          number,
          salt: currentChallenge.salt,
          signature: currentChallenge.signature,
        });
        setCaptchaState('ready');
      } catch (err) {
        if (!isRequestAbort(err) && !controller.signal.aborted) {
          setCaptchaState('error');
          setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
        }
      }
    }
    solvePow();
    return () => {
      controller.abort();
      if (captchaPowControllerRef.current === controller) {
        captchaPowControllerRef.current = null;
      }
    };
  }, [activeCaptchaMode, challenge, options, t, username]);

  useEffect(() => {
    if (!options?.captcha.enabled || captchaState === 'loading' || captchaState === 'checking' || captchaState === 'invalid' || captchaState === 'error' || captchaState === 'disabled') {
      return;
    }
    if ((!loginCAPTCHARequiresPow(options, activeCaptchaMode) || powPayload) && (activeCaptchaMode !== 'slider' || sliderDone)) {
      setCaptchaState('verified');
    } else if (captchaState !== 'solving') {
      setCaptchaState('ready');
    }
  }, [activeCaptchaMode, captchaState, options, powPayload, sliderDone]);

  const background = options?.background;
  const rawBackgroundURL = background?.enabled ? background.url.trim() : '';
  const safeBackgroundURL = useMemo(() => cssURL(rawBackgroundURL), [rawBackgroundURL]);
  const backgroundKind = useMemo(() => resolveBackgroundKind(background?.type, safeBackgroundURL), [background?.type, safeBackgroundURL]);
  const prefersReducedMotion = usePrefersReducedMotion();
  const showBackgroundVideo = Boolean(safeBackgroundURL && backgroundKind === 'video');
  const showBackgroundImage = Boolean(safeBackgroundURL && backgroundKind === 'image');
  const branding = options?.branding;
  const copyrightText = String(branding?.copyright ?? '').trim();
  const showProductVersion = branding?.show_version !== false && Boolean(branding?.product_version);
  const productVersion = String(branding?.product_version ?? '').trim();

  useEffect(() => {
    const video = backgroundVideoRef.current;
    if (!video || !prefersReducedMotion) {
      return undefined;
    }
    const showFirstFrame = () => {
      video.pause();
      video.currentTime = 0;
    };
    showFirstFrame();
    video.addEventListener('loadedmetadata', showFirstFrame);
    return () => video.removeEventListener('loadedmetadata', showFirstFrame);
  }, [safeBackgroundURL, prefersReducedMotion]);

  function handleThemeChange(value: string) {
    if (isThemeName(value)) {
      setTheme(value);
    }
  }

  function handleLanguageChange(value: string) {
    if (isLanguage(value)) {
      setLanguage(value);
    }
  }

  async function handleSubmit(values: { username?: string; password?: string; totpCode?: string }) {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const submittedUsername = normalizeLoginUsername(values.username ?? '');
      if (!isLoginUsernameReady(submittedUsername)) {
        setError(localizedLoginText(t, 'login.usernameRequired', 'Enter a valid username.'));
        return;
      }
      if (options?.captcha.enabled && (captchaState !== 'verified' || captchaUsernameRef.current !== submittedUsername)) {
        if (activeCaptchaMode === 'slider') {
          setCaptchaModalOpen(true);
        }
        setError(localizedLoginText(t, 'login.captchaRequired', 'Complete browser verification first.'));
        return;
      }
      const captcha = await buildLoginCaptchaIfNeeded({
        options,
        challenge,
        powPayload,
        activeCaptchaMode,
        slider,
        sliderPayload,
        captchaReceipt,
        setCaptchaState,
        notReadyMessage: localizedLoginText(t, 'login.captchaRequired', 'Complete browser verification first.'),
      });
      if (captcha) {
        captcha.username = submittedUsername;
      }
      const result = await login(submittedUsername, values.password ?? '', values.totpCode, captcha);
      localStorage.setItem('cheesewaf-token', result.token);
      const message = t('login.success');
      setSuccess(message);
      ArcoMessage.success(message);
      window.setTimeout(() => navigate(from, { replace: true }), 220);
    } catch (err) {
      if (err instanceof APIRequestError && err.code === 'TWO_FA_REQUIRED') {
        setRequires2FA(true);
        setError(t('login.totpRequired'));
        ArcoMessage.warning(t('login.totpRequired'));
        await refreshCaptcha(false);
        return;
      }
      if (err instanceof APIRequestError && err.code === 'INVALID_CAPTCHA') {
        const message = t('login.captchaInvalid');
        setError(message);
        await refreshCaptcha(false);
        setCaptchaModalOpen(true);
        return;
      }
      const message = loginErrorMessage(err, t);
      setError(message);
      if (options?.captcha.enabled) {
        await refreshCaptcha(false);
      }
    } finally {
      setLoading(false);
    }
  }

  function handlePointerDown(event: React.PointerEvent<HTMLElement>) {
    if (!slider || loading || captchaState === 'loading' || captchaState === 'solving' || captchaState === 'checking' || captchaState === 'verified' || captchaState === 'invalid' || captchaState === 'error') {
      return;
    }
    if (!(event.target instanceof Element) || !event.target.closest('.auth-slider-thumb')) {
      return;
    }
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
      captchaRefreshTimerRef.current = null;
    }
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    setError('');
    setSliderDragging(true);
    setSliderDone(false);
    setSliderPayload(null);
    setCaptchaReceipt(null);
    setLastSliderDragMs(null);
    setCaptchaState('ready');
    dragRef.current = { pointerId: event.pointerId, originX: event.clientX, startX: sliderX, startedAt: performance.now() };
    setSliderTrack([sliderTrackPoint(event, sliderX, 'down', 0)]);
  }

  function handlePointerMove(event: React.PointerEvent<HTMLElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId || !slider) {
      return;
    }
    const trackWidth = getSliderLayoutTravel(slider);
    const delta = pointerDeltaToSliderDelta(event.clientX - drag.originX, slider, trackRef.current);
    const nextX = Math.round(clamp(drag.startX + delta, 0, trackWidth));
    setSliderX(nextX);
    setSliderDone(false);
    const elapsed = Math.round(performance.now() - drag.startedAt);
    const point = sliderTrackPoint(event, nextX, 'move', elapsed);
    setSliderTrack((items) => [...items.slice(-90), point]);
  }

  async function verifySliderPosition(visualX: number, dragMs: number, currentSlider: LoginSliderCAPTCHAChallenge, track = sliderTrack) {
    if (visualX <= 0) {
      setCaptchaState('invalid');
      setError('');
      scheduleCaptchaRefresh();
      return;
    }
    const serverX = toServerSliderX(visualX, currentSlider);
    const sequence = ++captchaVerifySequenceRef.current;
    const requestUsername = normalizeLoginUsername(username);
    if (!isLoginUsernameReady(requestUsername) || captchaUsernameRef.current !== requestUsername) {
      setCaptchaState('error');
      setError(localizedLoginText(t, 'login.captchaUnavailable', 'Verification is unavailable. Please try again.'));
      return;
    }
    const controller = new AbortController();
    captchaVerifyControllerRef.current?.abort();
    captchaVerifyControllerRef.current = controller;
    setCaptchaState('checking');
    try {
      const nextSliderPayload = { token: currentSlider.token, x: serverX, drag_ms: dragMs, track: serializeSliderTrack(track, currentSlider, visualX, dragMs) };
      const verifyPayload: LoginCAPTCHAPayload = { mode: 'slider', username: requestUsername, slider: nextSliderPayload };
      if (loginCAPTCHARequiresPow(options, 'slider') && powPayload) {
        Object.assign(verifyPayload, powPayload, { mode: 'slider' });
      }
      const verification = await verifyLoginCaptcha(verifyPayload, controller.signal);
      if (controller.signal.aborted || sequence !== captchaVerifySequenceRef.current || slider?.token !== currentSlider.token || requestUsername !== normalizeLoginUsername(usernameRef.current) || requestUsername !== captchaUsernameRef.current) {
        return;
      }
      setSliderPayload(nextSliderPayload);
      setCaptchaReceipt(verification.receipt);
      setSliderDone(true);
      setCaptchaState('verified');
      setError('');
      if (captchaCloseTimerRef.current != null) {
        window.clearTimeout(captchaCloseTimerRef.current);
      }
      captchaCloseTimerRef.current = window.setTimeout(() => setCaptchaModalOpen(false), 1100);
    } catch (err) {
      if (isRequestAbort(err) || sequence !== captchaVerifySequenceRef.current || slider?.token !== currentSlider.token) {
        return;
      }
      setSliderPayload(null);
      setCaptchaReceipt(null);
      setSliderDone(false);
      setCaptchaState('invalid');
      setError('');
      scheduleCaptchaRefresh();
    } finally {
      if (captchaVerifyControllerRef.current === controller) {
        captchaVerifyControllerRef.current = null;
      }
    }
  }

  async function handlePointerUp(event: React.PointerEvent<HTMLElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId || !slider) {
      return;
    }
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    const currentSlider = slider;
    const trackWidth = getSliderLayoutTravel(slider);
    const delta = pointerDeltaToSliderDelta(event.clientX - drag.originX, slider, trackRef.current);
    const finalVisualX = Math.round(clamp(drag.startX + delta, 0, trackWidth));
    const elapsed = Math.max(0, Math.round(performance.now() - drag.startedAt));
    setLastSliderDragMs(elapsed);
    const finalTrack = [
      ...sliderTrack.slice(-90),
      sliderTrackPoint(event, finalVisualX, 'up', elapsed),
    ];
    setSliderTrack(finalTrack);
    dragRef.current = null;
    setSliderDragging(false);
    setSliderX(0);
    setSliderDone(false);
    setSliderPayload(null);
    setCaptchaReceipt(null);
    await verifySliderPosition(finalVisualX, elapsed, currentSlider, finalTrack);
  }

  function handleSliderKeyDown(event: React.KeyboardEvent<HTMLButtonElement>) {
    if (!slider || captchaState === 'checking' || captchaState === 'verified') {
      return;
    }
    const trackWidth = getSliderLayoutTravel(slider);
    const coarseStep = Math.max(10, Math.round(trackWidth / 10));
    switch (event.key) {
      case 'ArrowLeft':
      case 'ArrowDown':
        event.preventDefault();
        setSliderX((x) => Math.max(0, x - 1));
        break;
      case 'ArrowRight':
      case 'ArrowUp':
        event.preventDefault();
        setSliderX((x) => Math.min(trackWidth, x + 1));
        break;
      case 'Home':
        event.preventDefault();
        setSliderX(0);
        break;
      case 'End':
        event.preventDefault();
        setSliderX(trackWidth);
        break;
      case 'PageUp':
        event.preventDefault();
        setSliderX((x) => Math.min(trackWidth, x + coarseStep));
        break;
      case 'PageDown':
        event.preventDefault();
        setSliderX((x) => Math.max(0, x - coarseStep));
        break;
      case 'Enter':
      case ' ':
        event.preventDefault();
        void verifySliderPosition(sliderX, slider.min_drag_ms, slider);
        break;
    }
  }

  function scheduleCaptchaRefresh() {
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
    }
    captchaRefreshTimerRef.current = window.setTimeout(() => {
      captchaRefreshTimerRef.current = null;
      void refreshCaptcha();
    }, CAPTCHA_RETRY_DELAY_MS);
  }

  const closeCaptchaModal = useCallback(() => {
    cancelCaptchaWork(true);
    setCaptchaModalOpen(false);
    setCaptchaState(options?.captcha.enabled ? 'ready' : 'disabled');
  }, [cancelCaptchaWork, options?.captcha.enabled]);

  if (token) {
    return <Navigate to={from} replace />;
  }

  async function openCaptchaModal() {
    if (captchaState === 'verified') {
      return;
    }
    if (!options?.captcha.enabled) {
      return;
    }
    const requestedUsername = normalizeLoginUsername(usernameRef.current);
    if (!isLoginUsernameReady(requestedUsername)) {
      return;
    }
    setCaptchaModalOpen(true);
    if (activeCaptchaMode !== 'slider' || !slider) {
      await refreshCaptcha(true, requestedUsername);
      if (activeCaptchaMode !== 'slider') {
        return;
      }
    }
    if (activeCaptchaMode !== 'slider') {
      return;
    }
    if (captchaState === 'error' || !slider) {
      await refreshCaptcha(true, requestedUsername);
    }
  }

  const sliderMode = activeCaptchaMode === 'slider';
  const sliderClass = ['auth-slider', sliderDone ? 'auth-slider-done' : '', sliderDragging ? 'auth-slider-dragging' : ''].filter(Boolean).join(' ');
  const sliderCopy = captchaState === 'checking'
    ? t('login.sliderChecking')
    : captchaState === 'invalid'
      ? t('login.sliderInvalid')
      : sliderDone
        ? t('login.sliderReleasedWithTime', { seconds: formatSeconds(lastSliderDragMs) })
        : t('login.sliderHint');
  const showSliderFeedback = captchaState === 'checking' || captchaState === 'invalid';
  const captchaGateDisabled = loading
    || captchaState === 'loading'
    || captchaState === 'solving'
    || captchaState === 'checking'
    || captchaState === 'verified';

  return (
    <main className={safeBackgroundURL ? 'auth-screen auth-screen-media' : 'auth-screen'}>
      <div className="auth-toolbar" role="toolbar" aria-label={t('system.theme')}>
        <Select
          aria-label={t('system.theme')}
          className="auth-toolbar-select"
          value={isThemeName(theme) ? theme : 'light'}
          prefix={<SunMoon size={15} />}
          onChange={handleThemeChange}
        >
          {themeOptions.map((option) => (
            <Select.Option key={option.value} value={option.value}>
              {t(option.labelKey)}
            </Select.Option>
          ))}
        </Select>
        <Select
          aria-label={t('system.language')}
          className="auth-toolbar-select"
          value={isLanguage(language) ? language : 'zh-CN'}
          prefix={<Languages size={15} />}
          onChange={handleLanguageChange}
        >
          <Select.Option value="zh-CN">中文</Select.Option>
          <Select.Option value="en-US">English</Select.Option>
        </Select>
      </div>
      {showBackgroundVideo && (
        <video
          ref={backgroundVideoRef}
          className="auth-background-media"
          src={safeBackgroundURL}
          autoPlay={!prefersReducedMotion}
          muted
          loop={!prefersReducedMotion}
          playsInline
          preload={prefersReducedMotion ? 'metadata' : 'auto'}
        />
      )}
      {showBackgroundImage && (
        <div className="auth-background-media auth-background-image" style={{ backgroundImage: `url("${safeBackgroundURL}")` }} />
      )}
      {(showBackgroundVideo || showBackgroundImage) && <div className="auth-background-shade" />}
      <div className="auth-stack">
        <section
          className="auth-panel"
        >
          <div className="auth-brand">
            <span><BrandLogo /></span>
            <div>
              <h1>{t('login.title')}</h1>
              <p>{t('login.subtitle')}</p>
            </div>
          </div>

          <Form layout="vertical" className="auth-form" onSubmit={handleSubmit}>
            <Form.Item label={t('login.username')} field="username" rules={[{ required: true, message: t('login.usernameRequired') }]}>
              <Input prefix={<UserRound size={16} />} autoComplete="username" value={username} onChange={handleUsernameChange} />
            </Form.Item>
            <Form.Item label={t('login.password')} field="password" rules={[{ required: true, message: t('login.passwordRequired') }]}>
              <Input.Password prefix={<LockKeyhole size={16} />} autoComplete="current-password" />
            </Form.Item>
            {requires2FA && (
              <Form.Item label={t('login.totp')} field="totpCode">
                <Input prefix={<LockKeyhole size={16} />} maxLength={6} inputMode="numeric" />
              </Form.Item>
            )}
            {options?.captcha.enabled && isLoginUsernameReady(username) && (
              <button
                type="button"
                className={`auth-captcha-gate auth-captcha-state-${captchaState}`}
                onClick={openCaptchaModal}
                disabled={captchaGateDisabled}
              >
                <span className="auth-captcha-gate-main">
                  <span className="auth-captcha-gate-icon" aria-hidden="true">
                    <ShieldCheck size={16} />
                  </span>
                  <span className="auth-captcha-gate-label">{t(`login.captchaState.${captchaState}`)}</span>
                </span>
              </button>
            )}
            <div className="pressable">
              <Button type="primary" htmlType="submit" loading={loading} long>
                {t('login.submit')}
              </Button>
            </div>
            {error && <p className="form-error" role="alert">{error}</p>}
            {success && <p className="form-success" role="status">{success}</p>}
          </Form>
          {(copyrightText || showProductVersion) && (
            <footer className="auth-footer">
              {copyrightText ? <p className="auth-footer-copyright">{copyrightText}</p> : null}
              {showProductVersion ? (
                <p className="auth-footer-version">{t('login.productVersion', { version: productVersion })}</p>
              ) : null}
            </footer>
          )}
        </section>
        <div className="auth-load-time">
          {loadMs == null ? t('login.loading') : t('login.loadTime', { ms: loadMs })}
        </div>
      </div>
      <Modal
        className="auth-captcha-modal"
        title={null}
        visible={captchaModalOpen}
        onCancel={closeCaptchaModal}
        footer={null}
        closable={false}
        unmountOnExit
        aria-label={t('login.captchaWidgetTitle')}
      >
        <div className={`auth-captcha-widget auth-captcha-state-${captchaState}`}>
          <div className="auth-captcha-widget-head">
            <div>
              <strong>{t('login.captchaWidgetTitle')}</strong>
              <span>{captchaState === 'verified' ? t('login.captchaWidgetVerified') : t('login.captchaWidgetHint')}</span>
            </div>
          </div>
          {captchaState === 'verified' ? (
            <div className="auth-slider-success" role="status">
              <ShieldCheck size={18} />
              <span>{t('login.sliderReleasedWithTime', { seconds: formatSeconds(lastSliderDragMs) })}</span>
            </div>
          ) : sliderMode && slider ? (
            <div className={sliderClass} style={{ '--slider-width': `${slider.width}px` } as CSSProperties}>
              <div className="auth-slider-stage" aria-label={t('login.sliderImage')} role="img" style={{ aspectRatio: `${slider.width} / ${slider.height}` }}>
                <img ref={sliderImageRef} className="auth-slider-image" src={slider.image} width={slider.width} height={slider.height} alt="" draggable={false} />
                {slider.piece && (
                  <img
                    className="auth-slider-piece"
                    src={slider.piece}
                    width={slider.piece_size}
                    height={slider.piece_size}
                    alt={t('login.sliderPiece')}
                    draggable={false}
                    style={{
                      left: `${(sliderX / slider.width) * 100}%`,
                      top: `${(slider.target_y / slider.height) * 100}%`,
                      width: `${(slider.piece_size / slider.width) * 100}%`,
                      height: 'auto',
                    }}
                  />
                )}
                {(captchaState === 'invalid' || captchaState === 'checking') && (
                  <div className="auth-slider-stage-tip">
                    {captchaState === 'invalid'
                      ? t('login.sliderInvalidRefreshing')
                      : t('login.sliderChecking')}
                  </div>
                )}
              </div>
              {showSliderFeedback && (
                <div className="auth-slider-feedback" aria-live="polite">
                  <div>
                    <strong>{sliderCopy}</strong>
                    <span>{captchaState === 'invalid' ? t('login.sliderReloading') : t('login.captchaGateHint')}</span>
                  </div>
                </div>
              )}
              <div
                ref={trackRef}
                className={sliderX > 0 ? 'auth-slider-track auth-slider-track-progress' : 'auth-slider-track'}
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerUp}
                onPointerCancel={handlePointerUp}
              >
                <span className="auth-slider-fill" style={{ width: sliderX > 0 ? `${sliderProgress(sliderX, slider) * 100}%` : 0 }} />
                <button
                  type="button"
                  className={sliderDone ? 'auth-slider-thumb auth-slider-thumb-done' : 'auth-slider-thumb'}
                  style={{ left: `${sliderProgress(sliderX, slider) * 100}%`, transform: `translateX(-${sliderProgress(sliderX, slider) * 100}%)` }}
                  role="slider"
                  aria-valuemin={0}
                  aria-valuemax={getSliderLayoutTravel(slider)}
                  aria-valuenow={toServerSliderX(sliderX, slider)}
                  aria-label={t('login.sliderLabel')}
                  aria-disabled={captchaState === 'checking'}
                  onKeyDown={handleSliderKeyDown}
                >
                  <MoveRight size={18} />
                </button>
                <span className={sliderDone ? 'auth-slider-copy auth-slider-copy-done' : 'auth-slider-copy'}>{sliderCopy}</span>
              </div>
              <div className="auth-captcha-widget-foot">
                <span className="auth-captcha-widget-brand"><BrandLogo /> <strong>CheeseWAF</strong></span>
                <div>
                  <button type="button" onClick={() => void refreshCaptcha()} aria-label={t('login.captchaRefresh')} disabled={captchaState === 'checking' || captchaState === 'loading'}>
                    <RefreshCcw size={15} />
                  </button>
                  <button type="button" onClick={closeCaptchaModal} aria-label={t('login.captchaModalClose')}>
                    <X size={16} />
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="auth-captcha-compact">
              <span>{captchaState === 'loading' ? t('login.captchaState.loading') : t('login.powHint')}</span>
            </div>
          )}
        </div>
      </Modal>
    </main>
  );
}

async function buildLoginCaptchaIfNeeded({
  options,
  challenge,
  powPayload,
  activeCaptchaMode,
  slider,
  sliderPayload,
  captchaReceipt,
  setCaptchaState,
  notReadyMessage,
}: {
  options: LoginOptions | null;
  challenge: LoginCAPTCHAChallenge | null;
  powPayload: LoginCAPTCHAPayload | null;
  activeCaptchaMode: LoginCAPTCHAMode;
  slider: LoginSliderCAPTCHAChallenge | null;
  sliderPayload: LoginCAPTCHAPayload['slider'] | null;
  captchaReceipt: string | null;
  setCaptchaState: (state: CAPTCHAState) => void;
  notReadyMessage: string;
}): Promise<LoginCAPTCHAPayload | undefined> {
  if (!options?.captcha.enabled) {
    return undefined;
  }
  const sliderMode = activeCaptchaMode === 'slider';
  const needsPow = loginCAPTCHARequiresPow(options, activeCaptchaMode);
  const payload: LoginCAPTCHAPayload = { mode: activeCaptchaMode };
  if (needsPow) {
    if (!challenge) {
      throw new Error(notReadyMessage);
    }
    if (!powPayload) {
      setCaptchaState('solving');
      throw new Error(notReadyMessage);
    }
    Object.assign(payload, powPayload);
  }
  if (sliderMode) {
    if (!slider || !sliderPayload || !captchaReceipt) {
      throw new Error(notReadyMessage);
    }
    payload.receipt = captchaReceipt;
  }
  return payload;
}

async function solveSHA256(salt: string, target: string, maxNumber: number, signal?: AbortSignal) {
  for (let number = 0; number <= maxNumber; number += 1) {
    throwIfAborted(signal);
    const hash = await sha256Hex(`${salt}${number}`);
    throwIfAborted(signal);
    if (hash === target) {
      return number;
    }
    if (number > 0 && number % 256 === 0) {
      await yieldToBrowser(signal);
    }
  }
  throw new Error('captcha challenge could not be solved');
}

async function sha256Hex(value: string) {
  if (!crypto.subtle) {
    return sha256HexFallback(value);
  }
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sha256HexFallback(value: string) {
  const bytes = new TextEncoder().encode(value);
  const bitLength = bytes.length * 8;
  const paddedLength = (((bytes.length + 9 + 63) >> 6) << 6);
  const data = new Uint8Array(paddedLength);
  data.set(bytes);
  data[bytes.length] = 0x80;
  const view = new DataView(data.buffer);
  view.setUint32(paddedLength - 4, bitLength, false);

  const hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const w = new Array<number>(64);

  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = hash;
    for (let i = 0; i < 64; i += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + k[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }
  return hash.map((item) => item.toString(16).padStart(8, '0')).join('');
}

function rotr(value: number, bits: number) {
  return (value >>> bits) | (value << (32 - bits));
}

function resolveCAPTCHAMode(options: LoginOptions | null, responseMode?: string): LoginCAPTCHAMode {
  return String(responseMode || options?.captcha.mode || 'slider').toLowerCase() === 'pow' ? 'pow' : 'slider';
}

function loginCAPTCHARequiresPow(options: LoginOptions | null, mode?: LoginCAPTCHAMode, response?: LoginCAPTCHAResponse) {
  const resolvedMode = mode ?? resolveCAPTCHAMode(options, response?.mode);
  if (resolvedMode !== 'slider') {
    return true;
  }
  return Boolean(options?.captcha.slider?.pow_enabled || response?.challenge);
}

function useMobileCaptchaMode() {
  const query = '(max-width: 640px), (pointer: coarse)';
  const [matches, setMatches] = useState(() => (typeof window !== 'undefined' ? window.matchMedia(query).matches : false));
  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const media = window.matchMedia(query);
    const handleChange = () => setMatches(media.matches);
    handleChange();
    media.addEventListener('change', handleChange);
    return () => media.removeEventListener('change', handleChange);
  }, []);
  return matches;
}

function usePrefersReducedMotion() {
  const query = '(prefers-reduced-motion: reduce)';
  const [matches, setMatches] = useState(() => (typeof window !== 'undefined' ? window.matchMedia(query).matches : false));
  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const media = window.matchMedia(query);
    const handleChange = () => setMatches(media.matches);
    handleChange();
    media.addEventListener('change', handleChange);
    return () => media.removeEventListener('change', handleChange);
  }, []);
  return matches;
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function formatSeconds(milliseconds: number | null) {
  return ((milliseconds ?? 0) / 1000).toFixed(2);
}

function getSliderLayoutTravel(slider: LoginSliderCAPTCHAChallenge) {
  return slider.track_width || Math.max(0, slider.width - slider.piece_size);
}

function pointerDeltaToSliderDelta(pointerDeltaX: number, slider: LoginSliderCAPTCHAChallenge, track: HTMLElement | null) {
  if (!track) {
    return pointerDeltaX;
  }
  const rectWidth = track.getBoundingClientRect().width;
  const thumbWidth = track.querySelector<HTMLElement>('.auth-slider-thumb')?.getBoundingClientRect().width ?? 0;
  const renderedTravel = rectWidth - thumbWidth;
  const serverTravel = getSliderLayoutTravel(slider);
  if (!Number.isFinite(renderedTravel) || renderedTravel <= 0 || serverTravel <= 0) {
    return pointerDeltaX;
  }
  return pointerDeltaX * (serverTravel / renderedTravel);
}

function sliderProgress(value: number, slider: LoginSliderCAPTCHAChallenge) {
  const travel = getSliderLayoutTravel(slider);
  return travel > 0 ? clamp(value / travel, 0, 1) : 0;
}

function toServerSliderX(visualX: number, slider: LoginSliderCAPTCHAChallenge) {
  const serverTravel = getSliderLayoutTravel(slider);
  if (serverTravel <= 0) {
    return Math.round(clamp(visualX, 0, serverTravel));
  }
  return Math.round(clamp(visualX, 0, serverTravel));
}

function sliderTrackPoint(
  event: React.PointerEvent<HTMLElement>,
  sliderX: number,
  type: 'down' | 'move' | 'up',
  elapsedMs: number,
) {
  const rect = event.currentTarget.getBoundingClientRect();
  return {
    x: Math.round(sliderX),
    y: Math.round(Number.isFinite(rect.height) && rect.height > 0 ? event.clientY - rect.top : 0),
    t: Math.max(0, Math.round(elapsedMs)),
    type,
  };
}

function serializeSliderTrack(
  points: Array<{ x: number; y: number; t: number; type: 'down' | 'move' | 'up' }>,
  slider: LoginSliderCAPTCHAChallenge,
  finalVisualX: number,
  dragMs: number,
) {
  const normalized = points.slice(-96).map((point) => ({
    ...point,
    x: toServerSliderX(point.x, slider),
    y: Math.round(point.y),
    t: Math.max(0, Math.round(point.t)),
  }));
  if (normalized.length === 0) {
    normalized.push({ x: 0, y: 0, t: 0, type: 'down' });
  }
  const first = normalized[0];
  if (first.type !== 'down') {
    normalized.unshift({ x: 0, y: first.y || 0, t: 0, type: 'down' });
  }
  const last = normalized[normalized.length - 1];
  const finalX = toServerSliderX(finalVisualX, slider);
  if (last.type !== 'up') {
    normalized.push({ x: finalX, y: last.y || 0, t: Math.max(0, Math.round(dragMs)), type: 'up' });
  } else {
    normalized[normalized.length - 1] = { ...last, x: finalX, t: Math.max(0, Math.round(dragMs)), type: 'up' };
  }
  return JSON.stringify(normalized);
}

function loginErrorMessage(error: unknown, t: TFunction) {
  if (error instanceof APIRequestError) {
    switch (error.code) {
      case 'INVALID_CREDENTIALS':
        return t('login.invalidCredentials');
      case 'INVALID_TWO_FA_CODE':
        return t('login.invalidTotp');
      case 'REQUEST_TIMEOUT':
        return t('login.requestTimeout');
      case 'NETWORK_ERROR':
        return t('login.networkError');
      default:
        return error.rawMessage || error.message || t('login.failed');
    }
  }
  return error instanceof Error ? error.message : t('login.failed');
}

function resolveBackgroundKind(type: string | undefined, url: string) {
  const normalized = String(type || 'auto').toLowerCase();
  if (normalized === 'image' || normalized === 'video') {
    return normalized;
  }
  return /\.(mp4|webm|ogg|mov)(?:[?#].*)?$/i.test(url) ? 'video' : 'image';
}

function cssURL(value: string) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) {
    return '';
  }
  // Block CSS escape / injection sequences and non-URL values.
  if (/[);{}]/.test(trimmed)) {
    return '';
  }
  if (!/^(https?:\/\/|\/|data:image\/)/i.test(trimmed)) {
    return '';
  }
  return trimmed.replace(/["\\\n\r]/g, '');
}

function normalizeLoginOptions(value: LoginOptions | null | undefined): LoginOptions {
  return {
    captcha: {
      enabled: value?.captcha?.enabled ?? true,
      mode: value?.captcha?.mode || 'slider',
      algorithm: value?.captcha?.algorithm ?? 'SHA-256',
      max_number: value?.captcha?.max_number ?? 12000,
      slider: value?.captcha?.slider ?? {
        width: 320,
        height: 150,
        piece_size: 42,
        tolerance: 6,
        min_drag_ms: 450,
        pow_enabled: false,
        pow_max_number: 12000,
      },
    },
    background: {
      enabled: value?.background?.enabled ?? false,
      type: value?.background?.type || 'auto',
      url: value?.background?.url || '',
    },
    branding: {
      copyright: String(value?.branding?.copyright ?? '').trim(),
      show_version: value?.branding?.show_version !== false,
      product_version: String(value?.branding?.product_version ?? '').trim(),
    },
  };
}

function requestAbortError() {
  return new DOMException('Request aborted', 'AbortError');
}

function throwIfAborted(signal?: AbortSignal) {
  if (signal?.aborted) {
    throw requestAbortError();
  }
}

function yieldToBrowser(signal?: AbortSignal) {
  throwIfAborted(signal);
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, 0);
    const onAbort = () => {
      window.clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(requestAbortError());
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function normalizeLoginUsername(value: string) {
  return value.trim();
}

function isLoginUsernameReady(value: string) {
  const normalized = normalizeLoginUsername(value);
  return normalized.length >= LOGIN_USERNAME_MIN_LENGTH && normalized.length <= 128 && !/[\u0000-\u001f\u007f]/.test(normalized);
}

function localizedLoginText(t: TFunction, key: string, fallback: string) {
  const value = String(t(key));
  return value === key ? fallback : value;
}

async function preloadCaptchaImages(slider: LoginSliderCAPTCHAChallenge, signal?: AbortSignal) {
  await Promise.all([slider.image, slider.piece].filter((source): source is string => Boolean(source)).map((source) => preloadImage(source, signal)));
}

function preloadImage(source: string, signal?: AbortSignal) {
  if (signal?.aborted) return Promise.reject(requestAbortError());
  return new Promise<void>((resolve, reject) => {
    const image = new Image();
    const cleanup = () => {
      signal?.removeEventListener('abort', onAbort);
      image.onload = null;
      image.onerror = null;
    };
    const onAbort = () => {
      cleanup();
      image.src = '';
      reject(requestAbortError());
    };
    image.onload = () => {
      cleanup();
      resolve();
    };
    image.onerror = () => {
      cleanup();
      reject(new Error('CAPTCHA image failed to load'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    image.src = source;
  });
}

function isRequestAbort(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError';
}
