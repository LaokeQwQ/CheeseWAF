import { Button, Form, Input, Message as ArcoMessage, Modal } from '@arco-design/web-react';
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { LockKeyhole, MoveRight, RefreshCcw, ShieldCheck, UserRound, X } from 'lucide-react';
import { APIRequestError, fetchLoginCaptcha, fetchLoginOptions, login, verifyLoginCaptcha } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import type {
  LoginCAPTCHAChallenge,
  LoginCAPTCHAPayload,
  LoginCAPTCHAResponse,
  LoginOptions,
  LoginSliderCAPTCHAChallenge,
} from '../../types/api';

type CAPTCHAState = 'loading' | 'ready' | 'solving' | 'checking' | 'verified' | 'invalid' | 'disabled' | 'error';
type LoginCAPTCHAMode = 'slider' | 'pow';

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
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
  const token = localStorage.getItem('cheesewaf-token');
  const from = ((location.state as { from?: string } | null)?.from ?? '/') || '/';

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

  const applyCaptchaResponse = useCallback((response: Awaited<ReturnType<typeof fetchLoginCaptcha>>, activeOptions: LoginOptions | null) => {
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
    setActiveCaptchaMode(nextMode);
    setChallenge(response.challenge ?? null);
    setPowPayload(null);
    setSlider(response.slider ?? null);
    resetSlider();
    setCaptchaState('ready');
  }, [resetSlider, t]);

  const refreshCaptcha = useCallback(async (clearFeedback = true) => {
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
      captchaRefreshTimerRef.current = null;
    }
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
      applyCaptchaResponse(await fetchLoginCaptcha(mobileCaptcha ? 'pow' : undefined), options);
    } catch (err) {
      setCaptchaState('error');
      setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
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
        if (nextOptions.captcha.enabled) {
          setCaptchaState('loading');
          const response = await fetchLoginCaptcha(mobileCaptcha ? 'pow' : undefined);
          if (!cancelled) {
            applyCaptchaResponse(response, nextOptions);
          }
        } else {
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
    };
  }, [applyCaptchaResponse, mobileCaptcha, resetSlider]);

  useEffect(() => () => {
    if (captchaCloseTimerRef.current != null) {
      window.clearTimeout(captchaCloseTimerRef.current);
    }
    if (captchaRefreshTimerRef.current != null) {
      window.clearTimeout(captchaRefreshTimerRef.current);
    }
  }, []);

  useEffect(() => {
    if (!options?.captcha.enabled || !challenge || !loginCAPTCHARequiresPow(options, activeCaptchaMode)) {
      return undefined;
    }
    const currentChallenge = challenge;
    const currentMode = activeCaptchaMode;
    let cancelled = false;
    async function solvePow() {
      try {
        setCaptchaState('solving');
        const number = await solveSHA256(currentChallenge.salt, currentChallenge.challenge, currentChallenge.max_number);
        if (cancelled) {
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
        if (!cancelled) {
          setCaptchaState('error');
          setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
        }
      }
    }
    solvePow();
    return () => {
      cancelled = true;
    };
  }, [activeCaptchaMode, challenge, options, t]);

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
  const backgroundURL = background?.enabled ? background.url.trim() : '';
  const backgroundKind = useMemo(() => resolveBackgroundKind(background?.type, backgroundURL), [background?.type, backgroundURL]);

  if (token) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(values: { username?: string; password?: string; totpCode?: string }) {
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      if (options?.captcha.enabled && activeCaptchaMode === 'slider' && !captchaReceipt) {
        setCaptchaModalOpen(true);
        setError(t('login.captchaRequired'));
        ArcoMessage.warning(t('login.captchaRequired'));
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
      });
      const result = await login(values.username ?? '', values.password ?? '', values.totpCode, captcha);
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
        return;
      }
      if (err instanceof APIRequestError && err.code === 'INVALID_CAPTCHA') {
        const message = t('login.captchaInvalid');
        setError(message);
        ArcoMessage.warning(message);
        await refreshCaptcha(false);
        setCaptchaModalOpen(true);
        return;
      }
      const message = loginErrorMessage(err, t);
      setError(message);
      ArcoMessage.error(message);
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
    const delta = pointerDeltaToSliderDelta(event.clientX - drag.originX, sliderImageRef.current);
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
    setCaptchaState('checking');
    try {
      const nextSliderPayload = { token: currentSlider.token, x: serverX, drag_ms: dragMs, track: serializeSliderTrack(track, currentSlider, visualX, dragMs) };
      const verifyPayload: LoginCAPTCHAPayload = { mode: 'slider', slider: nextSliderPayload };
      if (loginCAPTCHARequiresPow(options, 'slider') && powPayload) {
        Object.assign(verifyPayload, powPayload, { mode: 'slider' });
      }
      const verification = await verifyLoginCaptcha(verifyPayload);
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
      setSliderPayload(null);
      setCaptchaReceipt(null);
      setSliderDone(false);
      setCaptchaState('invalid');
      setError('');
      scheduleCaptchaRefresh();
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
    const delta = pointerDeltaToSliderDelta(event.clientX - drag.originX, sliderImageRef.current);
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
    const step = Math.max(10, Math.round(trackWidth / 10));
    switch (event.key) {
      case 'ArrowLeft':
        event.preventDefault();
        setSliderX((x) => Math.max(0, x - step));
        break;
      case 'ArrowRight':
        event.preventDefault();
        setSliderX((x) => Math.min(trackWidth, x + step));
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
        setSliderX((x) => Math.max(0, x - step * 3));
        break;
      case 'PageDown':
        event.preventDefault();
        setSliderX((x) => Math.min(trackWidth, x + step * 3));
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
    }, 560);
  }

  async function openCaptchaModal() {
    if (captchaState === 'verified') {
      return;
    }
    if (!options?.captcha.enabled) {
      return;
    }
    if (activeCaptchaMode !== 'slider' || !slider) {
      await refreshCaptcha();
      if (activeCaptchaMode !== 'slider') {
        return;
      }
    }
    if (activeCaptchaMode !== 'slider') {
      return;
    }
    setCaptchaModalOpen(true);
    if (captchaState === 'error' || !slider) {
      await refreshCaptcha();
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
    <main className={backgroundURL ? 'auth-screen auth-screen-media' : 'auth-screen'}>
      {backgroundURL && backgroundKind === 'video' && (
        <video className="auth-background-media" src={backgroundURL} autoPlay muted loop playsInline />
      )}
      {backgroundURL && backgroundKind === 'image' && (
        <div className="auth-background-media auth-background-image" style={{ backgroundImage: `url("${cssURL(backgroundURL)}")` }} />
      )}
      {backgroundURL && <div className="auth-background-shade" />}
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
            <Form.Item label={t('login.username')} field="username">
              <Input prefix={<UserRound size={16} />} autoComplete="username" />
            </Form.Item>
            <Form.Item label={t('login.password')} field="password">
              <Input.Password prefix={<LockKeyhole size={16} />} autoComplete="current-password" />
            </Form.Item>
            {requires2FA && (
              <Form.Item label={t('login.totp')} field="totpCode">
                <Input prefix={<LockKeyhole size={16} />} maxLength={6} inputMode="numeric" />
              </Form.Item>
            )}
            {options?.captcha.enabled && (
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
        </section>
        <div className="auth-load-time">
          {loadMs == null ? t('login.loading') : t('login.loadTime', { ms: loadMs })}
        </div>
      </div>
      <Modal
        className="auth-captcha-modal"
        title={null}
        visible={captchaModalOpen}
        onCancel={() => setCaptchaModalOpen(false)}
        footer={null}
        closable={false}
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
            <div className={sliderClass} style={{ '--slider-width': `${slider.width}px`, '--piece-size': `${slider.piece_size}px` } as CSSProperties}>
              <div className="auth-slider-stage" aria-label={t('login.sliderImage')} role="img">
                <img ref={sliderImageRef} className="auth-slider-image" src={slider.image} width={slider.width} height={slider.height} alt="" draggable={false} />
                {slider.piece && (
                  <img
                    className="auth-slider-piece"
                    src={slider.piece}
                    width={slider.piece_size}
                    height={slider.piece_size}
                    alt={t('login.sliderPiece')}
                    draggable={false}
                    style={{ transform: `translate3d(${sliderX}px, ${slider.target_y}px, 0)` }}
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
                className="auth-slider-track"
                onPointerDown={handlePointerDown}
                onPointerMove={handlePointerMove}
                onPointerUp={handlePointerUp}
                onPointerCancel={handlePointerUp}
              >
                <span className="auth-slider-fill" style={{ width: sliderX > 0 ? `${sliderX + slider.piece_size / 2}px` : 0 }} />
                <button
                  type="button"
                  className={sliderDone ? 'auth-slider-thumb auth-slider-thumb-done' : 'auth-slider-thumb'}
                  style={{ transform: `translateX(${sliderX}px)` }}
                  role="slider"
                  aria-valuemin={0}
                  aria-valuemax={slider.track_width}
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
                  <button type="button" onClick={() => setCaptchaModalOpen(false)} aria-label={t('login.captchaModalClose')} disabled={captchaState === 'checking'}>
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
}: {
  options: LoginOptions | null;
  challenge: LoginCAPTCHAChallenge | null;
  powPayload: LoginCAPTCHAPayload | null;
  activeCaptchaMode: LoginCAPTCHAMode;
  slider: LoginSliderCAPTCHAChallenge | null;
  sliderPayload: LoginCAPTCHAPayload['slider'] | null;
  captchaReceipt: string | null;
  setCaptchaState: (state: CAPTCHAState) => void;
}): Promise<LoginCAPTCHAPayload | undefined> {
  if (!options?.captcha.enabled) {
    return undefined;
  }
  const sliderMode = activeCaptchaMode === 'slider';
  const needsPow = loginCAPTCHARequiresPow(options, activeCaptchaMode);
  const payload: LoginCAPTCHAPayload = { mode: activeCaptchaMode };
  if (needsPow) {
    if (!challenge) {
      throw new Error('captcha challenge is not ready');
    }
    let nextPowPayload = powPayload;
    if (!nextPowPayload) {
      setCaptchaState('solving');
      const number = await solveSHA256(challenge.salt, challenge.challenge, challenge.max_number);
      nextPowPayload = {
        mode: activeCaptchaMode,
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number,
        salt: challenge.salt,
        signature: challenge.signature,
      };
    }
    Object.assign(payload, nextPowPayload);
  }
  if (sliderMode) {
    if (!slider || !sliderPayload || !captchaReceipt) {
      throw new Error('complete slider verification first');
    }
    payload.receipt = captchaReceipt;
  }
  return payload;
}

async function solveSHA256(salt: string, target: string, maxNumber: number) {
  for (let number = 0; number <= maxNumber; number += 1) {
    const hash = await sha256Hex(`${salt}${number}`);
    if (hash === target) {
      return number;
    }
    if (number > 0 && number % 1024 === 0) {
      await new Promise((resolve) => window.setTimeout(resolve, 0));
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

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
}

function formatSeconds(milliseconds: number | null) {
  return ((milliseconds ?? 0) / 1000).toFixed(2);
}

function getSliderLayoutTravel(slider: LoginSliderCAPTCHAChallenge) {
  return slider.track_width || Math.max(0, slider.width - slider.piece_size);
}

function pointerDeltaToSliderDelta(pointerDeltaX: number, image: HTMLImageElement | null) {
  if (!image) {
    return pointerDeltaX;
  }
  const rectWidth = image.getBoundingClientRect().width;
  const layoutWidth = image.clientWidth || image.naturalWidth || rectWidth;
  if (!Number.isFinite(rectWidth) || rectWidth <= 0 || !Number.isFinite(layoutWidth) || layoutWidth <= 0) {
    return pointerDeltaX;
  }
  return pointerDeltaX * (layoutWidth / rectWidth);
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
  return value.replace(/["\\\n\r]/g, '');
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
  };
}
