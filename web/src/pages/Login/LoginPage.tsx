import { Button, Form, Input } from '@arco-design/web-react';
import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { LockKeyhole, MoveRight, RefreshCcw, ShieldCheck, UserRound } from 'lucide-react';
import { pressable } from '../../animations/micro';
import { APIRequestError, fetchLoginCaptcha, fetchLoginOptions, login } from '../../api/client';
import type {
  LoginCAPTCHAChallenge,
  LoginCAPTCHAPayload,
  LoginCAPTCHAResponse,
  LoginOptions,
  LoginSliderCAPTCHAChallenge,
} from '../../types/api';

type CAPTCHAState = 'loading' | 'ready' | 'solving' | 'verified' | 'disabled' | 'error';

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [options, setOptions] = useState<LoginOptions | null>(null);
  const [challenge, setChallenge] = useState<LoginCAPTCHAChallenge | null>(null);
  const [powPayload, setPowPayload] = useState<LoginCAPTCHAPayload | null>(null);
  const [slider, setSlider] = useState<LoginSliderCAPTCHAChallenge | null>(null);
  const [sliderX, setSliderX] = useState(0);
  const [sliderDone, setSliderDone] = useState(false);
  const [sliderDragMS, setSliderDragMS] = useState(0);
  const [captchaState, setCaptchaState] = useState<CAPTCHAState>('loading');
  const [loadMs, setLoadMs] = useState<number | null>(null);
  const dragRef = useRef<{ pointerId: number; originX: number; startX: number; startedAt: number } | null>(null);
  const trackRef = useRef<HTMLDivElement | null>(null);
  const token = localStorage.getItem('cheesewaf-token');
  const from = ((location.state as { from?: string } | null)?.from ?? '/') || '/';

  const resetSlider = useCallback(() => {
    dragRef.current = null;
    setSliderX(0);
    setSliderDone(false);
    setSliderDragMS(0);
  }, []);

  const applyCaptchaResponse = useCallback((response: Awaited<ReturnType<typeof fetchLoginCaptcha>>, activeOptions: LoginOptions | null) => {
    if (!response.enabled) {
      setChallenge(null);
      setPowPayload(null);
      setSlider(null);
      resetSlider();
      setCaptchaState('disabled');
      return;
    }
    const sliderMode = isSliderMode(activeOptions, response.mode);
    const needsPow = loginCAPTCHARequiresPow(activeOptions, response);
    if (needsPow && !response.challenge) {
      throw new Error(t('login.captchaUnavailable'));
    }
    if (sliderMode && !response.slider) {
      throw new Error(t('login.captchaUnavailable'));
    }
    setChallenge(response.challenge ?? null);
    setPowPayload(null);
    setSlider(response.slider ?? null);
    resetSlider();
    setCaptchaState('ready');
  }, [resetSlider, t]);

  const refreshCaptcha = useCallback(async () => {
    if (options && !options.captcha.enabled) {
      setCaptchaState('disabled');
      setChallenge(null);
      setPowPayload(null);
      setSlider(null);
      resetSlider();
      return;
    }
    setCaptchaState('loading');
    setError('');
    try {
      applyCaptchaResponse(await fetchLoginCaptcha(), options);
    } catch (err) {
      setCaptchaState('error');
      setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
    }
  }, [applyCaptchaResponse, options, resetSlider, t]);

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
          const response = await fetchLoginCaptcha();
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
  }, [applyCaptchaResponse, resetSlider]);

  useEffect(() => {
    if (!options?.captcha.enabled || !challenge || !loginCAPTCHARequiresPow(options)) {
      return undefined;
    }
    const currentChallenge = challenge;
    let cancelled = false;
    async function solvePow() {
      try {
        setCaptchaState('solving');
        const number = await solveSHA256(currentChallenge.salt, currentChallenge.challenge, currentChallenge.max_number);
        if (cancelled) {
          return;
        }
        setPowPayload({
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
  }, [challenge, options, t]);

  useEffect(() => {
    if (!options?.captcha.enabled || captchaState === 'loading' || captchaState === 'error' || captchaState === 'disabled') {
      return;
    }
    if ((!loginCAPTCHARequiresPow(options) || powPayload) && (!isSliderMode(options) || sliderDone)) {
      setCaptchaState('verified');
    } else if (captchaState !== 'solving') {
      setCaptchaState('ready');
    }
  }, [captchaState, options, powPayload, sliderDone]);

  const background = options?.background;
  const backgroundURL = background?.enabled ? background.url.trim() : '';
  const backgroundKind = useMemo(() => resolveBackgroundKind(background?.type, backgroundURL), [background?.type, backgroundURL]);

  if (token) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(values: { username?: string; password?: string; totpCode?: string }) {
    setLoading(true);
    setError('');
    try {
      const captcha = await buildLoginCaptchaIfNeeded({
        options,
        challenge,
        powPayload,
        slider,
        sliderDone,
        sliderX,
        sliderDragMS,
        setCaptchaState,
      });
      const result = await login(values.username ?? '', values.password ?? '', values.totpCode, captcha);
      localStorage.setItem('cheesewaf-token', result.token);
      navigate(from, { replace: true });
    } catch (err) {
      if (err instanceof APIRequestError && err.code === 'TWO_FA_REQUIRED') {
        setRequires2FA(true);
        setError(t('login.totpRequired'));
        return;
      }
      if (err instanceof APIRequestError && err.code === 'INVALID_CAPTCHA') {
        setError(t('login.captchaInvalid'));
        await refreshCaptcha();
        return;
      }
      setError(err instanceof Error ? err.message : 'Login failed');
      if (options?.captcha.enabled) {
        await refreshCaptcha();
      }
    } finally {
      setLoading(false);
    }
  }

  function updateSlider(clientX: number) {
    const track = trackRef.current;
    if (!track || !slider) {
      return;
    }
    const rect = track.getBoundingClientRect();
    const trackWidth = slider.track_width || Math.max(0, slider.width - slider.piece_size);
    const next = clamp(clientX - rect.left - slider.piece_size / 2, 0, trackWidth);
    setSliderX(Math.round(next));
    setSliderDone(false);
  }

  function handlePointerDown(event: React.PointerEvent<HTMLButtonElement>) {
    if (!slider || loading || captchaState === 'loading' || captchaState === 'error') {
      return;
    }
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = { pointerId: event.pointerId, originX: event.clientX, startX: sliderX, startedAt: performance.now() };
  }

  function handlePointerMove(event: React.PointerEvent<HTMLButtonElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId || !slider) {
      return;
    }
    const trackWidth = slider.track_width || Math.max(0, slider.width - slider.piece_size);
    setSliderX(Math.round(clamp(drag.startX + event.clientX - drag.originX, 0, trackWidth)));
    setSliderDone(false);
  }

  function handlePointerUp(event: React.PointerEvent<HTMLButtonElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) {
      return;
    }
    const elapsed = Math.max(0, Math.round(performance.now() - drag.startedAt));
    dragRef.current = null;
    setSliderDragMS(elapsed);
    setSliderDone(sliderX > 0);
  }

  const sliderMode = isSliderMode(options);

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
        <motion.section
          className="auth-panel"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.24 }}
        >
          <div className="auth-brand">
            <span>CW</span>
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
              <div className={`auth-captcha-card auth-captcha-state-${captchaState}`}>
                <div className="auth-captcha-head">
                  <div>
                    <ShieldCheck size={16} />
                    <span>{t(`login.captchaState.${captchaState}`)}</span>
                  </div>
                  <Button
                    size="mini"
                    htmlType="button"
                    icon={<RefreshCcw size={13} />}
                    onClick={refreshCaptcha}
                    disabled={loading || captchaState === 'loading'}
                  />
                </div>
                {sliderMode && slider ? (
                  <div className="auth-slider" style={{ '--slider-width': `${slider.width}px`, '--piece-size': `${slider.piece_size}px` } as CSSProperties}>
                    <button
                      type="button"
                      className="auth-slider-image-button"
                      onPointerDown={(event) => updateSlider(event.clientX)}
                      aria-label={t('login.sliderImage')}
                    >
                      <img className="auth-slider-image" src={slider.image} width={slider.width} height={slider.height} alt="" draggable={false} />
                    </button>
                    <div
                      ref={trackRef}
                      className="auth-slider-track"
                      role="slider"
                      aria-valuemin={0}
                      aria-valuemax={slider.track_width}
                      aria-valuenow={sliderX}
                      aria-label={t('login.sliderLabel')}
                    >
                      <span className="auth-slider-fill" style={{ width: `${sliderX + slider.piece_size / 2}px` }} />
                      <button
                        type="button"
                        className={sliderDone ? 'auth-slider-thumb auth-slider-thumb-done' : 'auth-slider-thumb'}
                        style={{ transform: `translateX(${sliderX}px)` }}
                        onPointerDown={handlePointerDown}
                        onPointerMove={handlePointerMove}
                        onPointerUp={handlePointerUp}
                        onPointerCancel={handlePointerUp}
                      >
                        <MoveRight size={18} />
                      </button>
                      <span className="auth-slider-copy">{sliderDone ? t('login.sliderReleased') : t('login.sliderHint')}</span>
                    </div>
                  </div>
                ) : (
                  <div className="auth-captcha-compact">
                    <span>{t('login.powHint')}</span>
                  </div>
                )}
              </div>
            )}
            <motion.div {...pressable}>
              <Button type="primary" htmlType="submit" loading={loading} long>
                {t('login.submit')}
              </Button>
            </motion.div>
            {error && <p className="form-error">{error}</p>}
          </Form>
        </motion.section>
        <div className="auth-load-time">
          {loadMs == null ? t('login.loading') : t('login.loadTime', { ms: loadMs })}
        </div>
      </div>
    </main>
  );
}

async function buildLoginCaptchaIfNeeded({
  options,
  challenge,
  powPayload,
  slider,
  sliderDone,
  sliderX,
  sliderDragMS,
  setCaptchaState,
}: {
  options: LoginOptions | null;
  challenge: LoginCAPTCHAChallenge | null;
  powPayload: LoginCAPTCHAPayload | null;
  slider: LoginSliderCAPTCHAChallenge | null;
  sliderDone: boolean;
  sliderX: number;
  sliderDragMS: number;
  setCaptchaState: (state: CAPTCHAState) => void;
}): Promise<LoginCAPTCHAPayload | undefined> {
  if (!options?.captcha.enabled) {
    return undefined;
  }
  const sliderMode = isSliderMode(options);
  const needsPow = loginCAPTCHARequiresPow(options);
  const payload: LoginCAPTCHAPayload = {};
  if (needsPow) {
    if (!challenge) {
      throw new Error('captcha challenge is not ready');
    }
    let nextPowPayload = powPayload;
    if (!nextPowPayload) {
      setCaptchaState('solving');
      const number = await solveSHA256(challenge.salt, challenge.challenge, challenge.max_number);
      nextPowPayload = {
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
    if (!slider || !sliderDone) {
      throw new Error('complete slider verification first');
    }
    payload.slider = {
      token: slider.token,
      x: Math.round(sliderX),
      drag_ms: Math.max(sliderDragMS, 0),
    };
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

function isSliderMode(options: LoginOptions | null, responseMode?: string) {
  return String(responseMode || options?.captcha.mode || 'slider').toLowerCase() === 'slider';
}

function loginCAPTCHARequiresPow(options: LoginOptions | null, response?: LoginCAPTCHAResponse) {
  const mode = String(response?.mode || options?.captcha.mode || 'slider').toLowerCase();
  if (mode !== 'slider') {
    return true;
  }
  return Boolean(options?.captcha.slider?.pow_enabled || response?.challenge);
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, value));
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
