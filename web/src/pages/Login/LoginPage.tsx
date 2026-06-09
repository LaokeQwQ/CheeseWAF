import { Button, Form, Input } from '@arco-design/web-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { LockKeyhole, RefreshCcw, ShieldCheck, UserRound } from 'lucide-react';
import { pressable } from '../../animations/micro';
import { APIRequestError, fetchLoginCaptcha, fetchLoginOptions, login } from '../../api/client';
import type { LoginCAPTCHAChallenge, LoginCAPTCHAPayload, LoginOptions } from '../../types/api';

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [requires2FA, setRequires2FA] = useState(false);
  const [options, setOptions] = useState<LoginOptions | null>(null);
  const [challenge, setChallenge] = useState<LoginCAPTCHAChallenge | null>(null);
  const [captchaState, setCaptchaState] = useState<'loading' | 'ready' | 'solving' | 'verified' | 'disabled' | 'error'>('loading');
  const [loadMs, setLoadMs] = useState<number | null>(null);
  const token = localStorage.getItem('cheesewaf-token');
  const from = ((location.state as { from?: string } | null)?.from ?? '/') || '/';

  const refreshCaptcha = useCallback(async () => {
    if (options && !options.captcha.enabled) {
      setCaptchaState('disabled');
      setChallenge(null);
      return;
    }
    setCaptchaState('loading');
    try {
      const response = await fetchLoginCaptcha();
      if (!response.enabled) {
        setCaptchaState('disabled');
        setChallenge(null);
        return;
      }
      if (!response.challenge) {
        throw new Error(t('login.captchaUnavailable'));
      }
      setChallenge(response.challenge);
      setCaptchaState('ready');
    } catch (err) {
      setCaptchaState('error');
      setError(err instanceof Error ? err.message : t('login.captchaUnavailable'));
    }
  }, [options, t]);

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
          if (cancelled) {
            return;
          }
          if (response.enabled && response.challenge) {
            setChallenge(response.challenge);
            setCaptchaState('ready');
          } else {
            setChallenge(null);
            setCaptchaState('disabled');
          }
        } else {
          setChallenge(null);
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
  }, [t]);

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
      const captcha = await solveLoginCaptchaIfNeeded(options, challenge, setCaptchaState);
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
              <div className={`auth-captcha-state auth-captcha-state-${captchaState}`}>
                <ShieldCheck size={16} />
                <span>{t(`login.captchaState.${captchaState}`)}</span>
                <Button
                  size="mini"
                  htmlType="button"
                  icon={<RefreshCcw size={13} />}
                  onClick={refreshCaptcha}
                  disabled={loading || captchaState === 'loading' || captchaState === 'solving'}
                />
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

async function solveLoginCaptchaIfNeeded(
  options: LoginOptions | null,
  challenge: LoginCAPTCHAChallenge | null,
  setCaptchaState: (state: 'loading' | 'ready' | 'solving' | 'verified' | 'disabled' | 'error') => void,
): Promise<LoginCAPTCHAPayload | undefined> {
  if (!options?.captcha.enabled) {
    return undefined;
  }
  if (!challenge) {
    throw new Error('captcha challenge is not ready');
  }
  setCaptchaState('solving');
  const number = await solveSHA256(challenge.salt, challenge.challenge, challenge.max_number);
  setCaptchaState('verified');
  return {
    algorithm: challenge.algorithm,
    challenge: challenge.challenge,
    number,
    salt: challenge.salt,
    signature: challenge.signature,
  };
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
      algorithm: value?.captcha?.algorithm ?? 'SHA-256',
      max_number: value?.captcha?.max_number ?? 75000,
    },
    background: {
      enabled: value?.background?.enabled ?? false,
      type: value?.background?.type || 'auto',
      url: value?.background?.url || '',
    },
  };
}
