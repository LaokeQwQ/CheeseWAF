import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import type { CapErrorEvent, CapSolveEvent, CapWidget } from 'cap-widget';
import type { LoginCapCAPTCHAChallenge } from '../../types/api';

type CapLoginCaptchaProps = {
  challenge: LoginCapCAPTCHAChallenge;
  locale: string;
  onSolve: (token: string) => void;
  onError: () => void;
};

export function CapLoginCaptcha({ challenge, locale, onSolve, onError }: CapLoginCaptchaProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { t } = useTranslation('translation', { lng: locale });

  useEffect(() => {
    let disposed = false;
    let widget: CapWidget | null = null;
    let wasmURL: string | undefined;
    let hashwxURL: string | undefined;
    const previousWasmURL = window.CAP_CUSTOM_WASM_URL;
    const previousHashwxURL = window.CAP_CUSTOM_HASHWX_URL;

    const handleSolve = (event: CapSolveEvent) => {
      if (!disposed && typeof event.detail?.token === 'string' && event.detail.token.length > 0) {
        onSolve(event.detail.token);
      }
    };
    const handleError = (_event: CapErrorEvent) => {
      if (!disposed) onError();
    };

    void (async () => {
      try {
        const apiEndpoint = resolveCapURL(challenge.api_endpoint);
        wasmURL = resolveCapURL(challenge.wasm_url);
        hashwxURL = resolveCapURL(challenge.hashwx_url);
        window.CAP_CUSTOM_WASM_URL = wasmURL;
        window.CAP_CUSTOM_HASHWX_URL = hashwxURL;

        await import('cap-widget');
        if (disposed || !containerRef.current) return;

        widget = document.createElement('cap-widget');
        widget.setAttribute('data-cap-api-endpoint', apiEndpoint);
        widget.setAttribute('data-cap-i18n-initial-state', t('login.capInitialState'));
        widget.setAttribute('data-cap-i18n-verifying-label', t('login.capVerifyingLabel'));
        widget.setAttribute('data-cap-i18n-solved-label', t('login.capSolvedLabel'));
        widget.setAttribute('data-cap-i18n-error-label', t('login.capErrorLabel'));
        widget.setAttribute('data-cap-i18n-verify-aria-label', t('login.capVerifyAriaLabel'));
        widget.setAttribute('data-cap-i18n-verifying-aria-label', t('login.capVerifyingAriaLabel'));
        widget.setAttribute('data-cap-i18n-verified-aria-label', t('login.capVerifiedAriaLabel'));
        widget.setAttribute('data-cap-i18n-error-aria-label', t('login.capErrorAriaLabel'));
        widget.addEventListener('solve', handleSolve);
        widget.addEventListener('error', handleError);
        containerRef.current.replaceChildren(widget);
      } catch {
        if (!disposed) onError();
      }
    })();

    return () => {
      disposed = true;
      widget?.removeEventListener('solve', handleSolve);
      widget?.removeEventListener('error', handleError);
      widget?.remove();
      if (containerRef.current) containerRef.current.replaceChildren();
      if (wasmURL && window.CAP_CUSTOM_WASM_URL === wasmURL) {
        if (previousWasmURL === undefined) delete window.CAP_CUSTOM_WASM_URL;
        else window.CAP_CUSTOM_WASM_URL = previousWasmURL;
      }
      if (hashwxURL && window.CAP_CUSTOM_HASHWX_URL === hashwxURL) {
        if (previousHashwxURL === undefined) delete window.CAP_CUSTOM_HASHWX_URL;
        else window.CAP_CUSTOM_HASHWX_URL = previousHashwxURL;
      }
    };
  }, [challenge.api_endpoint, challenge.challenge_id, challenge.hashwx_url, challenge.wasm_url, locale, onError, onSolve, t]);

  return <div ref={containerRef} className="flex min-h-[58px] items-center justify-center" data-testid="cap-widget-container" data-challenge-id={challenge.challenge_id} />;
}

function resolveCapURL(value: string) {
  const url = new URL(value, window.location.href);
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
    throw new Error('Invalid Cap resource URL');
  }
  if (window.location.protocol === 'https:' && url.protocol !== 'https:' && url.origin !== window.location.origin) {
    throw new Error('Insecure Cap resource URL');
  }
  return url.href;
}
