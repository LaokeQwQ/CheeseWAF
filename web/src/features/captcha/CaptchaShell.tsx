import type { ReactNode } from 'react';
import { Check, RefreshCw, X, XCircle } from 'lucide-react';
import type { CaptchaLocale } from './i18n';
import { captchaText } from './i18n';
import type { CaptchaStatus } from './BehaviorCaptcha';
import styles from './CaptchaShell.module.css';

export interface CaptchaShellProps {
  title: string;
  prompt: string;
  locale: CaptchaLocale;
  status: CaptchaStatus;
  message?: string;
  logoSrc?: string;
  className?: string;
  refreshDisabled?: boolean;
  onRefresh: () => void;
  onClose?: () => void;
  children: ReactNode;
}

export function CaptchaShell({ title, prompt, locale, status, message, logoSrc = '/cheesewaf-logo.png', className, refreshDisabled, onRefresh, onClose, children }: CaptchaShellProps) {
  const busy = status === 'loading' || status === 'verifying';
  return (
    <section className={`${styles.shell} ${className ?? ''}`} data-status={status} aria-busy={busy}>
      <header className={styles.header}>
        <div className={styles.heading}><strong>{title}</strong><p>{prompt}</p></div>
      </header>
      <div className={styles.body}>{children}</div>
      {message && (
        <div className={styles.status} data-tone={status} role="status" aria-live="polite">
          {status === 'success' ? <Check size={16} /> : status === 'failure' || status === 'error' ? <XCircle size={16} /> : null}
          <span>{message}</span>
        </div>
      )}
      <footer className={styles.footer}>
        <span className={styles.brand} aria-label="CheeseWAF">
          <img className={styles.logo} src={logoSrc} alt="" draggable={false} />
          <strong>CheeseWAF</strong>
        </span>
        <div className={styles.actions}>
          <button type="button" className={styles.iconButton} aria-label={captchaText(locale, 'retry')} title={captchaText(locale, 'retry')} disabled={refreshDisabled || status === 'success'} onClick={onRefresh}><RefreshCw size={17} /></button>
          {onClose && <button type="button" className={styles.iconButton} aria-label={captchaText(locale, 'close')} title={captchaText(locale, 'close')} onClick={onClose}><X size={18} /></button>}
        </div>
      </footer>
    </section>
  );
}
