import { RefreshCw, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { issueCaptchaLabChallenge, verifyCaptchaLabChallenge } from '../../api/client';
import { BehaviorCaptcha, CAPTCHA_TYPES, type CaptchaStatus, type CaptchaType, type IssueCaptcha, type VerifyCaptcha } from '../../features/captcha';
import styles from './CaptchaLabPage.module.css';

export interface CaptchaLabPageProps { issue?: IssueCaptcha; verify?: VerifyCaptcha }

export default function CaptchaLabPage({ issue = issueCaptchaLabChallenge, verify = verifyCaptchaLabChallenge }: CaptchaLabPageProps) {
  const { t, i18n } = useTranslation();
  const locale = i18n.resolvedLanguage?.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
  const [type, setType] = useState<CaptchaType>('random');
  const [generation, setGeneration] = useState(0);
  const [status, setStatus] = useState<CaptchaStatus>('loading');

  return (
    <main className={styles.page} aria-labelledby="captcha-lab-title">
      <header className={styles.pageHeader}>
        <div>
          <span className={styles.eyebrow}><ShieldCheck size={16} />{t('captchaLab.eyebrow')}</span>
          <h1 id="captcha-lab-title">{t('captchaLab.title')}</h1>
          <p>{t('captchaLab.subtitle')}</p>
        </div>
        <span className={`${styles.status} ${styles[status]}`}>{t(`captchaLab.status.${status}`)}</span>
      </header>
      <section className={styles.controls} aria-label={t('captchaLab.controlsAria')}>
        <label>
          <span>{t('captchaLab.challengeType')}</span>
          <select value={type} onChange={(event) => setType(event.target.value as CaptchaType)}>
            {CAPTCHA_TYPES.map((item) => (
              <option key={item} value={item}>{t(`captchaLab.types.${item}`)}</option>
            ))}
          </select>
        </label>
        <button type="button" onClick={() => setGeneration((current) => current + 1)}>
          <RefreshCw size={16} />{t('captchaLab.regenerate')}
        </button>
      </section>
      <section className={styles.stage}>
        <BehaviorCaptcha key={`${type}-${generation}`} type={type} issue={issue} verify={verify} locale={locale} onStatusChange={setStatus} />
      </section>
    </main>
  );
}
