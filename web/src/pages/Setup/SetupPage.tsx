import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, Cpu, LockKeyhole, Network, UserRound } from 'lucide-react';
import {
  Button,
  Checkbox,
  Input,
  Label,
  RadioGroup,
  RadioGroupItem,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  toast,
} from '@/components/ui';
import { apiClient, setupAdmin, unwrapAPIResponse } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import { passwordPolicyErrorKey } from '../../utils/passwordPolicy';

type ProbeResult = {
  profile: 'low' | 'medium' | 'high' | 'custom';
  incomplete?: boolean;
  cpu_logical?: number;
  memory_total_mb?: number;
  disk_write_mbps?: number;
  notes?: string[];
  suggested_config?: Record<string, unknown>;
};

type ProfileKey = 'low' | 'medium' | 'high' | 'custom';

export default function SetupPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [done, setDone] = useState(false);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [profile, setProfile] = useState<ProfileKey>('medium');
  const [confirmed, setConfirmed] = useState(false);
  const [account, setAccount] = useState({ username: '', password: '', adminListen: '127.0.0.1:9443', adminStrategy: 'local' });
  const [accountError, setAccountError] = useState('');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await unwrapAPIResponse<{ probe: ProbeResult }>(apiClient.post('/setup/probe', {}));
        if (!cancelled) {
          setProbe(data.probe);
          if (data.probe?.profile && data.probe.profile !== 'custom') {
            setProfile(data.probe.profile);
          }
        }
      } catch {
        // Probe is best-effort; operator can still complete setup with conservative defaults.
        if (!cancelled) {
          setProbe({ profile: 'low', incomplete: true, notes: ['probe unavailable'] });
          setProfile('low');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function persistDraft(patch: Record<string, unknown>) {
    try {
      await unwrapAPIResponse(apiClient.patch('/setup/draft', patch));
    } catch {
      /* draft optional when probe failed */
    }
  }

  async function handleAccountSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccountError('');
    const next = {
      username: account.username.trim(),
      password: account.password,
      adminListen: account.adminListen.trim() || '127.0.0.1:9443',
      adminStrategy: account.adminStrategy || 'local',
    };
    if (!next.username) {
      setAccountError(t('setup.usernameRequired'));
      return;
    }
    if (!next.password) {
      setAccountError(t('setup.passwordRequired'));
      return;
    }
    const policyKey = passwordPolicyErrorKey(next.password, '');
    if (policyKey) {
      setAccountError(t(`passwordPolicy.${policyKey}`));
      return;
    }
    if (!next.adminListen) {
      setAccountError(t('setup.adminListen', { defaultValue: 'Admin listen address is required.' }));
      return;
    }
    setAccount(next);
    await persistDraft({
      username: next.username,
      password: next.password,
      admin_listen: next.adminListen,
      admin_strategy: next.adminStrategy,
    });
    setStep(3);
  }

  async function handleComplete() {
    if (!confirmed) {
      setMessage(t('setup.confirmRequired', { defaultValue: 'Confirm the review checklist before completing setup.' }));
      return;
    }
    setLoading(true);
    setMessage('');
    try {
      await persistDraft({
        profile,
        username: account.username,
        password: account.password,
        admin_listen: account.adminListen,
        admin_strategy: account.adminStrategy,
        confirmed: true,
      });
      await setupAdmin(account.username, account.password, account.adminListen, account.adminStrategy);
      setDone(true);
      setStep(4);
      setMessage(t('setup.success'));
      toast.success(t('setup.success'));
      window.setTimeout(() => navigate('/login', { replace: true }), 800);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : t('setup.failed'));
    } finally {
      setLoading(false);
    }
  }

  const steps = [
    { title: t('setup.probe', { defaultValue: 'Probe' }), icon: <Cpu size={16} /> },
    { title: t('setup.profile', { defaultValue: 'Profile' }), icon: <Network size={16} /> },
    { title: t('setup.account'), icon: <UserRound size={16} /> },
    { title: t('setup.review', { defaultValue: 'Review' }), icon: <CheckCircle2 size={16} /> },
    { title: t('setup.complete'), icon: <LockKeyhole size={16} /> },
  ];

  return (
    <main className="auth-screen setup-screen">
      <section className="auth-panel setup-panel">
        <div className="auth-brand">
          <span><BrandLogo /></span>
          <div>
            <h1>{t('setup.title')}</h1>
            <p>{t('setup.subtitle')}</p>
          </div>
        </div>

        <ol className="setup-steps flex flex-wrap items-center gap-3 text-sm">
          {steps.map((item, index) => (
            <li
              key={item.title}
              className={[
                'inline-flex items-center gap-1.5',
                index === step ? 'font-semibold text-foreground' : 'text-muted-foreground',
                index < step ? 'opacity-80' : '',
              ].filter(Boolean).join(' ')}
              aria-current={index === step ? 'step' : undefined}
            >
              <span aria-hidden="true">{item.icon}</span>
              <span>{item.title}</span>
              {index < steps.length - 1 ? <span className="ml-1 text-muted-foreground/60" aria-hidden="true">/</span> : null}
            </li>
          ))}
        </ol>

        {step === 0 && (
          <div className="auth-form">
            <p>{t('setup.probeHint', { defaultValue: 'First-install hardware probe (max 30s). Incomplete probes fall back to low profile.' })}</p>
            {probe ? (
              <ul className="setup-probe-list">
                <li>CPU: {probe.cpu_logical ?? '—'}</li>
                <li>Memory MB: {probe.memory_total_mb ?? '—'}</li>
                <li>Disk MB/s: {probe.disk_write_mbps?.toFixed?.(1) ?? '—'}</li>
                <li>Recommended: {probe.profile}{probe.incomplete ? ' (incomplete)' : ''}</li>
                {(probe.notes ?? []).map((n) => <li key={n}>{n}</li>)}
              </ul>
            ) : (
              <p>{t('common.loading')}</p>
            )}
            <Button className="w-full" disabled={!probe} onClick={() => setStep(1)}>
              {t('common.next', { defaultValue: 'Next' })}
            </Button>
          </div>
        )}

        {step === 1 && (
          <div className="auth-form">
            <RadioGroup
              value={profile}
              onValueChange={(value) => setProfile(value as ProfileKey)}
              className="grid gap-3"
            >
              {([
                { value: 'low', label: 'low' },
                { value: 'medium', label: 'medium' },
                { value: 'high', label: 'high' },
                { value: 'custom', label: 'custom (advanced knobs after install)' },
              ] as const).map((option) => (
                <div key={option.value} className="flex items-center gap-2">
                  <RadioGroupItem value={option.value} id={`setup-profile-${option.value}`} />
                  <Label htmlFor={`setup-profile-${option.value}`} className="font-normal">
                    {option.label}
                  </Label>
                </div>
              ))}
            </RadioGroup>
            <div className="setup-actions" style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <Button variant="outline" onClick={() => setStep(0)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button onClick={async () => { await persistDraft({ profile }); setStep(2); }}>
                {t('common.next', { defaultValue: 'Next' })}
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <form className="auth-form" onSubmit={handleAccountSubmit}>
            <div className="mb-3.5 grid gap-1.5">
              <Label htmlFor="setup-username">{t('setup.username')}</Label>
              <Input
                id="setup-username"
                placeholder="admin"
                autoComplete="username"
                value={account.username}
                onChange={(event) => setAccount((prev) => ({ ...prev, username: event.target.value }))}
              />
            </div>
            <div className="mb-3.5 grid gap-1.5">
              <Label htmlFor="setup-password">{t('setup.password')}</Label>
              <Input
                id="setup-password"
                type="password"
                autoComplete="new-password"
                placeholder="********"
                value={account.password}
                onChange={(event) => setAccount((prev) => ({ ...prev, password: event.target.value }))}
              />
              <p className="text-xs text-muted-foreground">{t('users.passwordHint')}</p>
            </div>
            <div className="mb-3.5 grid gap-1.5">
              <Label htmlFor="setup-admin-listen">{`${t('setup.network')} / ${t('setup.adminListen')}`}</Label>
              <Input
                id="setup-admin-listen"
                placeholder="127.0.0.1:9443"
                value={account.adminListen}
                onChange={(event) => setAccount((prev) => ({ ...prev, adminListen: event.target.value }))}
              />
            </div>
            <div className="mb-3.5 grid gap-1.5">
              <Label htmlFor="setup-admin-strategy">{t('setup.adminStrategy', { defaultValue: 'Admin strategy' })}</Label>
              <Select
                value={account.adminStrategy}
                onValueChange={(value) => setAccount((prev) => ({ ...prev, adminStrategy: value }))}
              >
                <SelectTrigger id="setup-admin-strategy">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="local">{t('setup.strategyLocal')}</SelectItem>
                  <SelectItem value="public_tls">{t('setup.strategyPublicTLS')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {accountError ? <p className="auth-error" role="alert">{accountError}</p> : null}
            <div className="setup-actions" style={{ display: 'flex', gap: 8 }}>
              <Button type="button" variant="outline" onClick={() => setStep(1)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button type="submit">{t('common.next', { defaultValue: 'Next' })}</Button>
            </div>
          </form>
        )}

        {step === 3 && (
          <div className="auth-form">
            <p>{t('setup.reviewHint', { defaultValue: 'Review the settings that will be written, then confirm to complete setup.' })}</p>
            <ul>
              <li>profile: {profile}</li>
              <li>username: {account.username}</li>
              <li>admin_listen: {account.adminListen}</li>
              <li>admin_strategy: {account.adminStrategy}</li>
            </ul>
            <div className="flex items-start gap-2">
              <Checkbox
                id="setup-confirm"
                checked={confirmed}
                onCheckedChange={(value) => setConfirmed(value === true)}
              />
              <Label htmlFor="setup-confirm" className="font-normal leading-snug">
                {t('setup.confirmCheck', { defaultValue: 'I have reviewed the settings and want to complete setup.' })}
              </Label>
            </div>
            <div className="setup-actions" style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <Button variant="outline" onClick={() => setStep(2)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button loading={loading} disabled={!confirmed || done} onClick={handleComplete}>
                {t('setup.complete')}
              </Button>
            </div>
          </div>
        )}

        {step === 4 && done && (
          <p className="auth-success">{t('setup.success')}</p>
        )}

        {message && <p className={done ? 'auth-success' : 'auth-error'}>{message}</p>}
      </section>
    </main>
  );
}
