import { Button, Checkbox, Form, Input, Message as ArcoMessage, Radio, Select, Steps } from '../../ui';
import '../../styles/arco-components';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { CheckCircle2, Cpu, LockKeyhole, Network, UserRound } from 'lucide-react';
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
      ArcoMessage.success(t('setup.success'));
      window.setTimeout(() => navigate('/login', { replace: true }), 800);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : t('setup.failed'));
    } finally {
      setLoading(false);
    }
  }

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

        <Steps current={step} size="small" className="setup-steps">
          <Steps.Step title={t('setup.probe', { defaultValue: 'Probe' })} icon={<Cpu size={16} />} />
          <Steps.Step title={t('setup.profile', { defaultValue: 'Profile' })} icon={<Network size={16} />} />
          <Steps.Step title={t('setup.account')} icon={<UserRound size={16} />} />
          <Steps.Step title={t('setup.review', { defaultValue: 'Review' })} icon={<CheckCircle2 size={16} />} />
          <Steps.Step title={t('setup.complete')} icon={<LockKeyhole size={16} />} />
        </Steps>

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
            <Button type="primary" long disabled={!probe} onClick={() => setStep(1)}>
              {t('common.next', { defaultValue: 'Next' })}
            </Button>
          </div>
        )}

        {step === 1 && (
          <div className="auth-form">
            <Radio.Group value={profile} onChange={(v) => setProfile(v as ProfileKey)} direction="vertical">
              <Radio value="low">low</Radio>
              <Radio value="medium">medium</Radio>
              <Radio value="high">high</Radio>
              <Radio value="custom">custom (advanced knobs after install)</Radio>
            </Radio.Group>
            <div className="setup-actions" style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <Button onClick={() => setStep(0)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button type="primary" onClick={async () => { await persistDraft({ profile }); setStep(2); }}>
                {t('common.next', { defaultValue: 'Next' })}
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <Form
            layout="vertical"
            className="auth-form"
            initialValues={account}
            onSubmit={async (values) => {
              const next = {
                username: values.username ?? '',
                password: values.password ?? '',
                adminListen: values.adminListen ?? '127.0.0.1:9443',
                adminStrategy: values.adminStrategy ?? 'local',
              };
              setAccount(next);
              await persistDraft({
                username: next.username,
                password: next.password,
                admin_listen: next.adminListen,
                admin_strategy: next.adminStrategy,
              });
              setStep(3);
            }}
          >
            <Form.Item label={t('setup.username')} field="username" rules={[{ required: true, message: t('setup.usernameRequired') }]}>
              <Input placeholder="admin" autoComplete="username" />
            </Form.Item>
            <Form.Item
              label={t('setup.password')}
              field="password"
              extra={t('users.passwordHint')}
              rules={[
                { required: true, message: t('setup.passwordRequired') },
                {
                  validator: (value, callback) => {
                    const password = value == null ? '' : String(value);
                    if (!password) {
                      callback();
                      return;
                    }
                    const key = passwordPolicyErrorKey(password, '');
                    if (key) {
                      callback(t(`passwordPolicy.${key}`));
                      return;
                    }
                    callback();
                  },
                },
              ]}
            >
              <Input.Password autoComplete="new-password" placeholder="********" />
            </Form.Item>
            <Form.Item label={`${t('setup.network')} / ${t('setup.adminListen')}`} field="adminListen" rules={[{ required: true }]}>
              <Input placeholder="127.0.0.1:9443" />
            </Form.Item>
            <Form.Item label={t('setup.adminStrategy', { defaultValue: 'Admin strategy' })} field="adminStrategy">
              <Select
                options={[
                  { value: 'local', label: t('setup.strategyLocal') },
                  { value: 'public_tls', label: t('setup.strategyPublicTLS') },
                ]}
              />
            </Form.Item>
            <div className="setup-actions" style={{ display: 'flex', gap: 8 }}>
              <Button onClick={() => setStep(1)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button type="primary" htmlType="submit">{t('common.next', { defaultValue: 'Next' })}</Button>
            </div>
          </Form>
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
            <Checkbox checked={confirmed} onChange={setConfirmed}>
              {t('setup.confirmCheck', { defaultValue: 'I have reviewed the settings and want to complete setup.' })}
            </Checkbox>
            <div className="setup-actions" style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              <Button onClick={() => setStep(2)}>{t('common.back', { defaultValue: 'Back' })}</Button>
              <Button type="primary" loading={loading} disabled={!confirmed || done} onClick={handleComplete}>
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
