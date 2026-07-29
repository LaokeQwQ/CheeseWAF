import { Button, Form, Input, Message as ArcoMessage, Select, Steps } from '@arco-design/web-react';
import '../../styles/arco-components';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { LockKeyhole, Network, UserRound } from 'lucide-react';
import { setupAdmin } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import { passwordPolicyErrorKey } from '../../utils/passwordPolicy';

export default function SetupPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [done, setDone] = useState(false);
  const step = useMemo(() => (done ? 3 : 1), [done]);

  async function handleSubmit(values: { username?: string; password?: string; adminListen?: string; adminStrategy?: string }) {
    setLoading(true);
    setMessage('');
    try {
      await setupAdmin(values.username ?? '', values.password ?? '', values.adminListen ?? '127.0.0.1:9443', values.adminStrategy ?? 'local');
      setDone(true);
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
          <Steps.Step title={t('setup.account')} icon={<UserRound size={16} />} />
          <Steps.Step title={t('setup.network')} icon={<Network size={16} />} />
          <Steps.Step title={t('setup.complete')} icon={<LockKeyhole size={16} />} />
        </Steps>

        <Form layout="vertical" className="auth-form" onSubmit={handleSubmit} disabled={done}>
          <Form.Item
            label={t('setup.username')}
            field="username"
            rules={[{ required: true, message: t('setup.usernameRequired') }]}
          >
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
                  // username field may lag; policy still rejects weak patterns server-side
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
            <Input.Password placeholder="********" autoComplete="new-password" />
          </Form.Item>
          <Form.Item label={t('setup.adminListen')} field="adminListen">
            <Input defaultValue="127.0.0.1:9443" />
          </Form.Item>
          <Form.Item label={t('setup.adminStrategy')} field="adminStrategy" initialValue="local">
            <Select>
              <Select.Option value="local">{t('setup.strategyLocal')}</Select.Option>
              <Select.Option value="public_tls">{t('setup.strategyPublicTLS')}</Select.Option>
            </Select>
          </Form.Item>
          <div className="pressable">
            <Button type="primary" htmlType="submit" loading={loading} disabled={done} long>
              {done ? t('setup.complete') : t('common.next')}
            </Button>
          </div>
          {message && <p className={done ? 'form-success' : 'form-error'} role="status">{message}</p>}
        </Form>
      </section>
    </main>
  );
}
