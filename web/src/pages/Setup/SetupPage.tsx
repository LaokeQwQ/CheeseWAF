import { Button, Form, Input, Steps } from '@arco-design/web-react';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { LockKeyhole, Network, UserRound } from 'lucide-react';
import { pressable } from '../../animations/micro';
import { setupAdmin } from '../../api/client';

export default function SetupPage() {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  async function handleSubmit(values: { username?: string; password?: string; adminListen?: string }) {
    setLoading(true);
    setMessage('');
    try {
      await setupAdmin(values.username ?? '', values.password ?? '', values.adminListen ?? '127.0.0.1:9443');
      setMessage(t('setup.complete'));
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Setup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-screen setup-screen">
      <section className="auth-panel setup-panel">
        <div className="auth-brand">
          <span>CW</span>
          <div>
            <h1>{t('setup.title')}</h1>
            <p>{t('setup.subtitle')}</p>
          </div>
        </div>

        <Steps current={1} size="small" className="setup-steps">
          <Steps.Step title={t('setup.account')} icon={<UserRound size={16} />} />
          <Steps.Step title={t('setup.network')} icon={<Network size={16} />} />
          <Steps.Step title={t('setup.complete')} icon={<LockKeyhole size={16} />} />
        </Steps>

        <Form layout="vertical" className="auth-form" onSubmit={handleSubmit}>
          <Form.Item label={t('setup.username')} field="username">
            <Input placeholder="admin" />
          </Form.Item>
          <Form.Item label={t('setup.password')} field="password">
            <Input.Password placeholder="********" />
          </Form.Item>
          <Form.Item label={t('setup.adminListen')} field="adminListen">
            <Input defaultValue="127.0.0.1:9443" />
          </Form.Item>
          <motion.div {...pressable}>
            <Button type="primary" htmlType="submit" loading={loading} long>
              {t('common.next')}
            </Button>
          </motion.div>
          {message && <p className="form-error">{message}</p>}
        </Form>
      </section>
    </main>
  );
}
