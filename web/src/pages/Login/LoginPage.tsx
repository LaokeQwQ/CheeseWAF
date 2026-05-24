import { Button, Form, Input } from '@arco-design/web-react';
import { useState } from 'react';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { LockKeyhole, UserRound } from 'lucide-react';
import { pressable } from '../../animations/micro';
import { login } from '../../api/client';

export default function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(values: { username?: string; password?: string }) {
    setLoading(true);
    setError('');
    try {
      const result = await login(values.username ?? '', values.password ?? '');
      localStorage.setItem('cheesewaf-token', result.token);
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-screen">
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
          <Form.Item label={t('login.username')}>
            <Input prefix={<UserRound size={16} />} placeholder="admin" />
          </Form.Item>
          <Form.Item label={t('login.password')}>
            <Input.Password prefix={<LockKeyhole size={16} />} placeholder="********" />
          </Form.Item>
          <motion.div {...pressable}>
            <Button type="primary" htmlType="submit" loading={loading} long>
              {t('login.submit')}
            </Button>
          </motion.div>
          {error && <p className="form-error">{error}</p>}
        </Form>
      </motion.section>
    </main>
  );
}
