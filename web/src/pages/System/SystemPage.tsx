import { Button, Form, InputNumber, Select, Slider, Switch } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import i18n from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';

export default function SystemPage() {
  const { t } = useTranslation();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const setTheme = useAppStore((state) => state.setTheme);
  const setLanguage = useAppStore((state) => state.setLanguage);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('system.title')}</h1>
          <p>{t('system.subtitle')}</p>
        </div>
        <Button type="primary">{t('common.save')}</Button>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>{t('system.theme')}</h2>
          </div>
          <Form layout="vertical">
            <Form.Item label={t('system.theme')}>
              <Select value={theme} onChange={(value) => setTheme(value as ThemeName)}>
                {themeOptions.map((option) => (
                  <Select.Option key={option.value} value={option.value}>
                    {t(option.labelKey)}
                  </Select.Option>
                ))}
              </Select>
            </Form.Item>
            <Form.Item label={t('system.language')}>
              <Select
                value={language}
                onChange={(value) => {
                  const next = value as Language;
                  setLanguage(next);
                  i18n.changeLanguage(next);
                }}
              >
                <Select.Option value="zh-CN">中文</Select.Option>
                <Select.Option value="en-US">English</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="2FA">
              <Switch defaultChecked />
            </Form.Item>
          </Form>
        </section>

        <section className="panel panel-wide">
          <div className="panel-heading">
            <h2>{t('system.performance')}</h2>
          </div>
          <Form layout="vertical" className="performance-form">
            <Form.Item label={t('system.maxConnections')}>
              <InputNumber defaultValue={10000} min={100} max={100000} step={100} />
            </Form.Item>
            <Form.Item label={t('system.bodyLimit')}>
              <Slider defaultValue={64} min={1} max={512} marks={{ 1: '1MB', 256: '256MB', 512: '512MB' }} />
            </Form.Item>
            <Form.Item label={t('system.timeout')}>
              <Slider defaultValue={30} min={1} max={120} marks={{ 1: '1s', 60: '60s', 120: '120s' }} />
            </Form.Item>
          </Form>
        </section>
      </div>
    </section>
  );
}
