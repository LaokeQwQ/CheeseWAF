import { useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Space, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { BrainCircuit, PlugZap, ShieldCheck } from 'lucide-react';
import { analyzeLog, fetchAIConfig, testAIConnection, updateAIConfig } from '../../api/client';
import type { AIConfig } from '../../types/api';

const fallback: AIConfig = {
  enabled: false,
  api_base: 'https://api.openai.com/v1',
  api_key: '',
  api_key_set: false,
  model: 'gpt-4o-mini',
  async: true,
};

const sampleLog = JSON.stringify({
  id: 'sample-1',
  method: 'GET',
  uri: '/search?q=1%20or%201=1',
  client_ip: '203.0.113.10',
  action: 'block',
  category: 'sqli',
  severity: 'high',
  message: 'SQL injection pattern matched',
}, null, 2);

export default function AIPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [rawLog, setRawLog] = useState(sampleLog);
  const { data } = useQuery({ queryKey: ['ai-config'], queryFn: fetchAIConfig, retry: false });
  const config = data ?? fallback;
  const updateMutation = useMutation({
    mutationFn: updateAIConfig,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ai-config'] }),
  });
  const testMutation = useMutation({
    mutationFn: testAIConnection,
    onSuccess: () => ArcoMessage.success(t('ai.testOk')),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const analysisMutation = useMutation({
    mutationFn: analyzeLog,
    onError: (error) => ArcoMessage.error(error.message),
  });

  const runAnalysis = () => {
    try {
      analysisMutation.mutate(JSON.parse(rawLog));
    } catch (error) {
      ArcoMessage.error(error instanceof Error ? error.message : 'Invalid JSON');
    }
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ai.title')}</h1>
          <p>{t('ai.subtitle')}</p>
        </div>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2><PlugZap size={16} /> {t('ai.connection')}</h2>
            <Button icon={<ShieldCheck size={14} />} onClick={() => testMutation.mutate()} loading={testMutation.isPending}>
              {t('ai.test')}
            </Button>
          </div>
          <Form
            key={`ai-${config.enabled}-${config.api_base}-${config.model}-${config.api_key_set}`}
            layout="vertical"
            initialValues={{
              enabled: config.enabled,
              apiBase: config.api_base,
              apiKey: config.api_key,
              model: config.model,
              async: config.async,
            }}
            onSubmit={(values) => updateMutation.mutate({
              enabled: values.enabled,
              api_base: values.apiBase,
              api_key: values.apiKey,
              api_key_set: config.api_key_set,
              model: values.model,
              async: values.async,
            })}
          >
            <Form.Item label={t('ai.enabled')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('ai.apiBase')} field="apiBase"><Input /></Form.Item>
            <Form.Item label={t('ai.model')} field="model"><Input /></Form.Item>
            <Form.Item label={t('ai.apiKey')} field="apiKey">
              <Input.Password placeholder={config.api_key_set ? t('ai.keyStored') : ''} />
            </Form.Item>
            <Form.Item label={t('ai.async')} field="async"><Switch /></Form.Item>
            <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><BrainCircuit size={16} /> {t('ai.analysis')}</h2></div>
          <Input.TextArea value={rawLog} autoSize={{ minRows: 10, maxRows: 16 }} onChange={setRawLog} />
          <div style={{ marginTop: 12 }}>
            <Button type="primary" onClick={runAnalysis} loading={analysisMutation.isPending}>{t('ai.run')}</Button>
          </div>
        </section>
      </div>

      {analysisMutation.data && (
        <section className="table-panel">
          <div className="panel-heading">
            <h2>{t('ai.result')}</h2>
            <Tag color={riskColor(analysisMutation.data.risk)}>{analysisMutation.data.risk}</Tag>
          </div>
          <p>{analysisMutation.data.summary}</p>
          <Space direction="vertical" size={8}>
            {analysisMutation.data.recommended_actions.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </Space>
        </section>
      )}
    </section>
  );
}

function riskColor(risk: string) {
  switch (risk) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orangered';
    case 'medium':
      return 'orange';
    default:
      return 'green';
  }
}
