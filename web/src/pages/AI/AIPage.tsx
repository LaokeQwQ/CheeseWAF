import { useEffect, useMemo, useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Select, Space, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { BrainCircuit, Eye, ListChecks, PlugZap, ShieldCheck } from 'lucide-react';
import { analyzeEvents, analyzeLog, fetchAIConfig, fetchLogs, testAIConnection, updateAIConfig } from '../../api/client';
import AIAnalysisMeta from '../../components/AIAnalysisMeta';
import type { AIConfig, AttackAnalysis, LogEntry, LogQuery } from '../../types/api';
import { displayAction, displayCategory } from '../../utils/display';

const analysisRanges = [
  { value: '15m', labelKey: 'ai.range15m', seconds: 15 * 60 },
  { value: '1h', labelKey: 'ai.range1h', seconds: 60 * 60 },
  { value: '6h', labelKey: 'ai.range6h', seconds: 6 * 60 * 60 },
  { value: '24h', labelKey: 'ai.range24h', seconds: 24 * 60 * 60 },
  { value: '7d', labelKey: 'ai.range7d', seconds: 7 * 24 * 60 * 60 },
];

const fallback: AIConfig = {
  enabled: false,
  provider: 'openai',
  api_base: 'https://api.openai.com/v1',
  api_key: '',
  api_key_set: false,
  model: 'gpt-4o-mini',
  async: true,
};

export default function AIPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState('');
  const [analysisRange, setAnalysisRange] = useState('1h');
  const [analyses, setAnalyses] = useState<Record<string, AttackAnalysis>>({});
  const { data } = useQuery({ queryKey: ['ai-config'], queryFn: fetchAIConfig, retry: false });
  const { data: logs, isLoading } = useQuery({
    queryKey: ['ai-events', analysisRange],
    queryFn: () => fetchLogs(buildAnalysisWindowQuery(analysisRange, 80)),
    refetchInterval: 5_000,
    retry: false,
  });
  const config = data ?? fallback;
  const events = useMemo(() => (logs?.items ?? []).filter(isSecurityEvent), [logs?.items]);
  const selected = events.find((event) => event.id === selectedId) ?? events[0];
  const selectedAnalysis = selected ? analyses[selected.id] : undefined;

  useEffect(() => {
    if (!selectedId && events.length > 0) {
      setSelectedId(events[0].id);
    }
  }, [events, selectedId]);

  const updateMutation = useMutation({
    mutationFn: updateAIConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-config'] });
      ArcoMessage.success(t('system.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const testMutation = useMutation({
    mutationFn: testAIConnection,
    onSuccess: () => ArcoMessage.success(t('ai.testOk')),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const eventAnalysisMutation = useMutation({
    mutationFn: (entry: LogEntry) => analyzeLog(entry as unknown as Record<string, unknown>),
    onSuccess: (analysis) => setAnalyses((current) => ({ ...current, [analysis.log_id]: analysis })),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const batchAnalysisMutation = useMutation({
    mutationFn: () => analyzeEvents(buildAnalysisWindowQuery(analysisRange, 200)),
    onSuccess: (result) => {
      setAnalyses((current) => {
        const next = { ...current };
        for (const item of result.items) {
          next[item.log_id] = item;
        }
        return next;
      });
      ArcoMessage.success(`${t('ai.analyzed')} ${result.total}`);
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ai.title')}</h1>
          <p>{t('ai.subtitle')}</p>
        </div>
      </header>

      <div className="ai-workspace">
        <section className="panel">
          <div className="panel-heading">
            <h2><PlugZap size={16} /> {t('ai.connection')}</h2>
            <Button icon={<ShieldCheck size={14} />} onClick={() => testMutation.mutate()} loading={testMutation.isPending}>
              {t('ai.test')}
            </Button>
          </div>
          <Form
            key={`ai-${config.enabled}-${config.provider}-${config.api_base}-${config.model}-${config.api_key_set}`}
            layout="vertical"
            initialValues={{
              enabled: config.enabled,
              provider: config.provider || 'openai',
              apiBase: config.api_base,
              apiKey: config.api_key ?? '',
              model: config.model,
              async: config.async,
            }}
            onSubmit={(values) => updateMutation.mutate({
              enabled: values.enabled,
              provider: values.provider || 'openai',
              api_base: values.apiBase,
              api_key: values.apiKey,
              api_key_set: config.api_key_set,
              model: values.model,
              async: values.async,
            })}
          >
            <Form.Item label={t('ai.enabled')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('ai.provider')} field="provider">
              <Select>
                <Select.Option value="openai">{t('ai.providerOpenAI')}</Select.Option>
                <Select.Option value="anthropic">{t('ai.providerAnthropic')}</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ai.apiBase')} field="apiBase"><Input /></Form.Item>
            <Form.Item label={t('ai.model')} field="model"><Input /></Form.Item>
            <Form.Item label={t('ai.apiKey')} field="apiKey">
              <Input.Password placeholder={config.api_key_set ? t('ai.keyStored') : ''} />
            </Form.Item>
            <Form.Item label={t('ai.async')} field="async"><Switch /></Form.Item>
            <Button className="ai-config-save" type="primary" htmlType="submit" loading={updateMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>

        <section className="panel ai-events-panel">
          <div className="panel-heading">
            <h2><ListChecks size={16} /> {t('ai.events')}</h2>
            <Space wrap>
              <Select
                aria-label={t('ai.timeRange')}
                value={analysisRange}
                onChange={setAnalysisRange}
                style={{ width: 132 }}
              >
                {analysisRanges.map((range) => (
                  <Select.Option key={range.value} value={range.value}>{t(range.labelKey)}</Select.Option>
                ))}
              </Select>
              <Button type="primary" onClick={() => batchAnalysisMutation.mutate()} loading={batchAnalysisMutation.isPending} disabled={events.length === 0}>
                {t('ai.analyzeRecent')}
              </Button>
            </Space>
          </div>
          <div className="table-scroll ai-events-table">
            <Table
              rowKey="id"
              loading={isLoading}
              pagination={{ pageSize: 8 }}
              data={events}
              onRow={(record) => ({ onClick: () => setSelectedId(record.id) })}
              columns={[
                { title: t('logs.time'), dataIndex: 'timestamp', render: (value: string) => new Date(value).toLocaleString() },
                { title: t('logs.source'), dataIndex: 'client_ip' },
                {
                  title: t('logs.action'),
                  dataIndex: 'action',
                  render: (value: string) => (
                    <span className="status-group">
                      <Tag color={actionColor(value)}>{displayAction(value, t)}</Tag>
                    </span>
                  ),
                },
                {
                  title: t('logs.category'),
                  dataIndex: 'category',
                  render: (value: string) => value ? (
                    <span className="status-group">
                      <Tag color="orange">{displayCategory(value, t)}</Tag>
                    </span>
                  ) : '-',
                },
                { title: 'URI', dataIndex: 'uri', render: (value: string) => <code className="table-code" title={value || '-'}>{value || '-'}</code> },
                {
                  title: t('ai.analysis'),
                  render: (_: unknown, record: LogEntry) => (
                    <Space wrap className="table-action-group">
                      <Link to={`/logs/${encodeURIComponent(record.trace_id || record.id)}`} onClick={(event) => event.stopPropagation()} className="table-action-link">
                        <Button size="small" icon={<Eye size={14} />}>{t('logs.detail')}</Button>
                      </Link>
                      <Button
                        size="small"
                        loading={eventAnalysisMutation.isPending && selectedId === record.id}
                        onClick={(event) => {
                          event.stopPropagation();
                          setSelectedId(record.id);
                          eventAnalysisMutation.mutate(record);
                        }}
                      >
                        {analyses[record.id] ? t('ai.reanalyze') : t('ai.run')}
                      </Button>
                    </Space>
                  ),
                },
              ]}
            />
          </div>
        </section>
      </div>

      <section className="table-panel ai-event-detail">
        <div className="panel-heading">
          <h2><BrainCircuit size={16} /> {t('ai.eventAnalysis')}</h2>
          {selectedAnalysis && <Tag color={riskColor(selectedAnalysis.risk)}>{selectedAnalysis.risk}</Tag>}
        </div>
        {selected ? (
          <div className="ai-detail-grid">
            <div className="ai-event-card">
              <span>{t('ai.selectedEvent')}</span>
              <strong>{selected.id || selected.trace_id}</strong>
              <code>{selected.method} {selected.uri}</code>
              <Space wrap>
                <Tag>{selected.client_ip || '-'}</Tag>
                <Tag color={actionColor(selected.action)}>{displayAction(selected.action, t)}</Tag>
                <Tag color="orange">{displayCategory(selected.category, t)}</Tag>
              </Space>
              <Button type="primary" loading={eventAnalysisMutation.isPending} onClick={() => eventAnalysisMutation.mutate(selected)}>
                {selectedAnalysis ? t('ai.reanalyze') : t('ai.run')}
              </Button>
            </div>
            <div className="ai-analysis-card">
              {selectedAnalysis ? (
                <>
                  <p>{selectedAnalysis.summary}</p>
                  <div className="ai-analysis-columns">
                    <div>
                      <strong>{t('ai.evidence')}</strong>
                      {(selectedAnalysis.evidence ?? []).map((item) => <span key={item}>{item}</span>)}
                    </div>
                    <div>
                      <strong>{t('ai.actions')}</strong>
                      {selectedAnalysis.recommended_actions.map((item) => <span key={item}>{item}</span>)}
                    </div>
                  </div>
                  <AIAnalysisMeta analysis={selectedAnalysis} />
                </>
              ) : (
                <div className="empty-state">{t('ai.selectAndAnalyze')}</div>
              )}
            </div>
          </div>
        ) : (
          <div className="empty-state">{t('ai.noEvents')}</div>
        )}
      </section>
    </section>
  );
}

function buildAnalysisWindowQuery(rangeValue: string, limit: number): LogQuery {
  const range = analysisRanges.find((item) => item.value === rangeValue) ?? analysisRanges[1];
  const end = new Date();
  const start = new Date(end.getTime() - range.seconds * 1000);
  return {
    limit,
    start: start.toISOString(),
    end: end.toISOString(),
  };
}

function isSecurityEvent(entry: LogEntry) {
  return Boolean(entry.category || ['block', 'challenge', 'log'].includes(entry.action));
}

function actionColor(action: string) {
  switch (action) {
    case 'block':
      return 'red';
    case 'challenge':
      return 'orange';
    case 'log':
      return 'blue';
    default:
      return 'gray';
  }
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
