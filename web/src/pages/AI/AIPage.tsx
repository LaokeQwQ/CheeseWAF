import { useEffect, useMemo, useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Select, Space, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { BrainCircuit, ChevronLeft, ChevronRight, Eye, ListChecks, PlugZap, ShieldCheck } from 'lucide-react';
import { analyzeEvents, analyzeLogReference, fetchAIConfig, fetchLogs, testAIConnection, updateAIConfig } from '../../api/client';
import AIAnalysisMeta, { AIReasoningSummary } from '../../components/AIAnalysisMeta';
import type { AIConfig, AttackAnalysis, LogEntry, LogQuery } from '../../types/api';
import { displayAction, displayCategory } from '../../utils/display';

const analysisRanges = [
  { value: '15m', labelKey: 'ai.range15m', seconds: 15 * 60 },
  { value: '1h', labelKey: 'ai.range1h', seconds: 60 * 60 },
  { value: '6h', labelKey: 'ai.range6h', seconds: 6 * 60 * 60 },
  { value: '24h', labelKey: 'ai.range24h', seconds: 24 * 60 * 60 },
  { value: '7d', labelKey: 'ai.range7d', seconds: 7 * 24 * 60 * 60 },
];
const AI_EVENT_PAGE_SIZE = 8;

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
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState('');
  const [analysisRange, setAnalysisRange] = useState('24h');
  const [eventPage, setEventPage] = useState(1);
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
  const eventPageCount = Math.max(1, Math.ceil(events.length / AI_EVENT_PAGE_SIZE));
  const eventPageItems = events.slice((eventPage - 1) * AI_EVENT_PAGE_SIZE, eventPage * AI_EVENT_PAGE_SIZE);
  const eventPageStart = events.length === 0 ? 0 : (eventPage - 1) * AI_EVENT_PAGE_SIZE + 1;
  const eventPageEnd = Math.min(eventPage * AI_EVENT_PAGE_SIZE, events.length);
  const selected = events.find((event) => eventKey(event) === selectedId) ?? events[0];
  const selectedAnalysis = selected ? analyses[eventKey(selected)] : undefined;

  useEffect(() => {
    if (!selectedId && events.length > 0) {
      setSelectedId(eventKey(events[0]));
    }
  }, [events, selectedId]);

  useEffect(() => {
    setEventPage(1);
  }, [analysisRange]);

  useEffect(() => {
    if (eventPage > eventPageCount) {
      setEventPage(eventPageCount);
    }
  }, [eventPage, eventPageCount]);

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
    mutationFn: (entry: LogEntry) => analyzeLogReference(entry.trace_id || entry.id, i18n.language),
    onSuccess: (analysis, entry) => setAnalyses((current) => ({ ...current, [eventKey(entry)]: analysis, [analysis.log_id]: analysis })),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const batchAnalysisMutation = useMutation({
    mutationFn: () => analyzeEvents({ ...buildAnalysisWindowQuery(analysisRange, 200), language: i18n.language }),
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
  const analyzingEventKey = eventAnalysisMutation.variables ? eventKey(eventAnalysisMutation.variables) : '';

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
            <Form.Item label={t('ai.enabled')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
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
            <Form.Item label={t('ai.async')} field="async" triggerPropName="checked"><Switch /></Form.Item>
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
          <div className="ai-events-list-panel">
            <div className="ai-events-list-header" aria-hidden="true">
              <span>{t('logs.time')}</span>
              <span>{t('logs.source')}</span>
              <span>{t('logs.action')}</span>
              <span>{t('logs.category')}</span>
              <span>URI</span>
              <span>{t('ai.analysis')}</span>
            </div>
            <div className="ai-events-list" aria-busy={isLoading}>
              {isLoading && Array.from({ length: 4 }).map((_, index) => (
                <div className="ai-events-list-row security-event-skeleton" key={index} />
              ))}
              {!isLoading && eventPageItems.length === 0 && <div className="empty-state">{t('ai.noEvents')}</div>}
              {!isLoading && eventPageItems.map((record) => {
                const key = eventKey(record);
                return (
                  <article
                    className={`ai-events-list-row${selected && eventKey(selected) === key ? ' ai-events-list-row-active' : ''}`}
                    key={key}
                    onClick={() => setSelectedId(key)}
                  >
                    <div className="security-event-cell" data-label={t('logs.time')}>
                      <time dateTime={record.timestamp} title={formatTime(record.timestamp)}>{formatCompactTime(record.timestamp)}</time>
                    </div>
                    <div className="security-event-cell" data-label={t('logs.source')}>
                      <span title={record.client_ip || '-'}>{record.client_ip || '-'}</span>
                    </div>
                    <div className="security-event-cell" data-label={t('logs.action')}>
                      <Tag color={actionColor(record.action)}>{displayAction(record.action, t)}</Tag>
                    </div>
                    <div className="security-event-cell" data-label={t('logs.category')}>
                      {record.category ? <Tag color="orange">{displayCategory(record.category, t)}</Tag> : <span>-</span>}
                    </div>
                    <div className="security-event-cell security-event-uri" data-label="URI">
                      <code title={record.uri || '-'}>{record.uri || '-'}</code>
                    </div>
                    <div className="security-event-cell ai-events-row-actions" data-label={t('ai.analysis')} onClick={(event) => event.stopPropagation()}>
                      <Link to={`/logs/${encodeURIComponent(record.trace_id || record.id)}`} className="table-action-link">
                        <Button size="small" icon={<Eye size={14} />}>{t('logs.detail')}</Button>
                      </Link>
                      <Button
                        size="small"
                        loading={eventAnalysisMutation.isPending && analyzingEventKey === key}
                        onClick={() => {
                          setSelectedId(key);
                          eventAnalysisMutation.mutate(record);
                        }}
                      >
                        {analyses[key] ? t('ai.reanalyze') : t('ai.run')}
                      </Button>
                    </div>
                  </article>
                );
              })}
            </div>
            {!isLoading && events.length > AI_EVENT_PAGE_SIZE && (
              <footer className="security-events-pagination">
                <span>{eventPageStart}-{eventPageEnd} / {events.length}</span>
                <div>
                  <Button
                    aria-label={t('common.back')}
                    icon={<ChevronLeft size={15} />}
                    disabled={eventPage <= 1}
                    onClick={() => setEventPage((current) => Math.max(1, current - 1))}
                  />
                  <strong>{eventPage}</strong>
                  <Button
                    aria-label={t('common.next')}
                    icon={<ChevronRight size={15} />}
                    disabled={eventPage >= eventPageCount}
                    onClick={() => setEventPage((current) => Math.min(eventPageCount, current + 1))}
                  />
                </div>
              </footer>
            )}
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
              <strong>{eventKey(selected)}</strong>
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
                  <AIReasoningSummary analysis={selectedAnalysis} />
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

function eventKey(entry: LogEntry) {
  return entry.id || entry.trace_id;
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString();
}

function formatCompactTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
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
