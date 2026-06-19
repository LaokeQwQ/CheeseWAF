import { useEffect, useMemo, useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Select, Space, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { BrainCircuit, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Eye, KeyRound, ListChecks, PlugZap, ShieldCheck } from 'lucide-react';
import { analyzeEvents, analyzeLogReference, fetchAIConfig, fetchAIModels, fetchLogs, runAISelfLearning, testAIConnection, updateAIConfig } from '../../api/client';
import AIAnalysisMeta, { AIAnalysisSummary, AIReasoningSummary } from '../../components/AIAnalysisMeta';
import type { AIConfig, AIModelConfig, AIModelInfo, AISelfLearningReport, AttackAnalysis, LogEntry, LogQuery } from '../../types/api';
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
  allow_private_api_base: false,
  assistant: {
    provider: 'openai',
    api_base: 'https://api.openai.com/v1',
    api_key: '',
    api_key_set: false,
    model: 'gpt-4o-mini',
    allow_private_api_base: false,
  },
  reasoning: {
    provider: 'openai',
    api_base: 'https://api.openai.com/v1',
    api_key: '',
    api_key_set: false,
    model: 'gpt-4o-mini',
    allow_private_api_base: false,
  },
  self_learning: {
    enabled: false,
    auto_apply: false,
    dry_run: true,
    interval: '24h',
    at: '03:30',
    min_confidence: 0.995,
    min_events: 5,
    max_events: 200,
    max_rules_per_run: 3,
    action: 'block',
  },
  knowledge: {
    enabled: true,
    builtin: true,
    max_snippets: 5,
  },
};

export default function AIPage() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [form] = Form.useForm();
  const [selectedId, setSelectedId] = useState('');
  const [analysisRange, setAnalysisRange] = useState('24h');
  const [eventPage, setEventPage] = useState(1);
  const [analyses, setAnalyses] = useState<Record<string, AttackAnalysis>>({});
  const [models, setModels] = useState<AIModelInfo[]>([]);
  const [reasoningModels, setReasoningModels] = useState<AIModelInfo[]>([]);
  const [selfLearningReport, setSelfLearningReport] = useState<AISelfLearningReport | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const { data } = useQuery({ queryKey: ['ai-config'], queryFn: fetchAIConfig, retry: false });
  const { data: logs, isLoading } = useQuery({
    queryKey: ['ai-events', analysisRange],
    queryFn: () => fetchLogs(buildAnalysisWindowQuery(analysisRange, 80)),
    refetchInterval: 5_000,
    retry: false,
  });
  const config = data ?? fallback;
  const assistantConfig = normalizeAIModel(config.assistant, config);
  const reasoningConfig = normalizeAIModel(config.reasoning, config);
  const providerLabel = config.provider === 'anthropic'
    ? t('ai.providerAnthropic')
    : t('ai.providerOpenAI');
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
    form.setFieldsValue({
      enabled: config.enabled,
      provider: config.provider || 'openai',
      apiBase: config.api_base,
      apiKey: '',
      model: config.model,
      assistantProvider: assistantConfig.provider,
      assistantAPIBase: assistantConfig.api_base,
      assistantAPIKey: '',
      assistantModel: assistantConfig.model,
      assistantAllowPrivateAPIBase: assistantConfig.allow_private_api_base,
      reasoningProvider: reasoningConfig.provider,
      reasoningAPIBase: reasoningConfig.api_base,
      reasoningAPIKey: '',
      reasoningModel: reasoningConfig.model,
      reasoningAllowPrivateAPIBase: reasoningConfig.allow_private_api_base,
      async: config.async,
      allowPrivateAPIBase: config.allow_private_api_base,
      selfLearningEnabled: config.self_learning?.enabled ?? false,
      selfLearningAutoApply: config.self_learning?.auto_apply ?? false,
      selfLearningDryRun: config.self_learning?.dry_run ?? true,
      selfLearningInterval: formatDurationInput(config.self_learning?.interval ?? '24h'),
      selfLearningAt: config.self_learning?.at ?? '03:30',
      selfLearningMinConfidence: config.self_learning?.min_confidence ?? 0.995,
      selfLearningMinEvents: config.self_learning?.min_events ?? 5,
      selfLearningMaxEvents: config.self_learning?.max_events ?? 200,
      selfLearningMaxRulesPerRun: config.self_learning?.max_rules_per_run ?? 3,
      selfLearningAction: config.self_learning?.action ?? 'block',
      knowledgeEnabled: config.knowledge?.enabled ?? true,
      knowledgeBuiltin: config.knowledge?.builtin ?? true,
      knowledgeMaxSnippets: config.knowledge?.max_snippets ?? 5,
    });
  }, [assistantConfig.api_base, assistantConfig.allow_private_api_base, assistantConfig.model, assistantConfig.provider, config.allow_private_api_base, config.api_base, config.async, config.enabled, config.knowledge?.builtin, config.knowledge?.enabled, config.knowledge?.max_snippets, config.model, config.provider, config.self_learning?.action, config.self_learning?.at, config.self_learning?.auto_apply, config.self_learning?.dry_run, config.self_learning?.enabled, config.self_learning?.interval, config.self_learning?.max_events, config.self_learning?.max_rules_per_run, config.self_learning?.min_confidence, config.self_learning?.min_events, form, reasoningConfig.api_base, reasoningConfig.allow_private_api_base, reasoningConfig.model, reasoningConfig.provider]);

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
    mutationFn: (target: 'assistant' | 'reasoning') => testAIConnection(buildAIModelRequest(form.getFieldsValue(), target)),
    onSuccess: () => ArcoMessage.success(t('ai.testOk')),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const modelsMutation = useMutation({
    mutationFn: (target: 'assistant' | 'reasoning') => {
      return fetchAIModels(buildAIModelRequest(form.getFieldsValue(), target));
    },
    onSuccess: (result, target) => {
      if (target === 'reasoning') {
        setReasoningModels(result.items ?? []);
      } else {
        setModels(result.items ?? []);
      }
      ArcoMessage.success(t('ai.modelsLoaded', { count: result.total ?? result.items?.length ?? 0 }));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const selfLearningMutation = useMutation({
    mutationFn: (dryRun: boolean) => runAISelfLearning({ dry_run: dryRun, language: i18n.language }),
    onSuccess: (report) => {
      setSelfLearningReport(report);
      ArcoMessage.success(t('ai.selfLearningRunOk', { candidates: report.candidates.length, applied: report.applied.length }));
    },
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
    <section className="page-surface ai-page">
      <header className="page-header">
        <div>
          <h1>{t('ai.title')}</h1>
          <p>{t('ai.subtitle')}</p>
        </div>
      </header>

      <div className="ai-dashboard-grid">
        <section className="panel ai-config-panel">
          <div className="panel-heading">
            <h2><PlugZap size={16} /> {t('ai.connection')}</h2>
            <div className="ai-config-header-actions">
              <Form className="ai-config-inline-switches" form={form} layout="inline">
                <Form.Item label={t('ai.enabled')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
                <Form.Item label={t('ai.async')} field="async" triggerPropName="checked"><Switch /></Form.Item>
              </Form>
              <Button icon={<ShieldCheck size={14} />} onClick={() => testMutation.mutate('assistant')} loading={testMutation.isPending && testMutation.variables === 'assistant'}>
                {t('ai.test')}
              </Button>
            </div>
          </div>
          <div className="ai-config-summary" aria-label={t('ai.connection')}>
            <div className={config.enabled ? 'ai-config-state ai-config-state-on' : 'ai-config-state'}>
              <span>{config.enabled ? t('common.enabled') : t('common.disabled')}</span>
              <strong>{providerLabel}</strong>
              <em title={assistantConfig.model || '-'}>{assistantConfig.model || '-'}</em>
            </div>
            <div className="ai-config-summary-item">
              <span>{t('ai.apiBase')}</span>
              <strong title={assistantConfig.api_base || '-'}>{assistantConfig.api_base || '-'}</strong>
            </div>
            <div className="ai-config-summary-item">
              <span>{t('ai.apiKey')}</span>
              <strong>{config.api_key_set ? t('ai.keyStored') : t('ai.keyMissing')}</strong>
            </div>
          </div>
          <Form
            className="ai-config-form"
            form={form}
            key={`ai-${config.enabled}-${config.provider}-${config.api_base}-${config.model}-${config.api_key_set}`}
            layout="vertical"
            initialValues={{
              enabled: config.enabled,
              provider: config.provider || 'openai',
              apiBase: config.api_base,
              apiKey: config.api_key ?? '',
              model: config.model,
              async: config.async,
              allowPrivateAPIBase: config.allow_private_api_base,
            }}
            onSubmit={(values) => {
              const allValues = { ...values, ...form.getFieldsValue() };
              updateMutation.mutate({
                enabled: allValues.enabled,
                provider: allValues.assistantProvider || allValues.provider || 'openai',
                api_base: allValues.assistantAPIBase || allValues.apiBase,
                api_key: allValues.assistantAPIKey || allValues.apiKey,
                api_key_set: config.api_key_set,
                model: allValues.assistantModel || allValues.model,
                async: allValues.async,
                allow_private_api_base: allValues.assistantAllowPrivateAPIBase ?? allValues.allowPrivateAPIBase,
                assistant: {
                  provider: allValues.assistantProvider || 'openai',
                  api_base: allValues.assistantAPIBase,
                  api_key: allValues.assistantAPIKey,
                  api_key_set: assistantConfig.api_key_set,
                  model: allValues.assistantModel,
                  allow_private_api_base: allValues.assistantAllowPrivateAPIBase,
                },
                reasoning: {
                  provider: allValues.reasoningProvider || 'openai',
                  api_base: allValues.reasoningAPIBase,
                  api_key: allValues.reasoningAPIKey,
                  api_key_set: reasoningConfig.api_key_set,
                  model: allValues.reasoningModel,
                  allow_private_api_base: allValues.reasoningAllowPrivateAPIBase,
                },
                self_learning: {
                  enabled: allValues.selfLearningEnabled,
                  auto_apply: allValues.selfLearningAutoApply,
                  dry_run: allValues.selfLearningDryRun,
                  interval: durationInputToNanoseconds(allValues.selfLearningInterval),
                  at: allValues.selfLearningAt,
                  min_confidence: Number(allValues.selfLearningMinConfidence),
                  min_events: Number(allValues.selfLearningMinEvents),
                  max_events: Number(allValues.selfLearningMaxEvents),
                  max_rules_per_run: Number(allValues.selfLearningMaxRulesPerRun),
                  action: allValues.selfLearningAction || 'block',
                },
                knowledge: {
                  enabled: allValues.knowledgeEnabled,
                  builtin: allValues.knowledgeBuiltin,
                  max_snippets: Number(allValues.knowledgeMaxSnippets || 5),
                },
              });
            }}
          >
            <div className="ai-config-main">
              <AIModelFormBlock
                title={t('ai.assistantModel')}
                description={t('ai.assistantModelHint')}
                prefix="assistant"
                t={t}
                models={modelOptions(models, assistantConfig.model)}
                loadingModels={modelsMutation.isPending && modelsMutation.variables === 'assistant'}
                keyStored={assistantConfig.api_key_set}
                onFetchModels={() => modelsMutation.mutate('assistant')}
                onTest={() => testMutation.mutate('assistant')}
                testing={testMutation.isPending && testMutation.variables === 'assistant'}
              />
              <AIModelFormBlock
                title={t('ai.reasoningModel')}
                description={t('ai.reasoningModelHint')}
                prefix="reasoning"
                t={t}
                models={modelOptions(reasoningModels, reasoningConfig.model)}
                loadingModels={modelsMutation.isPending && modelsMutation.variables === 'reasoning'}
                keyStored={reasoningConfig.api_key_set}
                onFetchModels={() => modelsMutation.mutate('reasoning')}
                onTest={() => testMutation.mutate('reasoning')}
                testing={testMutation.isPending && testMutation.variables === 'reasoning'}
              />
              <div className={advancedOpen ? 'ai-advanced-settings ai-advanced-settings-open' : 'ai-advanced-settings'}>
                <button
                  type="button"
                  className="ai-advanced-toggle"
                  aria-expanded={advancedOpen}
                  onClick={() => setAdvancedOpen((current) => !current)}
                >
                  <span>
                    <strong>{t('ai.advancedSettings')}</strong>
                    <em>{t('ai.advancedSettingsHint')}</em>
                  </span>
                  {advancedOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </button>
                <div className="ai-advanced-panel" hidden={!advancedOpen}>
                  <div className="ai-config-subpanel">
                    <header>
                      <strong>{t('ai.selfLearning')}</strong>
                      <span>{t('ai.selfLearningHint')}</span>
                    </header>
                    <div className="ai-config-section">
                      <Form.Item label={t('common.enabled')} field="selfLearningEnabled" triggerPropName="checked"><Switch /></Form.Item>
                      <Form.Item label={t('ai.selfLearningAutoApply')} field="selfLearningAutoApply" triggerPropName="checked"><Switch /></Form.Item>
                      <Form.Item label={t('ai.selfLearningDryRun')} field="selfLearningDryRun" triggerPropName="checked"><Switch /></Form.Item>
                      <Form.Item label={t('ai.selfLearningInterval')} field="selfLearningInterval"><Input placeholder="24h" /></Form.Item>
                      <Form.Item label={t('ai.selfLearningAt')} field="selfLearningAt"><Input placeholder="03:30" /></Form.Item>
                      <Form.Item label={t('ai.selfLearningConfidence')} field="selfLearningMinConfidence"><Input type="number" min={0.9} max={1} step={0.001} /></Form.Item>
                      <Form.Item label={t('ai.selfLearningMinEvents')} field="selfLearningMinEvents"><Input type="number" min={2} /></Form.Item>
                      <Form.Item label={t('ai.selfLearningMaxRules')} field="selfLearningMaxRulesPerRun"><Input type="number" min={1} max={20} /></Form.Item>
                      <Form.Item label={t('ai.selfLearningAction')} field="selfLearningAction">
                        <Select>
                          <Select.Option value="block">{displayAction('block', t)}</Select.Option>
                          <Select.Option value="challenge">{displayAction('challenge', t)}</Select.Option>
                          <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                        </Select>
                      </Form.Item>
                    </div>
                    <Space wrap>
                      <Button onClick={() => selfLearningMutation.mutate(true)} loading={selfLearningMutation.isPending}>
                        {t('ai.selfLearningDryRunNow')}
                      </Button>
                      <Button status="warning" onClick={() => selfLearningMutation.mutate(false)} loading={selfLearningMutation.isPending}>
                        {t('ai.selfLearningRunNow')}
                      </Button>
                    </Space>
                    {selfLearningReport && (
                      <div className="ai-self-learning-report">
                        <Tag>{t('ai.selfLearningCandidates', { count: selfLearningReport.candidates.length })}</Tag>
                        <Tag color="green">{t('ai.selfLearningApplied', { count: selfLearningReport.applied.length })}</Tag>
                        <Tag color="orange">{t('ai.selfLearningSkipped', { count: selfLearningReport.skipped.length })}</Tag>
                      </div>
                    )}
                  </div>
                  <div className="ai-config-subpanel ai-knowledge-subpanel">
                    <header>
                      <strong>{t('ai.knowledge')}</strong>
                      <span>{t('ai.knowledgeHint')}</span>
                    </header>
                    <div className="ai-config-section ai-knowledge-grid">
                      <Form.Item label={t('common.enabled')} field="knowledgeEnabled" triggerPropName="checked"><Switch /></Form.Item>
                      <Form.Item label={t('ai.knowledgeBuiltin')} field="knowledgeBuiltin" triggerPropName="checked"><Switch /></Form.Item>
                      <Form.Item label={t('ai.knowledgeMaxSnippets')} field="knowledgeMaxSnippets"><Input type="number" min={1} max={20} /></Form.Item>
                    </div>
                  </div>
                </div>
              </div>
              <div className="ai-config-actions-row">
                <Button className="ai-config-save" type="primary" htmlType="submit" loading={updateMutation.isPending}>{t('common.save')}</Button>
              </div>
            </div>
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
                    <div className="security-event-cell ai-events-row-actions" data-label={t('ai.analysis')} role="group" aria-label={t('ai.analysis')}>
                      <Link
                        to={`/logs/${encodeURIComponent(record.trace_id || record.id)}`}
                        className="table-action-link"
                        onClick={(event) => event.stopPropagation()}
                      >
                        <Button size="small" icon={<Eye size={14} />}>{t('logs.detail')}</Button>
                      </Link>
                      <Button
                        size="small"
                        loading={eventAnalysisMutation.isPending && analyzingEventKey === key}
                        onClick={(event) => {
                          event.stopPropagation();
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
            <div className="ai-events-mobile-list" aria-busy={isLoading}>
              {isLoading && Array.from({ length: 4 }).map((_, index) => (
                <article className="ai-event-mobile-card security-event-skeleton" key={index} />
              ))}
              {!isLoading && eventPageItems.length === 0 && <div className="empty-state">{t('ai.noEvents')}</div>}
              {!isLoading && eventPageItems.map((record) => {
                const key = eventKey(record);
                const isSelected = Boolean(selected && eventKey(selected) === key);
                return (
                  <article
                    className={`ai-event-mobile-card${isSelected ? ' ai-event-mobile-card-active' : ''}`}
                    key={key}
                    onClick={() => setSelectedId(key)}
                  >
                    <header className="ai-event-mobile-head">
                      <div>
                        <time dateTime={record.timestamp} title={formatTime(record.timestamp)}>{formatCompactTime(record.timestamp)}</time>
                        <span>{record.client_ip || '-'}</span>
                      </div>
                      <div>
                        <Tag color={actionColor(record.action)}>{displayAction(record.action, t)}</Tag>
                        {record.category ? <Tag color="orange">{displayCategory(record.category, t)}</Tag> : <Tag>{t('common.monitor')}</Tag>}
                      </div>
                    </header>
                    <code title={record.uri || '-'}>{record.uri || '-'}</code>
                    <footer className="ai-event-mobile-actions" onClick={(event) => event.stopPropagation()}>
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
                    </footer>
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

        <section className="panel ai-event-detail">
        <div className="panel-heading">
          <h2><BrainCircuit size={16} /> {t('ai.eventAnalysis')}</h2>
          {selectedAnalysis && <Tag color={riskColor(selectedAnalysis.risk)}>{selectedAnalysis.risk}</Tag>}
        </div>
        {selected ? (
          <div className="ai-detail-grid">
            <div className="ai-event-card">
              <span>{t('ai.selectedEvent')}</span>
              <strong>{eventKey(selected)}</strong>
              <div className="ai-selected-event-meta">
                <Tag>{selected.client_ip || '-'}</Tag>
                <Tag color={actionColor(selected.action)}>{displayAction(selected.action, t)}</Tag>
                <Tag color="orange">{displayCategory(selected.category, t)}</Tag>
              </div>
              <code>{selected.method} {selected.uri}</code>
              <Button type="primary" loading={eventAnalysisMutation.isPending} onClick={() => eventAnalysisMutation.mutate(selected)}>
                {selectedAnalysis ? t('ai.reanalyze') : t('ai.run')}
              </Button>
            </div>
            <div className="ai-analysis-card">
              {selectedAnalysis ? (
                <>
                  <div className="ai-analysis-summary">
                    <KeyRound size={16} />
                    <AIAnalysisSummary analysis={selectedAnalysis} />
                  </div>
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
      </div>
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

function formatDurationInput(value: unknown) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return nanosecondsToDurationInput(value);
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      return nanosecondsToDurationInput(Number(trimmed));
    }
    return trimmed || '24h';
  }
  return '24h';
}

function nanosecondsToDurationInput(value: number) {
  const seconds = value / 1_000_000_000;
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return '24h';
  }
  if (seconds % 3_600 === 0) {
    return `${seconds / 3_600}h`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }
  return `${Math.round(seconds)}s`;
}

function durationInputToNanoseconds(value: unknown) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) {
    return 24 * 60 * 60 * 1_000_000_000;
  }
  if (/^\d+$/.test(text)) {
    return Number(text);
  }
  const match = text.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/);
  if (!match) {
    return 24 * 60 * 60 * 1_000_000_000;
  }
  const amount = Number(match[1]);
  const unit = match[2];
  const seconds = unit === 'd'
    ? amount * 86_400
    : unit === 'h'
      ? amount * 3_600
      : unit === 'm'
        ? amount * 60
        : unit === 'ms'
          ? amount / 1000
          : amount;
  return Math.max(0, Math.round(seconds * 1_000_000_000));
}

function eventKey(entry: LogEntry) {
  return entry.id || entry.trace_id;
}

function modelOptions(models: AIModelInfo[], currentModel: string) {
  const seen = new Set<string>();
  const out: AIModelInfo[] = [];
  for (const model of models) {
    const id = String(model.id || '').trim();
    if (!id || seen.has(id)) {
      continue;
    }
    seen.add(id);
    out.push({ ...model, id });
  }
  const current = currentModel.trim();
  if (current && !seen.has(current)) {
    out.unshift({ id: current });
  }
  return out;
}

function buildAIModelRequest(values: Record<string, any>, target: 'assistant' | 'reasoning') {
  const prefix = target === 'reasoning' ? 'reasoning' : 'assistant';
  return {
    target,
    provider: values[`${prefix}Provider`] || 'openai',
    api_base: values[`${prefix}APIBase`],
    api_key: values[`${prefix}APIKey`],
    model: values[`${prefix}Model`],
    allow_private_api_base: values[`${prefix}AllowPrivateAPIBase`],
  };
}

function normalizeAIModel(model: AIModelConfig | undefined, config: AIConfig): AIModelConfig {
  return {
    provider: model?.provider || config.provider || 'openai',
    api_base: model?.api_base || config.api_base || 'https://api.openai.com/v1',
    api_key: '',
    api_key_set: Boolean(model?.api_key_set ?? config.api_key_set),
    model: model?.model || config.model || 'gpt-4o-mini',
    allow_private_api_base: Boolean(model?.allow_private_api_base ?? config.allow_private_api_base),
  };
}

function AIModelFormBlock({
  title,
  description,
  prefix,
  t,
  models,
  loadingModels,
  keyStored,
  onFetchModels,
  onTest,
  testing,
}: {
  title: string;
  description: string;
  prefix: 'assistant' | 'reasoning';
  t: (key: string, options?: Record<string, unknown>) => string;
  models: AIModelInfo[];
  loadingModels: boolean;
  keyStored: boolean;
  onFetchModels: () => void;
  onTest: () => void;
  testing: boolean;
}) {
  return (
    <div className="ai-config-subpanel ai-model-config-subpanel">
      <header>
        <strong>{title}</strong>
        <span>{description}</span>
      </header>
      <div className="ai-config-section ai-model-config-grid">
        <Form.Item label={t('ai.provider')} field={`${prefix}Provider`}>
          <Select>
            <Select.Option value="openai">{t('ai.providerOpenAI')}</Select.Option>
            <Select.Option value="anthropic">{t('ai.providerAnthropic')}</Select.Option>
          </Select>
        </Form.Item>
        <Form.Item label={t('ai.apiBase')} field={`${prefix}APIBase`}><Input /></Form.Item>
        <Form.Item label={t('ai.model')} field={`${prefix}Model`}>
          <Select allowCreate showSearch placeholder={t('ai.modelPlaceholder')} notFoundContent={loadingModels ? t('ai.modelsLoading') : t('ai.modelsEmpty')}>
            {models.map((model) => (
              <Select.Option key={model.id} value={model.id}>
                {model.owned_by ? `${model.id} · ${model.owned_by}` : model.id}
              </Select.Option>
            ))}
          </Select>
        </Form.Item>
        <Form.Item label={t('ai.apiKey')} field={`${prefix}APIKey`}>
          <Input.Password placeholder={keyStored ? t('ai.keyStored') : ''} />
        </Form.Item>
        <Form.Item className="ai-model-private-field" label={t('ai.allowPrivateAPIBase')} field={`${prefix}AllowPrivateAPIBase`} triggerPropName="checked" extra={t('ai.allowPrivateAPIBaseHint')}>
          <Switch />
        </Form.Item>
      </div>
      <Space className="ai-model-config-actions" wrap>
        <Button htmlType="button" icon={<KeyRound size={14} />} onClick={onFetchModels} loading={loadingModels}>
          {t('ai.fetchModels')}
        </Button>
        <Button htmlType="button" icon={<ShieldCheck size={14} />} onClick={onTest} loading={testing}>
          {t('ai.test')}
        </Button>
      </Space>
    </div>
  );
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
