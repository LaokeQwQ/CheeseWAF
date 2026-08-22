import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { BrainCircuit, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Eye, KeyRound, ListChecks, PlugZap, ShieldCheck } from 'lucide-react';
import {
  Badge,
  Button,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Spinner,
  Switch,
  toast,
} from '@/components/ui';
import { APIRequestError, analyzeEventsStream, analyzeLogReferenceStream, fetchAIConfig, fetchAIModels, fetchLogs, runAISelfLearning, testAIConnection, updateAIConfig } from '../../api/client';
import AIAnalysisMeta, { AIAnalysisSummary, AIReasoningSummary } from '../../components/AIAnalysisMeta';
import PolicyDecisionCard from '../../components/PolicyDecisionCard';
import SafeMarkdown from '../../components/SafeMarkdown';
import type { AIAssistantTraceEvent, AIConfig, AIModelConfig, AIModelInfo, AISelfLearningReport, AttackAnalysis, LogEntry, LogQuery } from '../../types/api';
import { displayAction, displayCategory } from '../../utils/display';
import { usePollingVisibility } from '../../hooks/usePollingVisibility';
import '../../styles/ai-page.css';

const analysisRanges = [
  { value: '15m', labelKey: 'ai.range15m', seconds: 15 * 60 },
  { value: '1h', labelKey: 'ai.range1h', seconds: 60 * 60 },
  { value: '6h', labelKey: 'ai.range6h', seconds: 6 * 60 * 60 },
  { value: '24h', labelKey: 'ai.range24h', seconds: 24 * 60 * 60 },
  { value: '7d', labelKey: 'ai.range7d', seconds: 7 * 24 * 60 * 60 },
];
const AI_EVENT_PAGE_SIZE = 8;
export const SELF_LEARNING_MAX_EVENTS_RANGE = { min: 1, max: 10_000 };

type AIFormValues = {
  enabled: boolean;
  provider: string;
  apiBase: string;
  apiKey: string;
  model: string;
  assistantProvider: string;
  assistantAPIBase: string;
  assistantAPIKey: string;
  assistantModel: string;
  assistantAllowPrivateAPIBase: boolean;
  reasoningProvider: string;
  reasoningAPIBase: string;
  reasoningAPIKey: string;
  reasoningModel: string;
  reasoningAllowPrivateAPIBase: boolean;
  async: boolean;
  allowPrivateAPIBase: boolean;
  selfLearningEnabled: boolean;
  selfLearningAutoApply: boolean;
  selfLearningDryRun: boolean;
  selfLearningInterval: string;
  selfLearningAt: string;
  selfLearningMinConfidence: number | string;
  selfLearningMinEvents: number | string;
  selfLearningMaxEvents: number | string;
  selfLearningMaxRulesPerRun: number | string;
  selfLearningAction: string;
  knowledgeEnabled: boolean;
  knowledgeBuiltin: boolean;
  knowledgeMaxSnippets: number | string;
};

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

function formValuesFromConfig(config: AIConfig, assistantConfig: AIModelConfig, reasoningConfig: AIModelConfig): AIFormValues {
  return {
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
  };
}

export default function AIPage() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const singleAnalysisAbortRef = useRef<{ key: string; controller: AbortController } | null>(null);
  const [selectedId, setSelectedId] = useState('');
  const [analysisRange, setAnalysisRange] = useState('24h');
  const [eventPage, setEventPage] = useState(1);
  const [analyses, setAnalyses] = useState<Record<string, AttackAnalysis>>({});
  const [liveAnalysis, setLiveAnalysis] = useState<{
    key: string;
    trace: AIAssistantTraceEvent[];
    reasoning: string;
    content: string;
  } | null>(null);
  const [models, setModels] = useState<AIModelInfo[]>([]);
  const [reasoningModels, setReasoningModels] = useState<AIModelInfo[]>([]);
  const [selfLearningReport, setSelfLearningReport] = useState<AISelfLearningReport | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [maxEventsError, setMaxEventsError] = useState('');
  const configQuery = useQuery({ queryKey: ['ai-config'], queryFn: fetchAIConfig, retry: false });
  const { data } = configQuery;
  const aiEventsRefetchInterval = usePollingVisibility(5_000);
  const { data: logs, isLoading } = useQuery({
    queryKey: ['ai-events', analysisRange],
    queryFn: () => fetchLogs(buildAnalysisWindowQuery(analysisRange, 80)),
    refetchInterval: aiEventsRefetchInterval,
    retry: false,
  });
  const config = data ?? fallback;
  const assistantConfig = normalizeAIModel(config.assistant, config);
  const reasoningConfig = normalizeAIModel(config.reasoning, config);
  const [formValues, setFormValues] = useState<AIFormValues>(() => formValuesFromConfig(config, assistantConfig, reasoningConfig));
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
  const selectedLiveAnalysis = selected && liveAnalysis?.key === eventKey(selected) ? liveAnalysis : null;

  useEffect(() => {
    if (!selectedId && events.length > 0) {
      setSelectedId(eventKey(events[0]));
    }
  }, [events, selectedId]);

  useEffect(() => {
    setFormValues(formValuesFromConfig(config, assistantConfig, reasoningConfig));
    setMaxEventsError('');
  }, [
    assistantConfig.api_base,
    assistantConfig.allow_private_api_base,
    assistantConfig.model,
    assistantConfig.provider,
    config.allow_private_api_base,
    config.api_base,
    config.async,
    config.enabled,
    config.knowledge?.builtin,
    config.knowledge?.enabled,
    config.knowledge?.max_snippets,
    config.model,
    config.provider,
    config.self_learning?.action,
    config.self_learning?.at,
    config.self_learning?.auto_apply,
    config.self_learning?.dry_run,
    config.self_learning?.enabled,
    config.self_learning?.interval,
    config.self_learning?.max_events,
    config.self_learning?.max_rules_per_run,
    config.self_learning?.min_confidence,
    config.self_learning?.min_events,
    reasoningConfig.api_base,
    reasoningConfig.allow_private_api_base,
    reasoningConfig.model,
    reasoningConfig.provider,
  ]);

  useEffect(() => {
    setEventPage(1);
  }, [analysisRange]);

  useEffect(() => {
    if (eventPage > eventPageCount) {
      setEventPage(eventPageCount);
    }
  }, [eventPage, eventPageCount]);

  useEffect(() => () => {
    singleAnalysisAbortRef.current?.controller.abort();
  }, []);

  const setField = <K extends keyof AIFormValues>(key: K, value: AIFormValues[K]) => {
    setFormValues((current) => ({ ...current, [key]: value }));
  };

  const updateMutation = useMutation({
    mutationFn: updateAIConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-config'] });
      toast.success(t('system.saved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const testMutation = useMutation({
    mutationFn: (target: 'assistant' | 'reasoning') => testAIConnection(buildAIModelRequest(formValues, target)),
    onSuccess: () => toast.success(t('ai.testOk')),
    onError: (error) => toast.error(error.message),
  });
  const modelsMutation = useMutation({
    mutationFn: (target: 'assistant' | 'reasoning') => {
      return fetchAIModels(buildAIModelRequest(formValues, target));
    },
    onSuccess: (result, target) => {
      if (target === 'reasoning') {
        setReasoningModels(result.items ?? []);
      } else {
        setModels(result.items ?? []);
      }
      toast.success(t('ai.modelsLoaded', { count: result.total ?? result.items?.length ?? 0 }));
    },
    onError: (error) => toast.error(error.message),
  });
  const selfLearningMutation = useMutation({
    mutationFn: (dryRun: boolean) => runAISelfLearning({ dry_run: dryRun, language: i18n.language }),
    onSuccess: (report) => {
      setSelfLearningReport(report);
      toast.success(t('ai.selfLearningRunOk', { candidates: report.candidates.length, applied: report.applied.length }));
    },
    onError: (error) => toast.error(error.message),
  });
  const eventAnalysisMutation = useMutation({
    mutationFn: async ({ entry, controller }: { entry: LogEntry; controller: AbortController }) => {
      const key = eventKey(entry);
      setLiveAnalysis({ key, trace: [], reasoning: '', content: '' });
      const analysis = await analyzeLogReferenceStream(entry.trace_id || entry.id, i18n.language, (trace) => {
        setLiveAnalysis((current) => {
          if (!current || current.key !== key) {
            return current;
          }
          return {
            ...current,
            trace: [...current.trace.slice(-40), trace],
            reasoning: trace.type === 'reasoning_delta' ? appendStreamText(current.reasoning, trace.message) : current.reasoning,
            content: trace.type === 'content_delta' ? appendStreamText(current.content, trace.message) : current.content,
          };
        });
      }, controller.signal);
      return { analysis, controller, key };
    },
    onSuccess: ({ analysis, key }) => {
      setAnalyses((current) => ({ ...current, [key]: analysis, [analysis.log_id]: analysis }));
      setLiveAnalysis((current) => (current?.key === key ? null : current));
    },
    onError: (error) => {
      if (error instanceof APIRequestError && error.code === 'AI_ANALYSIS_CANCELLED') {
        return;
      }
      toast.error(error.message);
    },
    onSettled: (_data, _error, variables) => {
      if (!variables) {
        return;
      }
      const key = eventKey(variables.entry);
      setLiveAnalysis((current) => (current?.key === key ? null : current));
      if (singleAnalysisAbortRef.current?.controller === variables.controller) {
        singleAnalysisAbortRef.current = null;
      }
    },
  });
  const batchAnalysisMutation = useMutation({
    mutationFn: () => analyzeEventsStream(
      { ...buildAnalysisWindowQuery(analysisRange, 200), language: i18n.language },
      undefined,
    ),
    onSuccess: (result) => {
      setAnalyses((current) => {
        const next = { ...current };
        for (const item of result.items) {
          next[item.log_id] = item;
        }
        return next;
      });
      toast.success(`${t('ai.analyzed')} ${result.total}`);
    },
    onError: (error) => toast.error(error.message),
  });
  const analyzingEventKey = eventAnalysisMutation.variables ? eventKey(eventAnalysisMutation.variables.entry) : '';

  function startEventAnalysis(entry: LogEntry) {
    singleAnalysisAbortRef.current?.controller.abort();
    const controller = new AbortController();
    singleAnalysisAbortRef.current = { key: eventKey(entry), controller };
    eventAnalysisMutation.mutate({ entry, controller });
  }

  function handleSave(event: FormEvent) {
    event.preventDefault();
    if (!configQuery.isSuccess) {
      return;
    }
    const numeric = Number(formValues.selfLearningMaxEvents);
    if (!Number.isInteger(numeric) || numeric < SELF_LEARNING_MAX_EVENTS_RANGE.min || numeric > SELF_LEARNING_MAX_EVENTS_RANGE.max) {
      setMaxEventsError(t('ai.maxEventsRange', {
        min: SELF_LEARNING_MAX_EVENTS_RANGE.min,
        max: SELF_LEARNING_MAX_EVENTS_RANGE.max,
        defaultValue: `max_events must be ${SELF_LEARNING_MAX_EVENTS_RANGE.min}-${SELF_LEARNING_MAX_EVENTS_RANGE.max}`,
      }));
      return;
    }
    setMaxEventsError('');
    try {
      updateMutation.mutate(buildAIConfigPayload(formValues, config, assistantConfig, reasoningConfig));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('ai.invalidConfig'));
    }
  }

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
              <div className="ai-config-inline-switches flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-2">
                  <Label htmlFor="ai-enabled">{t('ai.enabled')}</Label>
                  <Switch id="ai-enabled" checked={formValues.enabled} onCheckedChange={(checked) => setField('enabled', checked)} />
                </div>
                <div className="flex items-center gap-2">
                  <Label htmlFor="ai-async">{t('ai.async')}</Label>
                  <Switch id="ai-async" checked={formValues.async} onCheckedChange={(checked) => setField('async', checked)} />
                </div>
              </div>
              <Button
                variant="outline"
                onClick={() => testMutation.mutate('assistant')}
                loading={testMutation.isPending && testMutation.variables === 'assistant'}
              >
                <ShieldCheck size={14} />
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
          <form className="ai-config-form" onSubmit={handleSave}>
            <div className="ai-config-main">
              <AIModelFormBlock
                title={t('ai.assistantModel')}
                description={t('ai.assistantModelHint')}
                prefix="assistant"
                t={t}
                values={formValues}
                setField={setField}
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
                values={formValues}
                setField={setField}
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
                      <FieldSwitch label={t('common.enabled')} checked={formValues.selfLearningEnabled} onChange={(v) => setField('selfLearningEnabled', v)} />
                      <FieldSwitch label={t('ai.selfLearningAutoApply')} checked={formValues.selfLearningAutoApply} onChange={(v) => setField('selfLearningAutoApply', v)} />
                      <FieldSwitch label={t('ai.selfLearningDryRun')} checked={formValues.selfLearningDryRun} onChange={(v) => setField('selfLearningDryRun', v)} />
                      <FieldInput label={t('ai.selfLearningInterval')} value={String(formValues.selfLearningInterval)} onChange={(v) => setField('selfLearningInterval', v)} placeholder="24h" />
                      <FieldInput label={t('ai.selfLearningAt')} value={String(formValues.selfLearningAt)} onChange={(v) => setField('selfLearningAt', v)} placeholder="03:30" />
                      <FieldInput label={t('ai.selfLearningConfidence')} type="number" value={String(formValues.selfLearningMinConfidence)} onChange={(v) => setField('selfLearningMinConfidence', v)} min={0.9} max={1} step={0.001} />
                      <FieldInput label={t('ai.selfLearningMinEvents')} type="number" value={String(formValues.selfLearningMinEvents)} onChange={(v) => setField('selfLearningMinEvents', v)} min={2} />
                      <div className="space-y-1.5">
                        <Label>{t('ai.maxEventsLabel')}</Label>
                        <Input
                          type="number"
                          min={SELF_LEARNING_MAX_EVENTS_RANGE.min}
                          max={SELF_LEARNING_MAX_EVENTS_RANGE.max}
                          step={1}
                          value={String(formValues.selfLearningMaxEvents)}
                          onChange={(event) => {
                            setField('selfLearningMaxEvents', event.target.value);
                            setMaxEventsError('');
                          }}
                        />
                        {maxEventsError ? <p className="text-xs text-destructive">{maxEventsError}</p> : null}
                      </div>
                      <FieldInput label={t('ai.selfLearningMaxRules')} type="number" value={String(formValues.selfLearningMaxRulesPerRun)} onChange={(v) => setField('selfLearningMaxRulesPerRun', v)} min={1} max={20} />
                      <div className="space-y-1.5">
                        <Label>{t('ai.selfLearningAction')}</Label>
                        <Select value={formValues.selfLearningAction} onValueChange={(value) => setField('selfLearningAction', value)}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="block">{displayAction('block', t)}</SelectItem>
                            <SelectItem value="challenge">{displayAction('challenge', t)}</SelectItem>
                            <SelectItem value="log">{displayAction('log', t)}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Button type="button" variant="outline" onClick={() => selfLearningMutation.mutate(true)} loading={selfLearningMutation.isPending}>
                        {t('ai.selfLearningDryRunNow')}
                      </Button>
                      <Button type="button" variant="secondary" onClick={() => selfLearningMutation.mutate(false)} loading={selfLearningMutation.isPending}>
                        {t('ai.selfLearningRunNow')}
                      </Button>
                    </div>
                    {selfLearningReport && (
                      <div className="ai-self-learning-report">
                        <Badge variant="secondary">{t('ai.selfLearningCandidates', { count: selfLearningReport.candidates.length })}</Badge>
                        <Badge variant="success">{t('ai.selfLearningApplied', { count: selfLearningReport.applied.length })}</Badge>
                        <Badge variant="warning">{t('ai.selfLearningSkipped', { count: selfLearningReport.skipped.length })}</Badge>
                      </div>
                    )}
                  </div>
                  <div className="ai-config-subpanel ai-knowledge-subpanel">
                    <header>
                      <strong>{t('ai.knowledge')}</strong>
                      <span>{t('ai.knowledgeHint')}</span>
                    </header>
                    <div className="ai-config-section ai-knowledge-grid">
                      <FieldSwitch label={t('common.enabled')} checked={formValues.knowledgeEnabled} onChange={(v) => setField('knowledgeEnabled', v)} />
                      <FieldSwitch label={t('ai.knowledgeBuiltin')} checked={formValues.knowledgeBuiltin} onChange={(v) => setField('knowledgeBuiltin', v)} />
                      <FieldInput label={t('ai.knowledgeMaxSnippets')} type="number" value={String(formValues.knowledgeMaxSnippets)} onChange={(v) => setField('knowledgeMaxSnippets', v)} min={1} max={20} />
                    </div>
                  </div>
                </div>
              </div>
              <div className="ai-config-actions-row">
                {configQuery.isError && (
                  <Button type="button" variant="outline" onClick={() => configQuery.refetch()} loading={configQuery.isFetching}>{t('common.retry')}</Button>
                )}
                <Button className="ai-config-save" type="submit" loading={updateMutation.isPending} disabled={!configQuery.isSuccess}>{t('common.save')}</Button>
              </div>
            </div>
          </form>
        </section>

        <section className="panel ai-events-panel">
          <div className="panel-heading">
            <h2><ListChecks size={16} /> {t('ai.events')}</h2>
            <div className="flex flex-wrap items-center gap-2">
              <Select value={analysisRange} onValueChange={setAnalysisRange}>
                <SelectTrigger className="ai-analysis-range-select w-[140px]" aria-label={t('ai.timeRange')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {analysisRanges.map((range) => (
                    <SelectItem key={range.value} value={range.value}>{t(range.labelKey)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={() => batchAnalysisMutation.mutate()} loading={batchAnalysisMutation.isPending} disabled={events.length === 0}>
                {t('ai.analyzeRecent')}
              </Button>
            </div>
          </div>
          <div className="ai-events-list-panel">
            <div className="ai-events-list-header" aria-hidden="true">
              <span>{t('logs.time')}</span>
              <span>{t('logs.source')}</span>
              <span>{t('logs.action')}</span>
              <span>{t('logs.category')}</span>
              <span>{t('logs.path')}</span>
              <span>{t('ai.analysis')}</span>
            </div>
            <div className="ai-events-list" aria-busy={isLoading}>
              {isLoading && Array.from({ length: 4 }).map((_, index) => (
                <div className="ai-events-list-row security-event-skeleton" key={index} />
              ))}
              {!isLoading && eventPageItems.length === 0 && <div className="empty-state">{t('ai.noEvents')}</div>}
              {!isLoading && eventPageItems.map((record) => {
                const key = eventKey(record);
                const selectedRow = Boolean(selected && eventKey(selected) === key);
                return (
                  <article
                    className={`ai-events-list-row${selectedRow ? ' ai-events-list-row-active' : ''}`}
                    key={key}
                    aria-current={selectedRow ? 'true' : undefined}
                  >
                    <button
                      type="button"
                      className="ai-event-row-select"
                      aria-pressed={selectedRow}
                      style={{ all: 'unset', display: 'grid', gap: 'inherit', width: '100%', cursor: 'pointer', boxSizing: 'border-box' }}
                      onClick={() => setSelectedId(key)}
                    >
                      <header className="ai-event-row-head">
                        <div className="ai-event-row-identity">
                          <time dateTime={record.timestamp} title={formatTime(record.timestamp)}>{formatCompactTime(record.timestamp)}</time>
                          <span title={record.client_ip || '-'}>{record.client_ip || '-'}</span>
                        </div>
                        <div className="ai-event-row-tags">
                          <Badge variant={actionBadgeVariant(record.action)}>{displayAction(record.action, t)}</Badge>
                          {record.category ? <Badge variant="warning">{displayCategory(record.category, t)}</Badge> : <Badge variant="secondary">{t('common.monitor')}</Badge>}
                        </div>
                      </header>
                      <code className="ai-event-row-uri" title={record.uri || '-'}>{record.uri || '-'}</code>
                    </button>
                    <footer className="ai-events-row-actions" role="group" aria-label={t('ai.analysis')}>
                      <Link
                        to={`/logs/${encodeURIComponent(record.trace_id || record.id)}`}
                        className="table-action-link"
                      >
                        <Button size="sm" variant="outline">
                          <Eye size={14} />
                          {t('logs.detail')}
                        </Button>
                      </Link>
                      <Button
                        size="sm"
                        variant="outline"
                        loading={eventAnalysisMutation.isPending && analyzingEventKey === key}
                        onClick={() => {
                          setSelectedId(key);
                          startEventAnalysis(record);
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
                    size="icon"
                    variant="outline"
                    aria-label={t('common.back')}
                    disabled={eventPage <= 1}
                    onClick={() => setEventPage((current) => Math.max(1, current - 1))}
                  >
                    <ChevronLeft size={15} />
                  </Button>
                  <strong>{eventPage}</strong>
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label={t('common.next')}
                    disabled={eventPage >= eventPageCount}
                    onClick={() => setEventPage((current) => Math.min(eventPageCount, current + 1))}
                  >
                    <ChevronRight size={15} />
                  </Button>
                </div>
              </footer>
            )}
          </div>
        </section>

        <section className="panel ai-event-detail">
          <div className="panel-heading">
            <h2><BrainCircuit size={16} /> {t('ai.eventAnalysis')}</h2>
            {selectedAnalysis && <Badge variant={riskBadgeVariant(selectedAnalysis.risk)}>{displayRisk(selectedAnalysis.risk, t)}</Badge>}
          </div>
          {selected ? (
            <div className="ai-detail-workbench">
              <div className="ai-event-summary-card">
                <div className="ai-event-summary-main">
                  <span>{t('ai.selectedEvent')}</span>
                  <strong>{eventKey(selected)}</strong>
                  <code>{selected.method} {selected.uri}</code>
                </div>
                <div className="ai-event-summary-meta">
                  <Badge variant="secondary">{selected.client_ip || '-'}</Badge>
                  <Badge variant={actionBadgeVariant(selected.action)}>{displayAction(selected.action, t)}</Badge>
                  <Badge variant="warning">{displayCategory(selected.category, t)}</Badge>
                </div>
                <Button
                  className="ai-event-summary-action"
                  loading={eventAnalysisMutation.isPending && analyzingEventKey === eventKey(selected)}
                  onClick={() => startEventAnalysis(selected)}
                >
                  {selectedAnalysis ? t('ai.reanalyze') : t('ai.run')}
                </Button>
              </div>
              <PolicyDecisionCard metadata={selected.metadata} compact />

              <div className="ai-analysis-workspace">
                {(selectedLiveAnalysis || (eventAnalysisMutation.isPending && analyzingEventKey === eventKey(selected))) && (
                  <div className="ai-analysis-card ai-analysis-live-card">
                    <AnalysisLiveTrace
                      pending={eventAnalysisMutation.isPending && analyzingEventKey === eventKey(selected)}
                      trace={selectedLiveAnalysis?.trace ?? []}
                      reasoning={selectedLiveAnalysis?.reasoning ?? ''}
                      content={selectedLiveAnalysis?.content ?? ''}
                    />
                  </div>
                )}
                <div className="ai-analysis-card ai-analysis-result-card">
                  {selectedAnalysis ? (
                    <>
                      <div className="ai-analysis-summary">
                        <KeyRound size={16} />
                        <AIAnalysisSummary analysis={selectedAnalysis} />
                      </div>
                      <AIReasoningSummary analysis={selectedAnalysis} />
                      <div className="ai-analysis-lists">
                        <section>
                          <strong>{t('ai.evidence')}</strong>
                          <ul>
                            {(selectedAnalysis.evidence ?? []).length > 0
                              ? selectedAnalysis.evidence.map((item, index) => <li key={`evidence-${index}`}>{item}</li>)
                              : <li>-</li>}
                          </ul>
                        </section>
                        <section>
                          <strong>{t('ai.actions')}</strong>
                          <ul>
                            {(selectedAnalysis.recommended_actions ?? []).length > 0
                              ? selectedAnalysis.recommended_actions.map((item, index) => <li key={`action-${index}`}>{item}</li>)
                              : <li>-</li>}
                          </ul>
                        </section>
                      </div>
                      <AIAnalysisMeta analysis={selectedAnalysis} />
                    </>
                  ) : (
                    <div className="empty-state">{t('ai.selectAndAnalyze')}</div>
                  )}
                </div>
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

function FieldSwitch({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <Label>{label}</Label>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

function FieldInput({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  min,
  max,
  step,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  min?: number;
  max?: number;
  step?: number;
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Input
        type={type}
        value={value}
        placeholder={placeholder}
        min={min}
        max={max}
        step={step}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  );
}

function AnalysisLiveTrace({
  pending,
  trace,
  reasoning,
  content,
}: {
  pending: boolean;
  trace: AIAssistantTraceEvent[];
  reasoning: string;
  content: string;
}) {
  const { t } = useTranslation();
  if (!pending && trace.length === 0 && !reasoning && !content) {
    return null;
  }
  const visibleTrace = formatAnalysisTraceEvents(trace, t)
    .filter((item): item is { key: string; text: string } => Boolean(item))
    .slice(-5);
  return (
    <div className="analysis-live-trace">
      <div>
        <strong>{pending ? t('ai.thinking') : t('ai.analysisTrace')}</strong>
        {pending && <Spinner className="size-3.5" />}
      </div>
      {reasoning && (
        <section>
          <span>{t('ai.liveReasoning')}</span>
          <SafeMarkdown text={reasoning} />
        </section>
      )}
      {content && (
        <section>
          <span>{t('ai.streamingAnswer')}</span>
          <SafeMarkdown text={content} />
        </section>
      )}
      {visibleTrace.length > 0 && (
        <ul>
          {visibleTrace.map((item) => (
            <li key={item.key}>
              <span>{item.text}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function formatAnalysisTraceEvents(trace: AIAssistantTraceEvent[], t: (key: string, options?: Record<string, unknown>) => string) {
  const toolDeltaCounts = new Map<string, number>();
  return trace.map((event, index) => {
    if (event.type === 'tool_call_delta') {
      const tool = event.tool_name || t('common.unknown');
      const chunks = (toolDeltaCounts.get(tool) ?? 0) + 1;
      toolDeltaCounts.set(tool, chunks);
      return { key: `trace-${index}-${event.type}-${tool}-${chunks}`, text: t('ai.toolDeltaLive', { tool, chunks }) };
    }
    const text = formatAnalysisTraceEvent(event, t);
    return text ? { key: `trace-${index}-${event.type}`, text } : '';
  });
}

function formatAnalysisTraceEvent(event: AIAssistantTraceEvent, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (event.type) {
    case 'heartbeat':
    case 'reasoning_delta':
    case 'content_delta':
      return '';
    case 'stream_open':
      return event.message || t('ai.streamConnected');
    case 'provider_response_start':
      return event.message || t('ai.providerStarted');
    case 'provider_first_event_slow':
    case 'provider_waiting_progress':
      return event.message || t('ai.providerSlow');
    case 'tool_error':
    case 'planning_error':
    case 'final_error':
      return event.error || event.message || t('ai.providerSlow');
    default:
      return event.message || '';
  }
}

function appendStreamText(current: string, delta: string) {
  if (!delta) {
    return current;
  }
  if (!current) {
    return delta;
  }
  if (/^\s/.test(delta) || /\s$/.test(current)) {
    return `${current}${delta}`;
  }
  const last = current[current.length - 1] ?? '';
  const first = delta[0] ?? '';
  const needsSpace = /[A-Za-z0-9)]/.test(last) && /[A-Za-z0-9([]/.test(first);
  return `${current}${needsSpace ? ' ' : ''}${delta}`;
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

export function buildAIConfigPayload(
  values: Record<string, any>,
  config: AIConfig,
  assistantConfig: AIModelConfig,
  reasoningConfig: AIModelConfig,
): AIConfig {
  return {
    enabled: values.enabled,
    provider: values.assistantProvider || values.provider || 'openai',
    api_base: values.assistantAPIBase || values.apiBase,
    api_key: values.assistantAPIKey || values.apiKey,
    api_key_set: config.api_key_set,
    model: values.assistantModel || values.model,
    async: values.async,
    allow_private_api_base: values.assistantAllowPrivateAPIBase ?? values.allowPrivateAPIBase,
    assistant: {
      provider: values.assistantProvider || 'openai',
      api_base: values.assistantAPIBase,
      api_key: values.assistantAPIKey,
      api_key_set: assistantConfig.api_key_set,
      model: values.assistantModel,
      allow_private_api_base: values.assistantAllowPrivateAPIBase,
    },
    reasoning: {
      provider: values.reasoningProvider || 'openai',
      api_base: values.reasoningAPIBase,
      api_key: values.reasoningAPIKey,
      api_key_set: reasoningConfig.api_key_set,
      model: values.reasoningModel,
      allow_private_api_base: values.reasoningAllowPrivateAPIBase,
    },
    self_learning: {
      enabled: values.selfLearningEnabled,
      auto_apply: values.selfLearningAutoApply,
      dry_run: values.selfLearningDryRun,
      interval: durationInputToNanoseconds(values.selfLearningInterval),
      at: values.selfLearningAt,
      min_confidence: Number(values.selfLearningMinConfidence),
      min_events: Number(values.selfLearningMinEvents),
      max_events: validateSelfLearningMaxEvents(values.selfLearningMaxEvents),
      max_rules_per_run: Number(values.selfLearningMaxRulesPerRun),
      action: values.selfLearningAction || 'block',
    },
    knowledge: {
      enabled: values.knowledgeEnabled,
      builtin: values.knowledgeBuiltin,
      max_snippets: Number(values.knowledgeMaxSnippets || 5),
    },
  };
}

export function validateSelfLearningMaxEvents(value: unknown) {
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric < SELF_LEARNING_MAX_EVENTS_RANGE.min || numeric > SELF_LEARNING_MAX_EVENTS_RANGE.max) {
    throw new Error(`max_events must be ${SELF_LEARNING_MAX_EVENTS_RANGE.min}-${SELF_LEARNING_MAX_EVENTS_RANGE.max}`);
  }
  return numeric;
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
  values,
  setField,
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
  values: AIFormValues;
  setField: <K extends keyof AIFormValues>(key: K, value: AIFormValues[K]) => void;
  models: AIModelInfo[];
  loadingModels: boolean;
  keyStored: boolean;
  onFetchModels: () => void;
  onTest: () => void;
  testing: boolean;
}) {
  const providerKey = `${prefix}Provider` as const;
  const apiBaseKey = `${prefix}APIBase` as const;
  const modelKey = `${prefix}Model` as const;
  const apiKeyKey = `${prefix}APIKey` as const;
  const privateKey = `${prefix}AllowPrivateAPIBase` as const;
  const modelValue = String(values[modelKey] || '');
  const modelIds = models.map((model) => model.id);
  const knownModel = modelIds.includes(modelValue);

  return (
    <div className="ai-config-subpanel ai-model-config-subpanel">
      <header>
        <strong>{title}</strong>
        <span>{description}</span>
      </header>
      <div className="ai-config-section ai-model-config-grid">
        <div className="space-y-1.5">
          <Label>{t('ai.provider')}</Label>
          <Select value={String(values[providerKey] || 'openai')} onValueChange={(value) => setField(providerKey, value)}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="openai">{t('ai.providerOpenAI')}</SelectItem>
              <SelectItem value="anthropic">{t('ai.providerAnthropic')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>{t('ai.apiBase')}</Label>
          <Input value={String(values[apiBaseKey] || '')} onChange={(event) => setField(apiBaseKey, event.target.value)} />
        </div>
        <div className="space-y-1.5">
          <Label>{t('ai.model')}</Label>
          {models.length > 0 ? (
            <Select
              value={knownModel ? modelValue : modelIds[0]}
              onValueChange={(value) => setField(modelKey, value)}
            >
              <SelectTrigger>
                <SelectValue placeholder={t('ai.modelPlaceholder')} />
              </SelectTrigger>
              <SelectContent>
                {models.map((model) => (
                  <SelectItem key={model.id} value={model.id}>
                    {model.owned_by ? `${model.id} · ${model.owned_by}` : model.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <>
              <Input
                value={modelValue}
                placeholder={loadingModels ? t('ai.modelsLoading') : t('ai.modelPlaceholder')}
                onChange={(event) => setField(modelKey, event.target.value)}
              />
              {!loadingModels ? <p className="text-xs text-muted-foreground">{t('ai.modelsEmpty')}</p> : null}
            </>
          )}
          {models.length > 0 && !knownModel && (
            <Input
              className="mt-1"
              value={modelValue}
              placeholder={t('ai.modelPlaceholder')}
              onChange={(event) => setField(modelKey, event.target.value)}
            />
          )}
        </div>
        <div className="space-y-1.5">
          <Label>{t('ai.apiKey')}</Label>
          <Input
            type="password"
            value={String(values[apiKeyKey] || '')}
            placeholder={keyStored ? t('ai.keyStored') : ''}
            onChange={(event) => setField(apiKeyKey, event.target.value)}
          />
        </div>
        <div className="ai-model-private-field flex items-center justify-between gap-2">
          <div>
            <Label>{t('ai.allowPrivateAPIBase')}</Label>
            <p className="text-xs text-muted-foreground">{t('ai.allowPrivateAPIBaseHint')}</p>
          </div>
          <Switch checked={Boolean(values[privateKey])} onCheckedChange={(checked) => setField(privateKey, checked)} />
        </div>
      </div>
      <div className="ai-model-config-actions flex flex-wrap gap-2">
        <Button type="button" variant="outline" onClick={onFetchModels} loading={loadingModels}>
          <KeyRound size={14} />
          {t('ai.fetchModels')}
        </Button>
        <Button type="button" variant="outline" onClick={onTest} loading={testing}>
          <ShieldCheck size={14} />
          {t('ai.test')}
        </Button>
      </div>
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
  const action = (entry.action || '').toLowerCase();
  const category = (entry.category || '').toLowerCase();
  if (action === 'block' || action === 'challenge') {
    return true;
  }
  if (!category) {
    return action === 'log';
  }
  if (['normal', 'access', 'pass', 'cache', 'cache_hit', 'redirect', 'health', 'proxy_error'].includes(category)) {
    return false;
  }
  if (['sqli', 'sql', 'xss', 'rce', 'lfi', 'xxe', 'ssrf', 'nosqli', 'ssti', 'webshell'].includes(category)) {
    return true;
  }
  if (action === 'log') {
    return true;
  }
  return ['threat_intel', 'ip_access', 'geoip', 'acl', 'bot', 'cc', 'ratelimit', 'api_security', 'protocol_enforcement', 'custom_rule'].includes(category);
}

function actionBadgeVariant(action: string): 'destructive' | 'warning' | 'default' | 'secondary' {
  switch (action) {
    case 'block':
      return 'destructive';
    case 'challenge':
      return 'warning';
    case 'log':
      return 'default';
    default:
      return 'secondary';
  }
}

function riskBadgeVariant(risk: string): 'destructive' | 'warning' | 'success' {
  switch (risk) {
    case 'critical':
    case 'high':
      return 'destructive';
    case 'medium':
      return 'warning';
    default:
      return 'success';
  }
}

function displayRisk(risk: string, t: (key: string) => string) {
  switch (risk) {
    case 'critical':
      return t('rules.critical');
    case 'high':
      return t('rules.high');
    case 'medium':
      return t('rules.medium');
    case 'low':
      return t('rules.low');
    default:
      return risk || '-';
  }
}
