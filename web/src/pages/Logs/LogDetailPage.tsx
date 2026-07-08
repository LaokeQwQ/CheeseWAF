import { Button, Message as ArcoMessage, Space, Spin, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, BrainCircuit, ShieldAlert } from 'lucide-react';
import { analyzeLogReferenceStream, fetchLogEvent } from '../../api/client';
import AIAnalysisMeta, { AIAnalysisSummary, AIReasoningSummary } from '../../components/AIAnalysisMeta';
import SafeMarkdown from '../../components/SafeMarkdown';
import type { AIAssistantTraceEvent, AttackAnalysis, LogEntry } from '../../types/api';
import { displayAction, displayCategory, displaySeverity, formatLogLocation } from '../../utils/display';

export default function LogDetailPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { traceId = '' } = useParams();
  const reference = decodeURIComponent(traceId);
  const abortRef = useRef<AbortController | null>(null);
  const [analysisTrace, setAnalysisTrace] = useState<AIAssistantTraceEvent[]>([]);
  const [streamReasoning, setStreamReasoning] = useState('');
  const [streamContent, setStreamContent] = useState('');
  const { data: event, isLoading, error } = useQuery({
    queryKey: ['log-detail', reference],
    queryFn: () => fetchLogEvent(reference),
    enabled: reference.length > 0,
    retry: false,
  });
  const analysisMutation = useMutation({
    mutationFn: async (entry: LogEntry) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;
      setAnalysisTrace([]);
      setStreamReasoning('');
      setStreamContent('');
      return analyzeLogReferenceStream(entry.trace_id || entry.id || reference, i18n.language, (trace) => {
        setAnalysisTrace((items) => [...items.slice(-40), trace]);
        if (trace.type === 'reasoning_delta') {
          setStreamReasoning((value) => appendStreamText(value, trace.message));
        }
        if (trace.type === 'content_delta') {
          setStreamContent((value) => appendStreamText(value, trace.message));
        }
      }, controller.signal);
    },
    onError: (mutationError) => ArcoMessage.error(mutationError.message),
  });
  const analysis = analysisMutation.data;

  useEffect(() => () => {
    abortRef.current?.abort();
  }, []);

  return (
    <section className="page-surface log-detail-page">
      <header className="page-header">
        <div>
          <h1>{t('logs.eventDetail')}</h1>
          <p>{event ? event.trace_id || event.id : reference}</p>
        </div>
        <Button icon={<ArrowLeft size={16} />} onClick={() => navigate('/logs')}>
          {t('logs.backToLogs')}
        </Button>
      </header>

      <Spin loading={isLoading}>
        {error && <section className="panel"><div className="empty-state">{error.message}</div></section>}
        {event && (
          <div className="event-detail-grid">
            <div className="event-detail-main">
              <section className="panel">
                <div className="panel-heading">
                  <h2><ShieldAlert size={16} /> {t('logs.event')}</h2>
                  <Space wrap>
                    <Tag color={actionColor(event.action)}>{displayAction(event.action, t)}</Tag>
                    <Tag color={event.category ? 'orange' : 'green'}>{displayCategory(event.category, t)}</Tag>
                    <Tag>{displaySeverity(event.severity, t)}</Tag>
                  </Space>
                </div>
                <div className="detail-kv-grid">
                  <DetailKV label={t('logs.trace')} value={event.trace_id || event.id || '-'} />
                  <DetailKV label={t('logs.time')} value={formatTime(event.timestamp)} />
                  <DetailKV label={t('logs.source')} value={event.client_ip || '-'} />
                  <DetailKV label={t('dashboard.ipLocation')} value={formatLogLocation(event, t)} />
                  <DetailKV label={t('logs.method')} value={event.method || '-'} />
                  <DetailKV label="URI" value={<code className="detail-inline-code">{event.uri || '-'}</code>} />
                  <DetailKV label={t('logs.status')} value={String(event.status_code || '-')} />
                  <DetailKV label={t('logs.latency')} value={formatLatency(event.latency)} />
                  <DetailKV label={t('logs.site')} value={event.site_id || '-'} />
                  <DetailKV label={t('logs.detector')} value={event.detector_id || '-'} />
                </div>
              </section>

              <section className="panel">
                <div className="panel-heading">
                  <h2>{t('logs.requestEvidence')}</h2>
                </div>
                <div className="detail-field-stack">
                  <DetailCode title={t('logs.message')} value={event.message} />
                  <DetailCode title={t('logs.payload')} value={event.payload} />
                  <DetailCode title={t('logs.userAgent')} value={event.user_agent} />
                  <DetailCode title={t('logs.metadata')} value={formatMetadata(event.metadata)} />
                </div>
              </section>
            </div>

            <aside className="event-detail-side">
              <section className="panel">
                <div className="panel-heading">
                  <h2><BrainCircuit size={16} /> {t('ai.eventAnalysis')}</h2>
                  {analysis && <Tag color={riskColor(analysis.risk)}>{displayRisk(analysis.risk, t)}</Tag>}
                </div>
                <Button
                  type="primary"
                  long
                  loading={analysisMutation.isPending}
                  onClick={() => analysisMutation.mutate(event)}
                >
                  {analysis ? t('ai.reanalyze') : t('ai.run')}
                </Button>
                <AnalysisLiveTrace
                  pending={analysisMutation.isPending}
                  trace={analysisTrace}
                  reasoning={streamReasoning}
                  content={streamContent}
                />
                <AnalysisResult analysis={analysis} />
              </section>
            </aside>
          </div>
        )}
      </Spin>
    </section>
  );
}

function DetailCode({ title, value }: { title: string; value?: string }) {
  return (
    <div className="detail-code-block">
      <span>{title}</span>
      <pre>{value && value.trim() ? value : '-'}</pre>
    </div>
  );
}

function DetailKV({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
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
  const visibleTrace = trace
    .map((item) => formatAnalysisTraceEvent(item, t))
    .filter((item): item is string => Boolean(item))
    .slice(-5);
  return (
    <div className="analysis-live-trace">
      <div>
        <strong>{pending ? t('ai.thinking') : t('ai.analysisTrace')}</strong>
        {pending && <Spin size={14} />}
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
            <li key={item}>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function formatAnalysisTraceEvent(event: AIAssistantTraceEvent, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (event.type) {
    case 'heartbeat':
    case 'reasoning_delta':
    case 'content_delta':
    case 'tool_call_delta':
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

function AnalysisResult({ analysis }: { analysis?: AttackAnalysis }) {
  const { t } = useTranslation();
  if (!analysis) {
    return <div className="empty-state compact-empty">{t('ai.selectAndAnalyze')}</div>;
  }
  return (
    <div className="analysis-result">
      <AIAnalysisSummary analysis={analysis} />
      <AIAnalysisMeta analysis={analysis} />
      <AIReasoningSummary analysis={analysis} />
      <div>
        <strong>{t('ai.evidence')}</strong>
        {(analysis.evidence ?? []).length > 0 ? analysis.evidence.map((item) => <span key={item}>{item}</span>) : <span>-</span>}
      </div>
      <div>
        <strong>{t('ai.actions')}</strong>
        {(analysis.recommended_actions ?? []).length > 0 ? analysis.recommended_actions.map((item) => <span key={item}>{item}</span>) : <span>-</span>}
      </div>
    </div>
  );
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

function formatMetadata(metadata?: Record<string, unknown>) {
  if (!metadata || Object.keys(metadata).length === 0) {
    return '';
  }
  return JSON.stringify(metadata, null, 2);
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString();
}

function formatLatency(nanoseconds: number) {
  if (!Number.isFinite(nanoseconds) || nanoseconds <= 0) {
    return '0ms';
  }
  return `${(nanoseconds / 1_000_000).toFixed(1)}ms`;
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
