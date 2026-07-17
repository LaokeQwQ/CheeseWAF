import { Button, Empty, Select, Skeleton, Table, Tag } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { Activity, ArrowRight, Bot, CheckCircle2, FlaskConical, Image, RefreshCw, Settings2, ShieldAlert, ShieldX, Users } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { buildBotChallengeOverview, fetchBotChallengeMetrics, type BotChallengeRange } from '../../api/botChallenge';
import { APIRequestError, fetchLogs } from '../../api/client';
import type { BotChallengeEvent, BotChallengeMetricPoint, BotChallengeMetrics, BotChallengeTypeEffect } from '../../types/api';
import styles from './BotChallengePage.module.css';
import CaptchaAssetsPanel from './CaptchaAssetsPanel';

const RANGE_HOURS: Record<BotChallengeRange, number> = { '1h': 1, '6h': 6, '24h': 24, '7d': 168, '30d': 720 };

export default function BotChallengePage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [range, setRange] = useState<BotChallengeRange>('24h');
  const [pageTab, setPageTab] = useState<'overview' | 'assets'>('overview');
  const eventsPermission = readLogsPermission();
  const metricsQuery = useQuery({ queryKey: ['bot-challenge-metrics', range], queryFn: () => fetchBotChallengeMetrics(range), staleTime: 20_000, refetchInterval: 30_000, retry: 1 });
  const eventsQuery = useQuery({ queryKey: ['bot-challenge-events', range], queryFn: () => fetchLogs({ start: new Date(Date.now() - RANGE_HOURS[range] * 3_600_000).toISOString(), limit: 250 }), enabled: eventsPermission !== 'denied', staleTime: 20_000, refetchInterval: 30_000, retry: false });
  const events = useMemo(() => {
    const end = new Date();
    const start = new Date(end.getTime() - RANGE_HOURS[range] * 3_600_000);
    return buildBotChallengeOverview(eventsQuery.data?.items ?? [], start, end).events;
  }, [eventsQuery.data, range]);
  const locale = i18n.resolvedLanguage ?? 'en-US';
  const loading = metricsQuery.isLoading && !metricsQuery.data;
  const failed = metricsQuery.isError && !metricsQuery.data;
  const metrics = metricsQuery.data;
  const eventsForbidden = eventsPermission === 'denied' || isHTTPStatus(eventsQuery.error, 403);
  const eventsError = eventsQuery.isError && !eventsForbidden ? eventsQuery.error : undefined;
  const refreshing = metricsQuery.isFetching || eventsQuery.isFetching;
  const refreshAll = () => void Promise.all(eventsPermission === 'denied' ? [metricsQuery.refetch()] : [metricsQuery.refetch(), eventsQuery.refetch()]);

  return <section className={`page-surface ${styles.page}`}>
    <header className={`page-header ${styles.header}`}>
      <div><h1>{t('botChallenge.title')}</h1><p>{t('botChallenge.subtitle')}</p></div>
      <div className={styles.actions}>
        <Select value={range} onChange={setRange} aria-label={t('botChallenge.period')}>
          {(['1h', '6h', '24h', '7d', '30d'] as BotChallengeRange[]).map((value) => <Select.Option key={value} value={value}>{t(`botChallenge.ranges.${value}`)}</Select.Option>)}
        </Select>
        <Button aria-label={t('common.refresh')} icon={<RefreshCw className={refreshing ? styles.spinning : undefined} size={16}/>} loading={refreshing} onClick={refreshAll}>{t('common.refresh')}</Button>
      </div>
    </header>

    <div className={styles.pageTabs} role="tablist" aria-label={t('botChallenge.title')}><button type="button" role="tab" aria-selected={pageTab === 'overview'} className={pageTab === 'overview' ? styles.activeTab : undefined} onClick={() => setPageTab('overview')}><Activity size={17}/>{t('botChallenge.overviewTab')}</button><button type="button" role="tab" aria-selected={pageTab === 'assets'} className={pageTab === 'assets' ? styles.activeTab : undefined} onClick={() => setPageTab('assets')}><Image size={17}/>{t('botChallenge.assetsTab')}</button></div>
    {pageTab === 'assets' ? <CaptchaAssetsPanel/> : loading ? <OverviewSkeleton /> : failed ? <LoadError t={t} retry={refreshAll}/> : <>
      <MetricGrid metrics={metrics} t={t}/>
      <div className={styles.workspace}>
        <section className={`panel ${styles.trendPanel}`}>
          <div className={`panel-heading ${styles.panelHeading}`}><div><h2>{t('botChallenge.trend')}</h2><span>{t('botChallenge.metricsSource')}</span></div><TrendLegend t={t}/></div>
          <TrendChart points={metrics?.trend ?? []} locale={locale} t={t}/>
        </section>
        <aside className={`panel ${styles.quickPanel}`}>
          <div className={'panel-heading'}><h2>{t('botChallenge.quickActions')}</h2></div>
          <QuickAction icon={<Settings2/>} title={t('botChallenge.openPolicy')} hint={t('botChallenge.openPolicyHint')} onClick={() => navigate('/protection')}/>
          <QuickAction icon={<Image/>} title={t('botChallenge.openAssets')} hint={t('botChallenge.openAssetsHint')} onClick={() => setPageTab('assets')}/>
          <QuickAction icon={<FlaskConical/>} title={t('botChallenge.openLab')} hint={t('botChallenge.openLabHint')} onClick={() => window.open('/captcha-lab', '_blank', 'noopener,noreferrer')}/>
        </aside>
      </div>
      <TypeEffectPanel points={metrics?.trend ?? []} t={t}/>
      <EventTable events={events} loading={eventsQuery.isLoading} forbidden={eventsForbidden} error={eventsError} retry={() => void eventsQuery.refetch()} locale={locale} navigate={navigate} t={t}/>
    </>}
  </section>;
}

function MetricGrid({ metrics, t }: { metrics?: BotChallengeMetrics; t: TFunction }) {
  const totals = metrics?.totals;
  const hasOutcomes = (totals?.successes ?? 0) + (totals?.failures ?? 0) > 0;
  const items = [
    { icon: <Users/>, label: t('botChallenge.challengedClients'), value: formatNumber(totals?.challenged_people), tone: 'brand' },
    { icon: <Bot/>, label: t('botChallenge.challengeCount'), value: formatNumber(totals?.challenges), tone: 'brand' },
    { icon: <ShieldX/>, label: t('botChallenge.blockedClients'), value: formatNumber(totals?.blocked_people), tone: 'danger' },
    { icon: <ShieldAlert/>, label: t('botChallenge.blockCount'), value: formatNumber(totals?.blocks), tone: 'danger' },
    { icon: <Activity/>, label: t('botChallenge.captchaBlocked'), value: formatNumber(totals?.captcha_blocks), tone: 'warning' },
    { icon: <CheckCircle2/>, label: t('botChallenge.passRate'), value: hasOutcomes ? `${((totals?.pass_rate ?? 0) * 100).toFixed(1)}%` : t('botChallenge.notAvailable'), tone: 'success', muted: !hasOutcomes },
  ];
  return <div className={styles.metrics}>{items.map((item) => <div className={`${styles.metric} ${styles[item.tone]}`} key={item.label}><span className={styles.metricIcon}>{item.icon}</span><span className={styles.metricLabel}>{item.label}</span><strong className={item.muted ? styles.muted : undefined}>{item.value}</strong></div>)}</div>;
}

export function TrendChart({ points, locale, t }: { points: BotChallengeMetricPoint[]; locale: string; t: TFunction }) {
  const grouped = useMemo(() => groupTrend(points), [points]);
  const [activeBucket, setActiveBucket] = useState<string | null>(null);
  const max = Math.max(1, ...grouped.flatMap((point) => [point.issued, point.successes, point.failures + point.blocks]));
  if (!grouped.some((point) => point.issued || point.successes || point.failures || point.blocks)) return <Empty className={styles.empty} description={t('botChallenge.noEvents')}/>;
  return <div className={styles.chart} role={'group'} aria-label={t('botChallenge.trendAria')}>
    <div className={styles.chartGrid}>{[100, 75, 50, 25, 0].map((value) => <span key={value} style={{ bottom: `${value}%` }}><b>{Math.round(max * value / 100)}</b></span>)}</div>
    <div className={styles.plot}>{grouped.map((point, index) => {
      const open = activeBucket === point.time;
      const tooltipID = `bot-challenge-bucket-${index}`;
      return <button
        type={'button'}
        className={`${styles.bucket} ${open ? styles.bucketActive : ''}`}
        key={point.time}
        aria-label={t('botChallenge.bucketAria', { challenged: point.issued, passed: point.successes, blocked: point.failures + point.blocks })}
        aria-expanded={open}
        aria-describedby={open ? tooltipID : undefined}
        onBlur={() => setActiveBucket((current) => current === point.time ? null : current)}
        onClick={() => setActiveBucket((current) => current === point.time ? null : point.time)}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            event.preventDefault();
            setActiveBucket(null);
          }
        }}
      >
      <i className={styles.issuedBar} style={{ height: `${point.issued / max * 100}%` }}/><i className={styles.successBar} style={{ height: `${point.successes / max * 100}%` }}/><i className={styles.blockedBar} style={{ height: `${(point.failures + point.blocks) / max * 100}%` }}/>
      {(index === 0 || index === grouped.length - 1 || index === Math.floor(grouped.length / 2)) && <small>{formatBucketTime(point.time, locale, grouped.length)}</small>}
      <span id={tooltipID} role={'tooltip'} data-open={open} className={styles.bucketTip}>{t('botChallenge.bucketDetail', { challenged: point.issued, passed: point.successes, failed: point.failures, blocked: point.blocks })}</span>
    </button>;
    })}</div>
  </div>;
}

function TrendLegend({ t }: { t: TFunction }) { return <div className={styles.legend}><span><i className={styles.issuedDot}/>{t('botChallenge.legendIssued')}</span><span><i className={styles.successDot}/>{t('botChallenge.legendPassed')}</span><span><i className={styles.blockedDot}/>{t('botChallenge.legendBlocked')}</span></div>; }

function TypeEffectPanel({ points, t }: { points: BotChallengeMetricPoint[]; t: TFunction }) {
  const effects = useMemo(() => aggregateEffects(points), [points]);
  return <section className={`panel ${styles.effectPanel}`}><div className={'panel-heading'}><h2>{t('botChallenge.typeEffect')}</h2><span>{t('botChallenge.typeEffectHint')}</span></div>{effects.length ? <div className={styles.effectList}>{effects.map((item) => <div key={item.type}><div><strong>{typeLabel(item.type, t)}</strong><span>{t('botChallenge.issuedCount', { count: item.issued })}</span></div><b>{item.passRate == null ? t('botChallenge.noOutcomeData') : `${(item.passRate * 100).toFixed(1)}%`}</b><div className={styles.rateTrack}><i style={{ width: `${(item.passRate ?? 0) * 100}%` }}/></div></div>)}</div> : <Empty description={t('botChallenge.noTypeData')}/>}</section>;
}

function EventTable({ events, loading, forbidden, error, retry, locale, navigate, t }: { events: BotChallengeEvent[]; loading: boolean; forbidden: boolean; error?: unknown; retry: () => void; locale: string; navigate: (path: string) => void; t: TFunction }) {
  const eventRows = events.map((event) => ({
    label: event.traceId || event.id,
    values: [
      [t('botChallenge.time'), new Date(event.timestamp).toLocaleString(locale)],
      [t('botChallenge.clientIp'), event.clientIp],
      [t('botChallenge.location'), event.country || t('common.unknown')],
      [t('botChallenge.site'), event.siteId || '—'],
      [t('botChallenge.type'), typeLabel(event.challengeType ?? 'unknown', t)],
      [t('botChallenge.reason'), event.reason || '—'],
    ],
    event,
  }));
  return <section className={`panel ${styles.eventPanel}`}>
    <div className={'panel-heading'}><h2>{t('botChallenge.events')}</h2><span>{t('botChallenge.eventsHint')}</span></div>
    {forbidden ? <EventPanelState
      title={t('botChallenge.captchaAssets.forbidden')}
      hint={t('botChallenge.eventsPermissionHint', { defaultValue: 'The read:logs permission is required to view challenge events. Metrics remain available with read:protection.' })}
    /> : error ? <EventPanelState title={t('botChallenge.loadFailed')} hint={eventErrorMessage(error, t)} retry={retry} retryLabel={t('common.retry')}/> : <>
      <div className={styles.eventTable}><Table loading={loading} rowKey={'id'} pagination={{ pageSize: 10, hideOnSinglePage: true, sizeCanChange: false }} data={events} noDataElement={<Empty description={t('botChallenge.noEvents')}/>} scroll={{ x: 980 }} columns={[{ title: t('botChallenge.time'), dataIndex: 'timestamp', width: 180, render: (value: string) => new Date(value).toLocaleString(locale) }, { title: t('botChallenge.clientIp'), dataIndex: 'clientIp', width: 150 }, { title: t('botChallenge.location'), dataIndex: 'country', width: 120, render: (value: string) => value || t('common.unknown') }, { title: t('botChallenge.site'), dataIndex: 'siteId', width: 150, render: (value: string) => value || '—' }, { title: t('botChallenge.type'), dataIndex: 'challengeType', width: 140, render: (value: string) => typeLabel(value ?? 'unknown', t) }, { title: t('botChallenge.outcome'), dataIndex: 'outcome', width: 110, render: (value: string) => <OutcomeTag value={value} t={t}/> }, { title: t('botChallenge.reason'), dataIndex: 'reason', ellipsis: true }, { title: t('botChallenge.traceId'), dataIndex: 'traceId', width: 190, render: (value: string, row: BotChallengeEvent) => <button className={styles.trace} onClick={() => navigate(`/logs/${encodeURIComponent(value || row.id)}`)}>{value || row.id}</button> }]}/></div>
      <div className={styles.eventCards}>{loading ? <Skeleton text={{ rows: 3 }} animation/> : eventRows.length === 0 ? <Empty description={t('botChallenge.noEvents')}/> : eventRows.map(({ label, values, event }) => <article key={event.id} className={styles.eventCard}><div className={styles.eventCardHeading}><OutcomeTag value={event.outcome} t={t}/><button className={styles.trace} onClick={() => navigate(`/logs/${encodeURIComponent(label)}`)}>{label}</button></div><dl>{values.map(([term, value]) => <div key={term}><dt>{term}</dt><dd>{value}</dd></div>)}</dl></article>)}</div>
    </>}
  </section>;
}

function EventPanelState({ title, hint, retry, retryLabel }: { title: string; hint: string; retry?: () => void; retryLabel?: string }) { return <div className={styles.eventState} role={retry ? 'alert' : 'status'}><ShieldX/><div><strong>{title}</strong><span>{hint}</span></div>{retry && <Button onClick={retry}>{retryLabel}</Button>}</div>; }
function QuickAction({ icon, title, hint, onClick }: { icon: React.ReactNode; title: string; hint: string; onClick: () => void }) { return <button type={'button'} onClick={onClick}>{icon}<span><strong>{title}</strong><small>{hint}</small></span><ArrowRight/></button>; }
function LoadError({ t, retry }: { t: TFunction; retry: () => void }) { return <div className={styles.error} role={'alert'}><ShieldX size={20}/><div><strong>{t('botChallenge.loadFailed')}</strong><span>{t('botChallenge.loadFailedHint')}</span></div><Button onClick={retry}>{t('common.retry')}</Button></div>; }
function OverviewSkeleton() { return <div className={styles.loading} aria-busy={true}><div className={styles.skeletonMetrics}>{Array.from({ length: 6 }, (_, index) => <Skeleton key={index} text={{ rows: 2, width: ['55%', '35%'] }} animation/>)}</div><Skeleton text={{ rows: 6 }} animation/></div>; }
function OutcomeTag({ value, t }: { value: string; t: TFunction }) { const colors: Record<string, string> = { passed: 'green', failed: 'orange', blocked: 'red', issued: 'blue' }; return <Tag color={colors[value] ?? 'gray'}>{t(`botChallenge.outcomes.${value}`)}</Tag>; }
function formatNumber(value?: number) { return value == null ? '—' : new Intl.NumberFormat().format(value); }
function formatBucketTime(value: string, locale: string, count: number) { return new Date(value).toLocaleString(locale, count > 24 ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' }); }
function typeLabel(type: string, t: TFunction) { return t(`protection.captchaTypes.${type}`, { defaultValue: type === 'unknown' ? t('common.unknown') : type }); }
function eventErrorMessage(error: unknown, t: TFunction) { return error instanceof Error && error.message.trim() ? error.message : t('botChallenge.loadFailedHint'); }
function isHTTPStatus(error: unknown, status: number) { return error instanceof APIRequestError && error.status === status; }
type EventPermission = 'allowed' | 'denied' | 'unknown';
function readLogsPermission(): EventPermission {
  const token = localStorage.getItem('cheesewaf-token') ?? '';
  const payload = token.split('.')[1];
  if (!payload) return 'unknown';
  try {
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='))) as { role?: string; scope?: string | string[]; scopes?: string | string[] };
    if (claims.role === 'admin') return 'allowed';
    const rawScopes = claims.scope ?? claims.scopes;
    const scopes = (Array.isArray(rawScopes) ? rawScopes : typeof rawScopes === 'string' ? rawScopes.split(/\s+/) : []).filter(Boolean);
    const explicitPermissions = scopes.filter((scope) => scope === '*' || scope.includes(':'));
    if (explicitPermissions.length === 0) return 'unknown';
    return explicitPermissions.some((scope) => scope === 'read:logs' || scope === '*' || (scope.endsWith('*') && 'read:logs'.startsWith(scope.slice(0, -1)))) ? 'allowed' : 'denied';
  } catch {
    return 'unknown';
  }
}
function groupTrend(points: BotChallengeMetricPoint[]) { const map = new Map<string, BotChallengeMetricPoint>(); for (const point of points) { const item = map.get(point.time) ?? { time: point.time, type: 'all', issued: 0, successes: 0, failures: 0, blocks: 0 }; item.issued += point.issued; item.successes += point.successes; item.failures += point.failures; item.blocks += point.blocks; map.set(point.time, item); } return [...map.values()].sort((a, b) => a.time.localeCompare(b.time)); }
function aggregateEffects(points: BotChallengeMetricPoint[]): BotChallengeTypeEffect[] { const map = new Map<string, BotChallengeTypeEffect>(); for (const point of points) { const item = map.get(point.type) ?? { type: point.type, issued: 0, passed: 0, failed: 0 }; item.issued += point.issued; item.passed = (item.passed ?? 0) + point.successes; item.failed = (item.failed ?? 0) + point.failures + point.blocks; map.set(point.type, item); } return [...map.values()].map((item) => { const decided = (item.passed ?? 0) + (item.failed ?? 0); return { ...item, passRate: decided ? (item.passed ?? 0) / decided : undefined }; }).sort((a, b) => b.issued - a.issued); }
