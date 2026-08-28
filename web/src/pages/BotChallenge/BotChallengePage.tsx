import {
  Badge,
  Button,
  Empty,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
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
  const [eventPage, setEventPage] = useState(0);
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
        <Select value={range} onValueChange={(value) => { setRange(value as BotChallengeRange); setEventPage(0); }}>
          <SelectTrigger className={styles.rangeSelect} aria-label={t('botChallenge.period')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(['1h', '6h', '24h', '7d', '30d'] as BotChallengeRange[]).map((value) => (
              <SelectItem key={value} value={value}>{t(`botChallenge.ranges.${value}`)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button aria-label={t('common.refresh')} variant="outline" loading={refreshing} onClick={refreshAll}>
          <RefreshCw className={refreshing ? styles.spinning : undefined} size={16}/>
          {t('common.refresh')}
        </Button>
      </div>
    </header>

    <div className={styles.pageTabs} role="tablist" aria-label={t('botChallenge.title')}>
      <button type="button" role="tab" id="bot-challenge-tab-overview" aria-controls="bot-challenge-panel-overview" aria-selected={pageTab === 'overview'} tabIndex={pageTab === 'overview' ? 0 : -1} className={pageTab === 'overview' ? styles.activeTab : undefined} onClick={() => setPageTab('overview')}><Activity size={17}/>{t('botChallenge.overviewTab')}</button>
      <button type="button" role="tab" id="bot-challenge-tab-assets" aria-controls="bot-challenge-panel-assets" aria-selected={pageTab === 'assets'} tabIndex={pageTab === 'assets' ? 0 : -1} className={pageTab === 'assets' ? styles.activeTab : undefined} onClick={() => setPageTab('assets')}><Image size={17}/>{t('botChallenge.assetsTab')}</button>
    </div>
    {pageTab === 'assets' ? <div id="bot-challenge-panel-assets" role="tabpanel" aria-labelledby="bot-challenge-tab-assets"><CaptchaAssetsPanel/></div> : loading ? <OverviewSkeleton /> : failed ? <LoadError t={t} retry={refreshAll}/> : <div id="bot-challenge-panel-overview" role="tabpanel" aria-labelledby="bot-challenge-tab-overview">
      <MetricGrid metrics={metrics} t={t} locale={locale}/>
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
      <EventTable events={events} loading={eventsQuery.isLoading} forbidden={eventsForbidden} error={eventsError} retry={() => void eventsQuery.refetch()} locale={locale} navigate={navigate} t={t} page={eventPage} setPage={setEventPage}/>
    </div>}
  </section>;
}

function MetricGrid({ metrics, t, locale }: { metrics?: BotChallengeMetrics; t: TFunction; locale: string }) {
  const totals = metrics?.totals;
  const hasOutcomes = (totals?.successes ?? 0) + (totals?.failures ?? 0) > 0;
  const items = [
    { icon: <Users/>, label: t('botChallenge.challengedClients'), value: formatNumber(totals?.challenged_people, locale), tone: 'brand' },
    { icon: <Bot/>, label: t('botChallenge.challengeCount'), value: formatNumber(totals?.challenges, locale), tone: 'brand' },
    { icon: <ShieldX/>, label: t('botChallenge.blockedClients'), value: formatNumber(totals?.blocked_people, locale), tone: 'danger' },
    { icon: <ShieldAlert/>, label: t('botChallenge.blockCount'), value: formatNumber(totals?.blocks, locale), tone: 'danger' },
    { icon: <Activity/>, label: t('botChallenge.captchaBlocked'), value: formatNumber(totals?.captcha_blocks, locale), tone: 'warning' },
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

function EventTable({ events, loading, forbidden, error, retry, locale, navigate, t, page, setPage }: { events: BotChallengeEvent[]; loading: boolean; forbidden: boolean; error?: unknown; retry: () => void; locale: string; navigate: (path: string) => void; t: TFunction; page: number; setPage: (page: number) => void }) {
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(events.length / pageSize));
  const paged = events.slice(page * pageSize, (page + 1) * pageSize);
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
      title={t('botChallenge.eventsForbidden')}
      hint={t('botChallenge.eventsPermissionHint')}
    /> : error ? <EventPanelState title={t('botChallenge.loadFailed')} hint={eventErrorMessage(error, t)} retry={retry} retryLabel={t('common.retry')}/> : <>
      <div className={styles.eventTable}>
        {loading ? <div className="p-4"><Skeleton className="h-24 w-full" /></div> : events.length === 0 ? <Empty description={t('botChallenge.noEvents')}/> : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('botChallenge.time')}</TableHead>
                  <TableHead>{t('botChallenge.clientIp')}</TableHead>
                  <TableHead>{t('botChallenge.location')}</TableHead>
                  <TableHead>{t('botChallenge.site')}</TableHead>
                  <TableHead>{t('botChallenge.type')}</TableHead>
                  <TableHead>{t('botChallenge.outcome')}</TableHead>
                  <TableHead>{t('botChallenge.reason')}</TableHead>
                  <TableHead>{t('botChallenge.traceId')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paged.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>{new Date(row.timestamp).toLocaleString(locale)}</TableCell>
                    <TableCell>{row.clientIp}</TableCell>
                    <TableCell>{row.country || t('common.unknown')}</TableCell>
                    <TableCell>{row.siteId || '—'}</TableCell>
                    <TableCell>{typeLabel(row.challengeType ?? 'unknown', t)}</TableCell>
                    <TableCell><OutcomeTag value={row.outcome} t={t}/></TableCell>
                    <TableCell className="max-w-[200px] truncate">{row.reason}</TableCell>
                    <TableCell>
                      <button className={styles.trace} onClick={() => navigate(`/logs/${encodeURIComponent(row.traceId || row.id)}`)}>{row.traceId || row.id}</button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {events.length > pageSize && (
              <div className="flex items-center justify-end gap-2 p-2">
                <Button size="sm" variant="outline" disabled={page <= 0} onClick={() => setPage(page - 1)}>{t('common.prev')}</Button>
                <span className="text-sm text-muted-foreground">{page + 1}/{pageCount}</span>
                <Button size="sm" variant="outline" disabled={page >= pageCount - 1} onClick={() => setPage(page + 1)}>{t('common.next')}</Button>
              </div>
            )}
          </>
        )}
      </div>
      <div className={styles.eventCards}>{loading ? <Skeleton className="h-24 w-full" /> : eventRows.length === 0 ? <Empty description={t('botChallenge.noEvents')}/> : eventRows.map(({ label, values, event }) => <article key={event.id} className={styles.eventCard}><div className={styles.eventCardHeading}><OutcomeTag value={event.outcome} t={t}/><button className={styles.trace} onClick={() => navigate(`/logs/${encodeURIComponent(label)}`)}>{label}</button></div><dl>{values.map(([term, value]) => <div key={term}><dt>{term}</dt><dd>{value}</dd></div>)}</dl></article>)}</div>
    </>}
  </section>;
}

function EventPanelState({ title, hint, retry, retryLabel }: { title: string; hint: string; retry?: () => void; retryLabel?: string }) { return <div className={styles.eventState} role={retry ? 'alert' : 'status'}><ShieldX/><div><strong>{title}</strong><span>{hint}</span></div>{retry && <Button variant="outline" onClick={retry}>{retryLabel}</Button>}</div>; }
function QuickAction({ icon, title, hint, onClick }: { icon: React.ReactNode; title: string; hint: string; onClick: () => void }) { return <button type={'button'} onClick={onClick}>{icon}<span><strong>{title}</strong><small>{hint}</small></span><ArrowRight/></button>; }
function LoadError({ t, retry }: { t: TFunction; retry: () => void }) { return <div className={styles.error} role={'alert'}><ShieldX size={20}/><div><strong>{t('botChallenge.loadFailed')}</strong><span>{t('botChallenge.loadFailedHint')}</span></div><Button variant="outline" onClick={retry}>{t('common.retry')}</Button></div>; }
function OverviewSkeleton() {
  return (
    <div className={styles.loading} aria-busy={true}>
      <div className={styles.skeletonMetrics}>{Array.from({ length: 6 }, (_, index) => <Skeleton key={index} className="h-20 w-full" />)}</div>
      <Skeleton className="h-40 w-full" />
    </div>
  );
}
function OutcomeTag({ value, t }: { value: string; t: TFunction }) {
  const variants: Record<string, 'success' | 'warning' | 'destructive' | 'default' | 'secondary'> = {
    passed: 'success',
    failed: 'warning',
    blocked: 'destructive',
    issued: 'default',
  };
  return <Badge variant={variants[value] ?? 'secondary'}>{t(`botChallenge.outcomes.${value}`)}</Badge>;
}
function formatNumber(value?: number, locale?: string) { return value == null ? '—' : new Intl.NumberFormat(locale).format(value); }
function formatBucketTime(value: string, locale: string, count: number) { return new Date(value).toLocaleString(locale, count > 24 ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' }); }
function typeLabel(type: string, t: TFunction) { return type === 'unknown' ? t('common.unknown') : t(`protection.captchaTypes.${type}`); }
function eventErrorMessage(error: unknown, t: TFunction) { return error instanceof Error && error.message.trim() ? error.message : t('botChallenge.loadFailedHint'); }
function isHTTPStatus(error: unknown, status: number) { return error instanceof APIRequestError && error.status === status; }
type EventPermission = 'allowed' | 'denied' | 'unknown';
function readLogsPermission(): EventPermission {
  // UI-only hint; the API still enforces read:logs. Use session profile, not stored tokens.
  try {
    const cached = sessionStorage.getItem('cheesewaf-account');
    if (cached) {
      const account = JSON.parse(cached) as { role?: string };
      if (account.role === 'admin' || account.role === 'operator') return 'allowed';
      if (account.role === 'readonly') return 'allowed';
      if (account.role) return 'denied';
    }
  } catch {
    /* ignore */
  }
  return 'unknown';
}
function groupTrend(points: BotChallengeMetricPoint[]) { const map = new Map<string, BotChallengeMetricPoint>(); for (const point of points) { const item = map.get(point.time) ?? { time: point.time, type: 'all', issued: 0, successes: 0, failures: 0, blocks: 0 }; item.issued += point.issued; item.successes += point.successes; item.failures += point.failures; item.blocks += point.blocks; map.set(point.time, item); } return [...map.values()].sort((a, b) => a.time.localeCompare(b.time)); }
function aggregateEffects(points: BotChallengeMetricPoint[]): BotChallengeTypeEffect[] { const map = new Map<string, BotChallengeTypeEffect>(); for (const point of points) { const item = map.get(point.type) ?? { type: point.type, issued: 0, passed: 0, failed: 0 }; item.issued += point.issued; item.passed = (item.passed ?? 0) + point.successes; item.failed = (item.failed ?? 0) + point.failures + point.blocks; map.set(point.type, item); } return [...map.values()].map((item) => { const decided = (item.passed ?? 0) + (item.failed ?? 0); return { ...item, passRate: decided ? (item.passed ?? 0) / decided : undefined }; }).sort((a, b) => b.issued - a.issued); }
