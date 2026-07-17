import { Button, DatePicker, Message as ArcoMessage, Progress, Select, Spin, Tag, Tooltip } from '@arco-design/web-react';
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Activity, ChevronRight, Cpu, HardDrive, Maximize2, MemoryStick, Recycle, RotateCcw, Server, ShieldCheck, Zap } from 'lucide-react';
import { fetchLogs, fetchMonitorSummary, fetchSites, reclaimSystemResources } from '../../api/client';
import type { LogEntry, LogQuery } from '../../types/api';
import { displayAction, displayCategory, formatLogLocation } from '../../utils/display';

const threatColors = ['var(--accent-danger)', 'var(--accent-warning)', 'var(--accent-purple)', 'var(--accent-info)'];
const realtimeWindowSeconds = 60;
const totalsRefreshMs = 10_000;
const refreshOptions = [1000, 3000, 5000, 10000];
const customStatsRangeValue = -1;
const dateTimePickerFormat = 'YYYY-MM-DD HH:mm';
/** Wheel-zoom floor: never show a thinner slice than this fraction of the period. */
const CHART_MIN_WINDOW_RATIO = 0.25;
/**
 * Minimum horizontal scale per bucket (px). Time labels like "08:42" need ~40px+;
 * below this they ellipsis into "0....".
 */
const CHART_MIN_BAR_WIDTH_PX = 48;
const statsRangeOptions = [
  { value: 30, labelKey: 'dashboard.last30m' },
  { value: 60, labelKey: 'dashboard.last60m' },
  { value: 360, labelKey: 'dashboard.last6h' },
  { value: 1440, labelKey: 'dashboard.last24h' },
  { value: 10080, labelKey: 'dashboard.last7d' },
  { value: customStatsRangeValue, labelKey: 'dashboard.customRange' },
];
const defaultCustomRange = () => {
  const end = new Date();
  const start = new Date(end.getTime() - 6 * 60 * 60 * 1000);
  return [start.toISOString(), end.toISOString()] as [string, string];
};
const DateRangePicker = DatePicker.RangePicker;

export default function DashboardPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [statsRange, setStatsRange] = useState(60);
  const [refreshMs, setRefreshMs] = useState(3000);
  const [customRange, setCustomRange] = useState<[string, string]>(() => defaultCustomRange());
  /** 1 = full period; lower = wheel-zoom into the latest segment. */
  const [chartWindowRatio, setChartWindowRatio] = useState(1);
  const totalsChartRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = totalsChartRef.current;
    if (!el) {
      return undefined;
    }
    function onWheel(event: globalThis.WheelEvent) {
      // Keep vertical wheel as chart zoom (original behavior); horizontal trackpad pan still scrolls.
      if (Math.abs(event.deltaY) < Math.abs(event.deltaX)) {
        return;
      }
      event.preventDefault();
      setChartWindowRatio((value) =>
        Math.max(CHART_MIN_WINDOW_RATIO, Math.min(1, Number((value + (event.deltaY > 0 ? 0.1 : -0.1)).toFixed(2)))),
      );
    }
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  const { data: monitor, isLoading: loadingMonitor, isFetching: fetchingMonitor, refetch: refetchMonitor } = useQuery({
    queryKey: ['monitor-summary'],
    queryFn: fetchMonitorSummary,
    refetchInterval: refreshMs,
    retry: false,
    staleTime: Math.max(1000, Math.floor(refreshMs * 0.8)),
  });
  const { data: periodLogs, isLoading: loadingPeriod, refetch: refetchPeriodLogs } = useQuery({
    queryKey: ['dashboard-period-logs', statsRange, customRange],
    queryFn: () => fetchLogs(buildStatsQuery(statsRange, customRange, statsRange === customStatsRangeValue ? 2500 : 1500)),
    refetchInterval: totalsRefreshMs,
    retry: false,
    staleTime: 20_000,
  });
  const { data: liveLogs, isLoading: loadingLive, isFetching: fetchingLive, refetch: refetchLiveLogs } = useQuery({
    queryKey: ['dashboard-live-logs'],
    queryFn: () => fetchLogs(buildWindowQuery(realtimeWindowSeconds, 180)),
    refetchInterval: refreshMs,
    retry: false,
    staleTime: Math.max(1000, Math.floor(refreshMs * 0.8)),
  });
  const { data: sites, refetch: refetchSites } = useQuery({
    queryKey: ['sites'],
    queryFn: fetchSites,
    refetchInterval: 60_000,
    retry: false,
    staleTime: 60_000,
  });
  const reclaimMutation = useMutation({
    mutationFn: reclaimSystemResources,
    onSuccess: (result) => {
      const actions = Array.isArray(result.actions) ? result.actions : [];
      const message = `${t('dashboard.reclaimResult')}: ${actions.filter((item) => item.ok).length}/${actions.length}`;
      if (result.ok) {
        ArcoMessage.success(message);
      } else {
        ArcoMessage.warning(message);
      }
      queryClient.invalidateQueries({ queryKey: ['monitor-summary'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const snapshot = monitor?.snapshot;
  const entries = Array.isArray(periodLogs?.items) ? periodLogs.items : [];
  const liveEntries = Array.isArray(liveLogs?.items) ? liveLogs.items : [];
  const siteItems = Array.isArray(sites) ? sites : [];
  const hasSiteItems = Array.isArray(sites);
  const statsWindow = useMemo(() => statsWindowFromState(statsRange, customRange), [customRange, statsRange]);
  const customRangePickerValue = useMemo(() => customRange.map(formatDateTimePickerValue) as [string, string], [customRange]);
  const traffic = useMemo(() => buildTraffic(entries, statsWindow.start, statsWindow.end), [entries, statsWindow.end, statsWindow.start]);
  const visibleTraffic = useMemo(() => sliceVisibleTraffic(traffic, chartWindowRatio), [chartWindowRatio, traffic]);
  const securityEntries = useMemo(() => entries.filter(isSecurityEvent), [entries]);
  const visibleSecurityEntries = useMemo(() => securityEntries.slice(0, 6), [securityEntries]);
  const liveSeries = useMemo(() => buildRealtimeSeries(liveEntries, realtimeWindowSeconds), [liveEntries]);
  const threats = useMemo(() => buildThreatMix(entries, t), [entries, t]);
  const averageLatency = useMemo(() => averageRequestLatency(entries), [entries]);
  const periodRequests = traffic.reduce((sum, point) => sum + point.count, 0);
  const periodBlockedCount = entries.filter((entry) => entry.action === 'block').length;
  const liveRequests = liveEntries.length;
  const liveBlockedCount = liveEntries.filter((entry) => entry.action === 'block').length;
  const siteCount = hasSiteItems ? siteItems.length : snapshot?.sites ?? 0;
  const enabledSiteCount = siteItems.filter((site) => site.enabled !== false).length;
  const siteDelta = hasSiteItems
    ? t('dashboard.sitesEnabled', { enabled: enabledSiteCount, total: siteItems.length })
    : snapshot
      ? t('dashboard.sitesFromRuntime')
      : t('dashboard.sitesLoading');
  const host = snapshot?.host;
  const cpuPercent = clampPercent(host?.cpu_percent ?? 0);
  const memoryHostPercent = clampPercent(host?.memory_percent ?? 0);
  const diskPercent = clampPercent(host?.disk_percent ?? 0);
  const swapPercent = clampPercent(host?.swap_percent ?? 0);
  const cpuCount = host?.cpu_count ?? 0;
  const load1 = host?.load1 ?? 0;
  const loadPercent = clampPercent(cpuCount > 0 ? (load1 / cpuCount) * 100 : load1 * 25);
  const loading = (loadingMonitor && !monitor) || (loadingPeriod && !periodLogs);
  const refreshingLiveResources = fetchingMonitor || fetchingLive;
  const maxTraffic = Math.max(...visibleTraffic.map((point) => point.count), 1);
  const yMax = niceAxisMax(maxTraffic);
  const yMid = formatNumber(Math.round(yMax / 2));
  // Enforce min scale so 24h/7d axis labels (e.g. 08:42) stay readable and scroll instead of crushing.
  const chartMinWidthPx = Math.max(visibleTraffic.length * CHART_MIN_BAR_WIDTH_PX, 0);
  const monitorState = snapshot
    ? { color: 'green', label: t('common.online') }
    : { color: loadingMonitor ? 'blue' : 'orange', label: loadingMonitor ? t('common.loading') : t('shell.connectionReconnecting') };
  const manualRefresh = () => {
    void refetchMonitor();
    void refetchLiveLogs();
    void refetchPeriodLogs();
    void refetchSites();
  };
  const handleStatsRangeChange = (value: number) => {
    setStatsRange(value);
    setChartWindowRatio(1);
    if (value === customStatsRangeValue && !validCustomRange(customRange)) {
      setCustomRange(defaultCustomRange());
    }
  };
  const handleCustomRangeChange = (dateString: string[], date: unknown[]) => {
    const next = normalizeDateRange(dateString) ?? normalizeDateRange(date);
    if (next) {
      setCustomRange(next);
      setChartWindowRatio(1);
    }
  };

  return (
    <section className="page-surface dashboard-page">
      <header className="page-header">
        <div>
          <h1>{t('dashboard.title')}</h1>
          <p>{t('dashboard.subtitle')}</p>
        </div>
        <Tag color={monitorState.color} icon={<ShieldCheck size={14} />}>
          {monitorState.label}
        </Tag>
      </header>

      <div className="metric-grid">
        {[
          { label: t('dashboard.totalRequests'), value: formatNumber(periodRequests), delta: rangeLabel(statsRange, customRange, t), icon: Zap },
          { label: t('dashboard.totalBlocked'), value: formatNumber(periodBlockedCount), delta: `${blockRate(periodBlockedCount, periodRequests)}%`, icon: ShieldCheck },
          { label: t('dashboard.responseSpeed'), value: formatLatency(averageLatency), delta: t('dashboard.responseSpeedHint'), icon: Activity },
          { label: t('dashboard.sites'), value: formatNumber(siteCount), delta: siteDelta, icon: HardDrive },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <article className="metric-card" key={item.label}>
              <Icon size={20} />
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <em>{item.delta}</em>
            </article>
          );
        })}
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-main-stack">
          <section className="panel panel-wide dashboard-traffic-panel">
            <div className="panel-heading dashboard-chart-heading">
              <div className="dashboard-chart-copy">
                <h2>{t('dashboard.totals')}</h2>
                <p>{t('dashboard.totalsHint')}</p>
              </div>
              <div
                className={statsRange === customStatsRangeValue ? 'dashboard-chart-toolbar dashboard-chart-toolbar-custom' : 'dashboard-chart-toolbar'}
                aria-label={t('dashboard.totals')}
              >
                <div className="dashboard-chart-control">
                  <span className="dashboard-chart-control-label">{t('dashboard.statsWindow')}</span>
                  <Select className="dashboard-footer-select" value={statsRange} onChange={(value) => handleStatsRangeChange(Number(value))}>
                    {statsRangeOptions.map((option) => <Select.Option key={option.value} value={option.value}>{t(option.labelKey)}</Select.Option>)}
                  </Select>
                </div>
                {statsRange === customStatsRangeValue && (
                  <div className="dashboard-chart-control dashboard-chart-custom-range">
                    <span className="dashboard-chart-control-label">{t('dashboard.customTimeRange')}</span>
                    <DateRangePicker
                      className="dashboard-date-range"
                      showTime
                      value={customRangePickerValue}
                      onChange={handleCustomRangeChange}
                      allowClear={false}
                      format={dateTimePickerFormat}
                    />
                  </div>
                )}
                <div className="dashboard-chart-control dashboard-chart-refresh-control">
                  <span className="dashboard-chart-control-label">{t('dashboard.autoRefresh')}</span>
                  <Select className="dashboard-footer-select dashboard-refresh-select" value={refreshMs} onChange={(value) => setRefreshMs(Number(value))}>
                    {refreshOptions.map((value) => <Select.Option key={value} value={value}>{value / 1000}s</Select.Option>)}
                  </Select>
                </div>
                <div className="dashboard-chart-actions">
                  <Tooltip content={t('dashboard.manualRefresh')}>
                    <Button
                      className={refreshingLiveResources ? 'icon-button refresh-button refresh-button-active' : 'icon-button refresh-button'}
                      icon={<RotateCcw size={15} />}
                      onClick={manualRefresh}
                    />
                  </Tooltip>
                  <Tooltip content={t('dashboard.resetChartView')}>
                    <Button
                      className="icon-button"
                      icon={<Maximize2 size={15} />}
                      onClick={() => setChartWindowRatio(1)}
                    />
                  </Tooltip>
                </div>
              </div>
            </div>
            <Spin loading={loading}>
              <div ref={totalsChartRef} className="traffic-chart" aria-label={t('dashboard.totals')}>
                <div className="chart-y-axis" aria-hidden="true">
                  <span>{yMax}</span>
                  <span>{yMid}</span>
                  <span>0</span>
                </div>
                <div className="chart-scroll" tabIndex={0} aria-label={t('dashboard.chartScrollAria')}>
                  <div
                    className="chart-scroll-body"
                    style={{
                      '--bar-count': Math.max(visibleTraffic.length, 1),
                      minWidth: chartMinWidthPx > 0 ? `${chartMinWidthPx}px` : undefined,
                    } as CSSProperties}
                  >
                    <div className="chart-plot">
                      {visibleTraffic.map((point, index) => (
                        <span
                          key={`${point.label}-${index}`}
                          className="chart-bar"
                          style={{ height: `${Math.max((point.count / yMax) * 100, point.count > 0 ? 5 : 2)}%` }}
                          title={`${formatNumber(point.count)} · ${point.label}`}
                          aria-hidden="true"
                        >
                          <i />
                        </span>
                      ))}
                    </div>
                    <div className="chart-x-axis chart-x-axis-scroll" aria-hidden="true">
                      {visibleTraffic.map((point, index) => {
                        const show = shouldShowChartTick(index, visibleTraffic.length);
                        return (
                          <span key={`tick-${point.label}-${index}`} className={show ? 'chart-x-tick' : 'chart-x-tick chart-x-tick-hidden'}>
                            {show ? point.label : ''}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            </Spin>
            <div className="dashboard-chart-footer">
              <div className="chart-legend" aria-label={t('dashboard.trafficRequests')}>
                <span><i /> {t('dashboard.trafficRequests')}</span>
              </div>
            </div>
          </section>

          <section className="panel panel-wide dashboard-events-panel">
            <div className="panel-heading dashboard-events-heading">
              <h2>{t('dashboard.events')}</h2>
              <Link
                className="dashboard-events-more"
                to="/logs"
                aria-label={t('dashboard.eventsOpenLogs')}
                title={t('dashboard.eventsOpenLogs')}
              >
                <ChevronRight size={16} strokeWidth={2.25} aria-hidden="true" />
              </Link>
            </div>
            <div className="event-list-scroll" tabIndex={0} aria-label={t('dashboard.eventScrollAria')}>
              <div className="event-list event-list-table" role="table" aria-label={t('dashboard.events')}>
                <div className="event-row event-row-head" role="row">
                  <span className="event-col-time">{t('dashboard.eventTime')}</span>
                  <span className="event-col-id">{t('dashboard.eventId')}</span>
                  <span className="event-col-ip">{t('dashboard.sourceIp')}</span>
                  <span className="event-col-geo">{t('dashboard.ipLocation')}</span>
                  <span className="event-col-type">{t('dashboard.attackType')}</span>
                  <span className="event-col-action">{t('dashboard.action')}</span>
                </div>
                {visibleSecurityEntries.length === 0 && <div className="empty-state">{t('dashboard.noSecurityEvents')}</div>}
                {visibleSecurityEntries.map((event) => {
                  const eventKey = event.id || event.trace_id || `${event.client_ip}-${event.timestamp}`;
                  return (
                    <div className="event-row" key={eventKey} role="row">
                      <span className="event-time event-col-time" data-label={t('dashboard.eventTime')} title={event.timestamp}>{formatEventTime(event.timestamp)}</span>
                      <Link
                        className="event-trace-link event-col-id"
                        data-label={t('dashboard.eventId')}
                        to={`/logs/${encodeURIComponent(event.trace_id || event.id || '-')}`}
                        title={event.trace_id || event.id || '-'}
                      >
                        <code className="event-trace">{event.trace_id || event.id || '-'}</code>
                      </Link>
                      <span className="event-source event-col-ip" data-label={t('dashboard.sourceIp')} title={event.client_ip || '-'}>
                        {event.client_ip || '-'}
                      </span>
                      <span className="event-country event-col-geo" data-label={t('dashboard.ipLocation')} title={eventLocationLabel(event, t)}>
                        {eventLocationLabel(event, t)}
                      </span>
                      <span className="event-status-group event-col-type" data-label={t('dashboard.attackType')}>
                        <Tag color={event.category ? 'orange' : event.action === 'pass' || !event.action ? 'green' : 'blue'}>{eventCategoryLabel(event, t)}</Tag>
                      </span>
                      <span className="event-status-group event-col-action" data-label={t('dashboard.action')}>
                        <Tag color={event.action === 'block' ? 'red' : 'blue'}>
                          {displayAction(event.action, t)}
                        </Tag>
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        </div>

        <div className="dashboard-side-stack">
          <section className="panel realtime-panel">
            <div className="panel-heading">
              <h2>{t('dashboard.realtime')}</h2>
              <Tooltip content={t('dashboard.manualRefresh')}>
                <Button
                  className={fetchingLive ? 'icon-button refresh-button refresh-button-active' : 'icon-button refresh-button'}
                  icon={<RotateCcw size={14} />}
                  onClick={() => void refetchLiveLogs()}
                />
              </Tooltip>
            </div>
            <Spin loading={loadingLive && !liveLogs}>
              <div className="realtime-summary">
                <div>
                  <span>{t('dashboard.liveRequests')}</span>
                  <strong>{formatNumber(liveRequests)}</strong>
                </div>
                <div>
                  <span>{t('dashboard.liveBlocked')}</span>
                  <strong>{formatNumber(liveBlockedCount)}</strong>
                </div>
                <div>
                  <span>{t('dashboard.liveRate')}</span>
                  <strong>{formatRate(liveRequests / realtimeWindowSeconds)}</strong>
                </div>
              </div>
              <RealtimeLineChart points={liveSeries} />
              <span className="realtime-window">{t('dashboard.last60s')}</span>
            </Spin>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <h2>{t('dashboard.resources')}</h2>
              <Tooltip content={t('dashboard.manualRefresh')}>
                <Button
                  className={fetchingMonitor ? 'icon-button refresh-button refresh-button-active' : 'icon-button refresh-button'}
                  icon={<RotateCcw size={14} />}
                  onClick={() => void refetchMonitor()}
                />
              </Tooltip>
            </div>
            <div className="resource-stack">
              <div className="resource-row">
                <Cpu size={18} />
                <span>{t('dashboard.cpu')}</span>
                <Progress percent={cpuPercent} size="small" showText={false} />
                <strong>{formatPercent(host?.cpu_percent ?? 0)}</strong>
                <small>{cpuCount > 0 ? t('dashboard.cpuHint', { cores: cpuCount }) : t('common.unknown')}</small>
              </div>
              <div className="resource-row">
                <Activity size={18} />
                <span>{t('dashboard.systemLoad')}</span>
                <Progress percent={loadPercent} size="small" showText={false} />
                <strong>{formatLoad(load1)}</strong>
                <small>{cpuCount > 0 ? t('dashboard.loadHint', { cores: cpuCount }) : t('dashboard.loadHintNoCores')}</small>
              </div>
              <div className="resource-row">
                <MemoryStick size={18} />
                <span>{t('dashboard.memory')}</span>
                <Progress percent={memoryHostPercent} size="small" showText={false} />
                <strong>{formatPercent(host?.memory_percent ?? 0)}</strong>
                <small>{formatCapacity(host?.memory_used ?? 0, host?.memory_total ?? 0, t)}</small>
              </div>
              <div className="resource-row">
                <Recycle size={18} />
                <span>{t('dashboard.swap')}</span>
                <Progress percent={swapPercent} size="small" showText={false} />
                <strong>{formatPercent(host?.swap_percent ?? 0)}</strong>
                <small>{formatCapacity(host?.swap_used ?? 0, host?.swap_total ?? 0, t, 'dashboard.swapNotEnabled')}</small>
              </div>
              <div className="resource-row">
                <HardDrive size={18} />
                <span>{t('dashboard.disk')}</span>
                <Progress percent={diskPercent} size="small" showText={false} />
                <strong>{formatPercent(host?.disk_percent ?? 0)}</strong>
                <small>{formatCapacity(host?.disk_used ?? 0, host?.disk_total ?? 0, t)}</small>
              </div>
              <div className="resource-row" aria-label={t('dashboard.processRuntime')}>
                <Server size={18} />
                <span>{t('dashboard.runtimeServiceProcesses')}</span>
                <span className="resource-row-track" aria-hidden="true" />
                <strong>{formatNumber(snapshot?.process_count ?? (snapshot ? 1 : 0))}</strong>
              </div>
              <div className="resource-row">
                <Zap size={18} />
                <span>{t('dashboard.runtimeServiceMemory')}</span>
                <span className="resource-row-track" aria-hidden="true" />
                <strong>{formatBytes(snapshot?.memory_alloc ?? 0)}</strong>
              </div>
            </div>
            <div className="resource-actions">
              <Button icon={<Recycle size={14} />} loading={reclaimMutation.isPending} onClick={() => reclaimMutation.mutate('memory')}>
                {t('dashboard.reclaimMemory')}
              </Button>
              <Button icon={<Recycle size={14} />} loading={reclaimMutation.isPending} onClick={() => reclaimMutation.mutate('swap')}>
                {t('dashboard.reclaimSwap')}
              </Button>
            </div>
          </section>

          <section className="panel">
            <div className="panel-heading">
              <h2>{t('dashboard.threatMix')}</h2>
            </div>
            <div className="threat-list">
              {threats.length === 0 && <div className="empty-state">{t('monitor.requests')}: 0</div>}
              {threats.map((threat, index) => (
                <div className="threat-row" key={threat.name}>
                  <span>{threat.name}</span>
                  <Progress
                    percent={threat.value}
                    showText={false}
                    color={threatColors[index % threatColors.length]}
                    size="small"
                  />
                  <strong>{threat.value}%</strong>
                </div>
              ))}
            </div>
          </section>
        </div>

      </div>
    </section>
  );
}

function buildWindowQuery(windowSeconds: number, limit: number, action?: string): LogQuery {
  const end = new Date();
  const start = new Date(end.getTime() - windowSeconds * 1000);
  return {
    limit,
    action,
    start: start.toISOString(),
    end: end.toISOString(),
  };
}

function buildStatsQuery(rangeMinutes: number, customRange: [string, string], limit: number): LogQuery {
  if (rangeMinutes === customStatsRangeValue && validCustomRange(customRange)) {
    return {
      limit,
      start: customRange[0],
      end: customRange[1],
    };
  }
  return buildWindowQuery(rangeMinutes * 60, limit);
}

function statsWindowFromState(rangeMinutes: number, customRange: [string, string]) {
  if (rangeMinutes === customStatsRangeValue && validCustomRange(customRange)) {
    return { start: new Date(customRange[0]), end: new Date(customRange[1]) };
  }
  const end = new Date();
  const start = new Date(end.getTime() - rangeMinutes * 60 * 1000);
  return { start, end };
}

function buildTraffic(entries: LogEntry[], start: Date, end: Date) {
  const startTime = start.getTime();
  const endTime = end.getTime();
  const windowMs = Math.max(60_000, endTime - startTime);
  const rangeMinutes = windowMs / 60_000;
  const bucketCount = rangeMinutes <= 60 ? 12 : rangeMinutes <= 1440 ? 24 : Math.min(96, Math.max(28, Math.ceil(rangeMinutes / 360)));
  const buckets = Array.from({ length: bucketCount }, () => 0);
  const bucketMs = windowMs / buckets.length;
  for (const entry of entries) {
    const time = Date.parse(entry.timestamp);
    if (!Number.isFinite(time) || time < startTime || time > endTime + 60_000) {
      continue;
    }
    const index = Math.min(buckets.length - 1, Math.max(0, Math.floor((time - startTime) / bucketMs)));
    buckets[index] += 1;
  }
  return buckets.map((count, index) => {
    const at = new Date(startTime + bucketMs * index);
    return {
      count,
      label: rangeMinutes > 1440
        ? at.toLocaleDateString(undefined, { month: '2-digit', day: '2-digit' })
        : at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
    };
  });
}

function sliceVisibleTraffic(points: Array<{ count: number; label: string }>, ratio: number) {
  if (points.length <= 2 || ratio >= 0.99) {
    return points;
  }
  const size = Math.max(2, Math.ceil(points.length * ratio));
  return points.slice(Math.max(0, points.length - size));
}

function shouldShowChartTick(index: number, total: number) {
  if (total <= 8) {
    return true;
  }
  if (index === 0 || index === total - 1) {
    return true;
  }
  const step = Math.max(1, Math.ceil(total / 8));
  return index % step === 0;
}

function niceAxisMax(value: number) {
  const target = Math.max(1, Math.ceil(value));
  if (target <= 4) {
    return target;
  }
  const magnitude = 10 ** Math.floor(Math.log10(target));
  const normalized = target / magnitude;
  const nice = normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return nice * magnitude;
}

function buildRealtimeSeries(entries: LogEntry[], windowSeconds: number) {
  const bucketCount = 30;
  const buckets = Array.from({ length: bucketCount }, () => 0);
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const bucketMs = windowMs / bucketCount;
  for (const entry of entries) {
    const time = Date.parse(entry.timestamp);
    if (!Number.isFinite(time) || time < now - windowMs || time > now + 1000) {
      continue;
    }
    const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((time - (now - windowMs)) / bucketMs)));
    buckets[index] += 1;
  }
  return buckets.map((count, index) => ({
    count,
    label: `${Math.round(windowSeconds - (index * windowSeconds) / bucketCount)}s`,
  }));
}

function RealtimeLineChart({ points }: { points: Array<{ count: number; label: string }> }) {
  const max = Math.max(...points.map((point) => point.count), 1);
  const path = points.map((point, index) => {
    const x = points.length <= 1 ? 0 : (index / (points.length - 1)) * 100;
    const y = 54 - (point.count / max) * 46;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(2)} ${y.toFixed(2)}`;
  }).join(' ');
  return (
    <svg className="realtime-line" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
      <path className="realtime-line-area" d={`${path} L 100 58 L 0 58 Z`} />
      <path className="realtime-line-path" d={path} />
    </svg>
  );
}

function buildThreatMix(entries: LogEntry[], t: (key: string, options?: Record<string, unknown>) => string) {
  const counts = new Map<string, number>();
  for (const entry of entries) {
    if (!entry.category) {
      continue;
    }
    const category = displayCategory(entry.category, t);
    counts.set(category, (counts.get(category) ?? 0) + 1);
  }
  const total = Array.from(counts.values()).reduce((sum, value) => sum + value, 0);
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4)
    .map(([name, count]) => ({ name, value: total > 0 ? Math.round((count / total) * 100) : 0 }));
}

function averageRequestLatency(entries: LogEntry[]) {
  const values = entries.map((entry) => Number(entry.latency)).filter((value) => Number.isFinite(value) && value > 0);
  if (values.length === 0) {
    return 0;
  }
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function formatLatency(nanoseconds: number) {
  if (nanoseconds <= 0) {
    return '0ms';
  }
  return `${(nanoseconds / 1_000_000).toFixed(1)}ms`;
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value}B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)}KB`;
  }
  return `${(value / 1024 / 1024).toFixed(1)}MB`;
}

function formatCapacity(used: number, total: number, t: (key: string) => string, zeroKey = 'common.unknown') {
  if (total <= 0) {
    return t(zeroKey);
  }
  return `${formatBytes(used)} / ${formatBytes(total)}`;
}

function formatPercent(value: number) {
  if (!Number.isFinite(value)) {
    return '0%';
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)}%`;
}

function formatLoad(value: number) {
  if (!Number.isFinite(value)) {
    return '0.00';
  }
  return value.toFixed(2);
}

function clampPercent(value: number) {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(value)));
}

function formatNumber(value: number) {
  return new Intl.NumberFormat(undefined, { notation: value >= 10000 ? 'compact' : 'standard' }).format(value);
}

function formatRate(value: number) {
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)}/s`;
}

function formatEventTime(value: string) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return '-';
  }
  return new Intl.DateTimeFormat(undefined, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(time));
}

function rangeLabel(value: number, customRange: [string, string], t: (key: string, options?: Record<string, unknown>) => string) {
  if (value === customStatsRangeValue) {
    return validCustomRange(customRange)
      ? t('dashboard.customRangeSummary', { range: compactRangeLabel(customRange) })
      : t('dashboard.customRange');
  }
  if (value === 30) return t('dashboard.last30m');
  if (value === 360) return t('dashboard.last6h');
  if (value === 1440) return t('dashboard.last24h');
  if (value === 10080) return t('dashboard.last7d');
  return t('dashboard.last60m');
}

function validCustomRange(range: [string, string]) {
  const start = Date.parse(range[0]);
  const end = Date.parse(range[1]);
  return Number.isFinite(start) && Number.isFinite(end) && end > start;
}

function normalizeDateRange(date: unknown[]): [string, string] | null {
  if (!Array.isArray(date) || date.length !== 2) {
    return null;
  }
  const start = dateLikeToDate(date[0]);
  const end = dateLikeToDate(date[1]);
  if (!start || !end || end.getTime() <= start.getTime()) {
    return null;
  }
  return [start.toISOString(), end.toISOString()];
}

function dateLikeToDate(value: unknown) {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    if (typeof value === 'string') {
      const local = parsePickerDateTime(value);
      if (local) {
        return local;
      }
    }
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date : null;
  }
  if (value && typeof value === 'object' && 'toDate' in value && typeof value.toDate === 'function') {
    const date = value.toDate();
    return date instanceof Date && Number.isFinite(date.getTime()) ? date : null;
  }
  return null;
}

function parsePickerDateTime(value: string) {
  const match = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2})$/);
  if (!match) {
    return null;
  }
  const [, year, month, day, hour, minute] = match;
  const date = new Date(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute));
  return Number.isFinite(date.getTime()) ? date : null;
}

function formatDateTimePickerValue(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    return '';
  }
  const pad = (part: number) => String(part).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function compactRangeLabel(range: [string, string]) {
  const start = new Date(range[0]);
  const end = new Date(range[1]);
  const format = new Intl.DateTimeFormat(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  return `${format.format(start)} - ${format.format(end)}`;
}

function blockRate(blocked: number, requests: number) {
  if (requests <= 0) {
    return 0;
  }
  return Math.min(100, Math.max(0, Math.round((blocked / requests) * 100)));
}

function eventCategoryLabel(entry: LogEntry, t: (key: string, options?: Record<string, unknown>) => string) {
  if (entry.category) {
    return displayCategory(entry.category, t);
  }
  if (entry.action && entry.action !== 'allow' && entry.action !== 'pass') {
    return displayAction(entry.action, t);
  }
  return displayCategory('pass', t);
}

function eventLocationLabel(entry: LogEntry, t: (key: string, options?: Record<string, unknown>) => string) {
  return formatLogLocation(entry, t);
}

function isSecurityEvent(entry: LogEntry) {
  return Boolean(entry.category || ['block', 'challenge', 'log'].includes(entry.action));
}
