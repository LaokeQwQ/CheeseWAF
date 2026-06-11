import { Button, Message as ArcoMessage, Progress, Select, Spin, Tag, Tooltip } from '@arco-design/web-react';
import { useMemo, useState, type CSSProperties } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Activity, Cpu, HardDrive, MemoryStick, Network, Recycle, RotateCcw, ShieldCheck, Zap, ZoomIn, ZoomOut } from 'lucide-react';
import { listItemVariants, listVariants } from '../../animations/variants';
import { fetchLogs, fetchMonitorSummary, fetchSites, reclaimSystemResources } from '../../api/client';
import type { LogEntry, LogQuery } from '../../types/api';
import { displayAction, displayCategory } from '../../utils/display';

const threatColors = ['var(--accent-danger)', 'var(--accent-warning)', 'var(--accent-purple)', 'var(--accent-info)'];
const realtimeWindowSeconds = 60;
const totalsRefreshMs = 10_000;
const refreshOptions = [1000, 3000, 5000, 10000];
const statsRangeOptions = [
  { value: 30, labelKey: 'dashboard.last30m' },
  { value: 60, labelKey: 'dashboard.last60m' },
  { value: 360, labelKey: 'dashboard.last6h' },
  { value: 1440, labelKey: 'dashboard.last24h' },
  { value: 10080, labelKey: 'dashboard.last7d' },
];

export default function DashboardPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [statsRange, setStatsRange] = useState(60);
  const [refreshMs, setRefreshMs] = useState(3000);
  const [chartScale, setChartScale] = useState(1);
  const { data: monitor, isLoading: loadingMonitor, isFetching: fetchingMonitor, refetch: refetchMonitor } = useQuery({
    queryKey: ['dashboard-monitor'],
    queryFn: fetchMonitorSummary,
    refetchInterval: refreshMs,
    retry: false,
  });
  const { data: periodLogs, isLoading: loadingPeriod, refetch: refetchPeriodLogs } = useQuery({
    queryKey: ['dashboard-period-logs', statsRange],
    queryFn: () => fetchLogs(buildWindowQuery(statsRange * 60, 5000)),
    refetchInterval: totalsRefreshMs,
    retry: false,
  });
  const { data: liveLogs, isLoading: loadingLive, isFetching: fetchingLive, refetch: refetchLiveLogs } = useQuery({
    queryKey: ['dashboard-live-logs'],
    queryFn: () => fetchLogs(buildWindowQuery(realtimeWindowSeconds, 500)),
    refetchInterval: refreshMs,
    retry: false,
  });
  const { data: sites, refetch: refetchSites } = useQuery({ queryKey: ['dashboard-sites'], queryFn: fetchSites, refetchInterval: 30_000, retry: false });
  const reclaimMutation = useMutation({
    mutationFn: reclaimSystemResources,
    onSuccess: (result) => {
      const message = `${t('dashboard.reclaimResult')}: ${result.actions.filter((item) => item.ok).length}/${result.actions.length}`;
      if (result.ok) {
        ArcoMessage.success(message);
      } else {
        ArcoMessage.warning(message);
      }
      queryClient.invalidateQueries({ queryKey: ['dashboard-monitor'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const snapshot = monitor?.snapshot;
  const entries = periodLogs?.items ?? [];
  const liveEntries = liveLogs?.items ?? [];
  const traffic = useMemo(() => buildTraffic(entries, statsRange), [entries, statsRange]);
  const liveSeries = useMemo(() => buildRealtimeSeries(liveEntries, realtimeWindowSeconds), [liveEntries]);
  const threats = useMemo(() => buildThreatMix(entries, t), [entries, t]);
  const latency = useMemo(() => p95Latency(entries), [entries]);
  const periodRequests = traffic.reduce((sum, point) => sum + point.count, 0);
  const periodBlockedCount = entries.filter((entry) => entry.action === 'block').length;
  const liveRequests = liveEntries.length;
  const liveBlockedCount = liveEntries.filter((entry) => entry.action === 'block').length;
  const siteCount = sites?.length ?? snapshot?.sites ?? 0;
  const host = snapshot?.host;
  const cpuPercent = clampPercent(host?.cpu_percent ?? 0);
  const memoryHostPercent = clampPercent(host?.memory_percent ?? 0);
  const diskPercent = clampPercent(host?.disk_percent ?? 0);
  const swapPercent = clampPercent(host?.swap_percent ?? 0);
  const cpuCount = host?.cpu_count ?? 0;
  const load1 = host?.load1 ?? 0;
  const loadPercent = clampPercent(cpuCount > 0 ? (load1 / cpuCount) * 100 : load1 * 25);
  const loading = loadingMonitor || loadingPeriod;
  const refreshingLiveResources = fetchingMonitor || fetchingLive;
  const maxTraffic = Math.max(...traffic.map((point) => point.count), 1);
  const yMax = Math.max(1, Math.ceil(maxTraffic / chartScale));
  const yMid = yMax <= 1 ? '0.5' : formatNumber(Math.ceil(yMax / 2));
  const monitorState = snapshot
    ? { color: 'green', label: t('common.online') }
    : { color: loadingMonitor ? 'blue' : 'orange', label: loadingMonitor ? t('common.loading') : t('shell.connectionReconnecting') };
  const manualRefresh = () => {
    void refetchMonitor();
    void refetchLiveLogs();
    void refetchPeriodLogs();
    void refetchSites();
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

      <motion.div className="metric-grid" variants={listVariants} initial="initial" animate="enter">
        {[
          { label: t('dashboard.totalRequests'), value: formatNumber(periodRequests), delta: rangeLabel(statsRange, t), icon: Zap },
          { label: t('dashboard.totalBlocked'), value: formatNumber(periodBlockedCount), delta: `${blockRate(periodBlockedCount, periodRequests)}%`, icon: ShieldCheck },
          { label: t('shell.latency'), value: formatLatency(latency), delta: 'P95', icon: Network },
          { label: t('dashboard.sites'), value: formatNumber(siteCount), delta: snapshot ? t('common.online') : t('common.unknown'), icon: HardDrive },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <motion.article className="metric-card" key={item.label} variants={listItemVariants}>
              <Icon size={20} />
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <em>{item.delta}</em>
            </motion.article>
          );
        })}
      </motion.div>

      <div className="dashboard-grid">
        <div className="dashboard-main-stack">
          <section className="panel panel-wide">
            <div className="panel-heading">
              <h2>{t('dashboard.totals')}</h2>
              <div className="chart-controls">
                <Button icon={<ZoomOut size={14} />} onClick={() => setChartScale((value) => Math.max(0.5, Number((value - 0.25).toFixed(2))))} />
                <span>{Math.round(chartScale * 100)}%</span>
                <Button icon={<ZoomIn size={14} />} onClick={() => setChartScale((value) => Math.min(2.5, Number((value + 0.25).toFixed(2))))} />
                <Button icon={<RotateCcw size={14} />} onClick={() => setChartScale(1)} />
              </div>
            </div>
            <Spin loading={loading}>
              <div className="traffic-chart" aria-label={t('dashboard.totals')}>
                <div className="chart-y-axis" aria-hidden="true">
                  <span>{yMax}</span>
                  <span>{yMid}</span>
                  <span>0</span>
                </div>
                <div className="chart-plot" style={{ '--bar-count': traffic.length } as CSSProperties}>
                  {traffic.map((point, index) => (
                    <motion.span
                      key={`${point.label}-${index}`}
                      className="chart-bar"
                      initial={{ height: 0 }}
                      animate={{ height: `${Math.max((point.count / yMax) * 100, point.count > 0 ? 5 : 2)}%` }}
                      transition={{ delay: index * 0.018, duration: 0.26 }}
                      title={`${point.label}: ${point.count} ${t('dashboard.trafficRequests')}`}
                    >
                      <i />
                    </motion.span>
                  ))}
                </div>
                <div className="chart-x-axis" aria-hidden="true">
                  <span>{traffic[0]?.label ?? '-'}</span>
                  <span>{traffic[Math.floor(traffic.length / 2)]?.label ?? '-'}</span>
                  <span>{traffic[traffic.length - 1]?.label ?? '-'}</span>
                </div>
              </div>
            </Spin>
            <div className="dashboard-chart-footer">
              <div className="chart-legend" aria-label={t('dashboard.trafficRequests')}>
                <span><i /> {t('dashboard.trafficRequests')}</span>
                <span>{t('dashboard.statsWindow')}: {rangeLabel(statsRange, t)}</span>
              </div>
              <div className="control-cluster dashboard-footer-controls">
                <span>{t('dashboard.statsWindow')}</span>
                <Select className="dashboard-footer-select" value={statsRange} onChange={(value) => setStatsRange(Number(value))}>
                  {statsRangeOptions.map((option) => <Select.Option key={option.value} value={option.value}>{t(option.labelKey)}</Select.Option>)}
                </Select>
              </div>
              <div className="control-cluster dashboard-footer-controls">
                <span>{t('dashboard.autoRefresh')}</span>
                <Select className="dashboard-footer-select dashboard-refresh-select" value={refreshMs} onChange={(value) => setRefreshMs(Number(value))}>
                  {refreshOptions.map((value) => <Select.Option key={value} value={value}>{value / 1000}s</Select.Option>)}
                </Select>
                <Tooltip content={t('dashboard.manualRefresh')}>
                  <Button
                    className={refreshingLiveResources ? 'icon-button refresh-button refresh-button-active' : 'icon-button refresh-button'}
                    icon={<RotateCcw size={15} />}
                    onClick={manualRefresh}
                  />
                </Tooltip>
              </div>
            </div>
          </section>

          <section className="panel panel-wide">
            <div className="panel-heading">
              <h2>{t('dashboard.events')}</h2>
            </div>
            <div className="event-list">
              {entries.length === 0 && <div className="empty-state">{t('monitor.requests')}: 0</div>}
              {entries.slice(0, 6).map((event) => (
                <div className="event-row" key={event.id || event.trace_id || `${event.client_ip}-${event.timestamp}`}>
                  <Link className="event-trace-link" to={`/logs/${encodeURIComponent(event.trace_id || event.id || '-')}`} title={event.trace_id || event.id || '-'}>
                    <code className="event-trace">{event.trace_id || event.id || '-'}</code>
                  </Link>
                  <span className="event-source" title={event.client_ip || '-'}>
                    {event.client_ip || '-'}
                  </span>
                  <span className="event-status-group">
                    <Tag color={event.category ? 'orange' : event.action === 'pass' || !event.action ? 'green' : 'blue'}>{eventCategoryLabel(event, t)}</Tag>
                    <Tag color={event.action === 'block' ? 'red' : 'blue'}>
                      {displayAction(event.action, t)}
                    </Tag>
                  </span>
                </div>
              ))}
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
            <Spin loading={loadingLive}>
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
            </div>
            <div className="resource-runtime">
              <span>{t('dashboard.processRuntime')}</span>
              <strong>{t('dashboard.processHint', { goroutines: snapshot?.goroutines ?? 0, heap: formatBytes(snapshot?.memory_alloc ?? 0) })}</strong>
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

function buildTraffic(entries: LogEntry[], rangeMinutes: number) {
  const bucketCount = rangeMinutes <= 60 ? 12 : rangeMinutes <= 1440 ? 24 : 28;
  const buckets = Array.from({ length: bucketCount }, () => 0);
  const now = Date.now();
  const windowMs = rangeMinutes * 60 * 1000;
  const bucketMs = windowMs / buckets.length;
  for (const entry of entries) {
    const time = Date.parse(entry.timestamp);
    if (!Number.isFinite(time) || time < now - windowMs || time > now + 60_000) {
      continue;
    }
    const index = Math.min(buckets.length - 1, Math.max(0, Math.floor((time - (now - windowMs)) / bucketMs)));
    buckets[index] += 1;
  }
  return buckets.map((count, index) => {
    const at = new Date(now - windowMs + bucketMs * index);
    return {
      count,
      label: at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
    };
  });
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

function p95Latency(entries: LogEntry[]) {
  const values = entries.map((entry) => Number(entry.latency)).filter((value) => Number.isFinite(value) && value > 0).sort((a, b) => a - b);
  if (values.length === 0) {
    return 0;
  }
  return values[Math.min(values.length - 1, Math.floor(values.length * 0.95))];
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

function rangeLabel(value: number, t: (key: string) => string) {
  if (value === 30) return t('dashboard.last30m');
  if (value === 360) return t('dashboard.last6h');
  if (value === 1440) return t('dashboard.last24h');
  if (value === 10080) return t('dashboard.last7d');
  return t('dashboard.last60m');
}

function blockRate(blocked: number, requests: number) {
  if (requests <= 0) {
    return 0;
  }
  return Math.round((blocked / requests) * 100);
}

function eventCategoryLabel(entry: LogEntry, t: (key: string, options?: Record<string, unknown>) => string) {
  if (entry.category) {
    return displayCategory(entry.category, t);
  }
  if (entry.action && entry.action !== 'pass') {
    return displayAction(entry.action, t);
  }
  return displayCategory('pass', t);
}
