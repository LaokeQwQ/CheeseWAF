import { Progress, Spin, Tag } from '@arco-design/web-react';
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { Cpu, HardDrive, Network, ShieldCheck, Zap } from 'lucide-react';
import { listItemVariants, listVariants } from '../../animations/variants';
import { fetchLogs, fetchMonitorSummary, fetchSites } from '../../api/client';
import type { LogEntry } from '../../types/api';

const threatColors = ['var(--accent-danger)', 'var(--accent-warning)', 'var(--accent-purple)', 'var(--accent-info)'];

export default function DashboardPage() {
  const { t } = useTranslation();
  const { data: monitor, isLoading: loadingMonitor } = useQuery({ queryKey: ['dashboard-monitor'], queryFn: fetchMonitorSummary, refetchInterval: 10_000, retry: false });
  const { data: logs, isLoading: loadingLogs } = useQuery({ queryKey: ['dashboard-logs'], queryFn: () => fetchLogs({ limit: 200 }), refetchInterval: 8_000, retry: false });
  const { data: sites } = useQuery({ queryKey: ['dashboard-sites'], queryFn: fetchSites, refetchInterval: 30_000, retry: false });
  const snapshot = monitor?.snapshot;
  const entries = logs?.items ?? [];
  const traffic = useMemo(() => buildTraffic(entries), [entries]);
  const threats = useMemo(() => buildThreatMix(entries), [entries]);
  const latency = useMemo(() => p95Latency(entries), [entries]);
  const blocked = snapshot?.blocked ?? entries.filter((entry) => entry.action === 'block').length;
  const requests = snapshot?.requests ?? logs?.total ?? entries.length;
  const siteCount = sites?.length ?? snapshot?.sites ?? 0;
  const loading = loadingMonitor || loadingLogs;

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('dashboard.title')}</h1>
          <p>{t('dashboard.subtitle')}</p>
        </div>
        <Tag color="green" icon={<ShieldCheck size={14} />}>
          {t('common.online')}
        </Tag>
      </header>

      <motion.div className="metric-grid" variants={listVariants} initial="initial" animate="enter">
        {[
          { label: t('shell.requests'), value: formatNumber(requests), delta: 'live', icon: Zap },
          { label: t('shell.attacks'), value: formatNumber(blocked), delta: `${blockRate(blocked, requests)}%`, icon: ShieldCheck },
          { label: t('shell.latency'), value: formatLatency(latency), delta: 'P95', icon: Network },
          { label: t('dashboard.sites'), value: formatNumber(siteCount), delta: t('common.online'), icon: HardDrive },
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
        <section className="panel panel-wide">
          <div className="panel-heading">
            <h2>{t('dashboard.traffic')}</h2>
            <span>last 60m</span>
          </div>
          <Spin loading={loading}>
            <div className="bar-chart" aria-label={t('dashboard.traffic')}>
              {traffic.map((value, index) => (
                <motion.span
                  key={`${value}-${index}`}
                  initial={{ height: 0 }}
                  animate={{ height: `${Math.max(value, 4)}%` }}
                  transition={{ delay: index * 0.02, duration: 0.28 }}
                  title={`${value}%`}
                />
              ))}
            </div>
          </Spin>
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

        <section className="panel">
          <div className="panel-heading">
            <h2>{t('dashboard.resources')}</h2>
          </div>
          <div className="resource-stack">
            <div>
              <Cpu size={18} />
              <span>Go</span>
              <Progress percent={runtimePercent(snapshot?.goroutines ?? 0)} size="small" showText={false} />
              <strong>{snapshot?.goroutines ?? 0}</strong>
            </div>
            <div>
              <HardDrive size={18} />
              <span>RAM</span>
              <Progress percent={memoryPercent(snapshot?.memory_alloc ?? 0)} size="small" showText={false} />
              <strong>{formatBytes(snapshot?.memory_alloc ?? 0)}</strong>
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
              <div className="event-row" key={event.id || event.trace_id}>
                <code>{event.trace_id || event.id}</code>
                <span>{event.client_ip}</span>
                <Tag color={event.category ? 'orange' : 'green'}>{displayCategory(event.category)}</Tag>
                <Tag color={event.action === 'block' ? 'red' : 'blue'}>
                  {event.action === 'block' ? t('common.block') : event.action || t('common.monitor')}
                </Tag>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}

function buildTraffic(entries: LogEntry[]) {
  const buckets = Array.from({ length: 12 }, () => 0);
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const bucketMs = windowMs / buckets.length;
  for (const entry of entries) {
    const time = Date.parse(entry.timestamp);
    if (!Number.isFinite(time) || time < now - windowMs || time > now + 60_000) {
      continue;
    }
    const index = Math.min(buckets.length - 1, Math.max(0, Math.floor((time - (now - windowMs)) / bucketMs)));
    buckets[index] += 1;
  }
  const max = Math.max(...buckets, 1);
  return buckets.map((count) => Math.round((count / max) * 100));
}

function buildThreatMix(entries: LogEntry[]) {
  const counts = new Map<string, number>();
  for (const entry of entries) {
    if (!entry.category) {
      continue;
    }
    const category = displayCategory(entry.category);
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

function displayCategory(value: string) {
  return value ? value.toUpperCase() : 'PASS';
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

function formatNumber(value: number) {
  return new Intl.NumberFormat(undefined, { notation: value >= 10000 ? 'compact' : 'standard' }).format(value);
}

function blockRate(blocked: number, requests: number) {
  if (requests <= 0) {
    return 0;
  }
  return Math.round((blocked / requests) * 100);
}

function runtimePercent(goroutines: number) {
  return Math.min(100, Math.round((goroutines / 128) * 100));
}

function memoryPercent(bytes: number) {
  return Math.min(100, Math.round((bytes / (512 * 1024 * 1024)) * 100));
}
