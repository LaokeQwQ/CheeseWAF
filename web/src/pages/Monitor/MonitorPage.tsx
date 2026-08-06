import { Progress, Table, Tag } from '../../ui';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Activity, AlertTriangle, Cpu, Database, HardDrive, ShieldAlert } from 'lucide-react';
import { fetchMonitorSummary } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import type { Alert } from '../../types/api';
import { displaySeverity } from '../../utils/display';

export default function MonitorPage() {
  const { t } = useTranslation();
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['monitor'],
    queryFn: fetchMonitorSummary,
    refetchInterval: 15_000,
    retry: false,
  });
  const snapshot = data?.snapshot;
  const disk = snapshot?.disk_usage ?? {};
  const dataBytes = disk.data ?? 0;
  const logBytes = disk.logs ?? 0;
  const diskTotal = snapshot?.host?.disk_total ?? 0;
  const loading = isLoading && !data;
  const processCount = snapshot?.process_count;

  if (isError && !data) {
    return (
      <section className="page-surface">
        <header className="page-header">
          <div>
            <h1>{t('monitor.title')}</h1>
            <p>{t('monitor.subtitle')}</p>
          </div>
        </header>
        <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />
      </section>
    );
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('monitor.title')}</h1>
          <p>{t('monitor.subtitle')}</p>
        </div>
      </header>

      <div className="metric-grid">
        <Metric icon={<Activity size={18} />} label={t('monitor.requests')} value={loading ? '—' : String(snapshot?.requests ?? 0)} loading={loading} />
        <Metric icon={<ShieldAlert size={18} />} label={t('monitor.blocked')} value={loading ? '—' : String(snapshot?.blocked ?? 0)} loading={loading} />
        <Metric
          icon={<Cpu size={18} />}
          label={t('monitor.processes')}
          value={loading ? '—' : (typeof processCount === 'number' ? String(processCount) : '—')}
          loading={loading}
        />
        <Metric icon={<Database size={18} />} label={t('monitor.memory')} value={loading ? '—' : formatBytes(snapshot?.memory_alloc ?? 0)} loading={loading} />
      </div>

      <div className="monitor-grid">
        <section className="panel">
          <div className="panel-heading"><h2><HardDrive size={16} /> {t('monitor.disk')}</h2></div>
          <div className="resource-stack">
            <div>
              <HardDrive size={16} />
              <span>{t('monitor.dataPath')}</span>
              <Progress percent={usagePercent(dataBytes, diskTotal)} size="small" />
              <span>{formatBytes(dataBytes)}</span>
            </div>
            <div>
              <HardDrive size={16} />
              <span>{t('monitor.logsPath')}</span>
              <Progress percent={usagePercent(logBytes, diskTotal)} size="small" />
              <span>{formatBytes(logBytes)}</span>
            </div>
          </div>
        </section>

        <section className="panel monitor-alerts-panel">
          <div className="panel-heading"><h2><AlertTriangle size={16} /> {t('monitor.alerts')}</h2></div>
          <div className="table-scroll monitor-alerts-table">
            <Table
              rowKey="rule_id"
              pagination={false}
              loading={loading}
              data={data?.alerts ?? []}
              columns={[
                { title: t('monitor.rule'), dataIndex: 'name' },
                { title: t('monitor.severity'), dataIndex: 'severity', render: (value: string) => <Tag color={severityColor(value)}>{displaySeverity(value, t)}</Tag> },
                { title: t('monitor.message'), dataIndex: 'message' },
                { title: t('monitor.value'), dataIndex: 'value', render: (_: number, record: Alert) => `${record.value} / ${record.threshold}` },
              ]}
            />
          </div>
        </section>
      </div>
    </section>
  );
}

function Metric({ icon, label, value, loading }: { icon: ReactNode; label: string; value: string; loading?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="metric-card">
      {icon}
      <span>{label}</span>
      {loading ? <strong className="metric-loading" aria-busy="true">—</strong> : <strong>{value}</strong>}
      <em>{t('monitor.live')}</em>
    </div>
  );
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  if (value < 1024 * 1024 * 1024) {
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  }
  return `${(value / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function usagePercent(value: number, total: number) {
  if (total > 0) {
    return Math.min(100, Math.max(0, Math.round((value / total) * 100)));
  }
  // No host total available — leave progress at 0 rather than invent a 1 GiB denominator.
  return 0;
}

function severityColor(value: string) {
  if (value === 'critical') {
    return 'red';
  }
  if (value === 'high') {
    return 'orange';
  }
  if (value === 'medium') {
    return 'gold';
  }
  return 'blue';
}
