import { Progress, Table, Tag } from '@arco-design/web-react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Activity, AlertTriangle, Cpu, Database, HardDrive, ShieldAlert } from 'lucide-react';
import { fetchMonitorSummary } from '../../api/client';
import type { Alert } from '../../types/api';

export default function MonitorPage() {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ['monitor'], queryFn: fetchMonitorSummary, refetchInterval: 15_000, retry: false });
  const snapshot = data?.snapshot;
  const disk = snapshot?.disk_usage ?? {};
  const dataBytes = disk.data ?? 0;
  const logBytes = disk.logs ?? 0;

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('monitor.title')}</h1>
          <p>{t('monitor.subtitle')}</p>
        </div>
      </header>

      <div className="metric-grid">
        <Metric icon={<Activity size={18} />} label={t('monitor.requests')} value={String(snapshot?.requests ?? 0)} />
        <Metric icon={<ShieldAlert size={18} />} label={t('monitor.blocked')} value={String(snapshot?.blocked ?? 0)} />
        <Metric icon={<Cpu size={18} />} label={t('monitor.goroutines')} value={String(snapshot?.goroutines ?? 0)} />
        <Metric icon={<Database size={18} />} label={t('monitor.memory')} value={formatBytes(snapshot?.memory_alloc ?? 0)} />
      </div>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><HardDrive size={16} /> {t('monitor.disk')}</h2></div>
          <div className="resource-stack">
            <div><HardDrive size={16} /><span>data</span><Progress percent={usagePercent(dataBytes)} size="small" /><span>{formatBytes(dataBytes)}</span></div>
            <div><HardDrive size={16} /><span>logs</span><Progress percent={usagePercent(logBytes)} size="small" /><span>{formatBytes(logBytes)}</span></div>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><AlertTriangle size={16} /> {t('monitor.alerts')}</h2></div>
          <Table
            rowKey="rule_id"
            pagination={false}
            data={data?.alerts ?? []}
            columns={[
              { title: t('monitor.rule'), dataIndex: 'name' },
              { title: t('monitor.severity'), dataIndex: 'severity', render: (value: string) => <Tag color={severityColor(value)}>{value}</Tag> },
              { title: t('monitor.message'), dataIndex: 'message' },
              { title: t('monitor.value'), dataIndex: 'value', render: (_: number, record: Alert) => `${record.value} / ${record.threshold}` },
            ]}
          />
        </section>
      </div>
    </section>
  );
}

function Metric({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="metric-card">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
      <em>live</em>
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
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function usagePercent(value: number) {
  return Math.min(100, Math.round((value / (1024 * 1024 * 1024)) * 100));
}

function severityColor(value: string) {
  if (value === 'high' || value === 'critical') {
    return 'red';
  }
  if (value === 'medium') {
    return 'orange';
  }
  return 'blue';
}
