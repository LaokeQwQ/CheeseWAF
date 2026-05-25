import { Button, Form, Input, Progress, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Archive, Database, RotateCcw } from 'lucide-react';
import { cleanupStorage, exportBackup, fetchStorageStats, fetchTasks, updateTasks } from '../../api/client';
import type { ScheduledTask } from '../../types/api';

export default function OperationsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: tasks = [] } = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks, retry: false });
  const { data: storage } = useQuery({ queryKey: ['storage'], queryFn: fetchStorageStats, retry: false });
  const cleanup = useMutation({ mutationFn: cleanupStorage, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['storage'] }) });
  const backup = useMutation({ mutationFn: exportBackup });
  const tasksMutation = useMutation({ mutationFn: updateTasks, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['tasks'] }) });
  const dataSize = storage?.data ?? 0;
  const logSize = storage?.logs ?? 0;
  const total = Math.max(dataSize + logSize, 1);
  const reportTask = tasks.find((task) => task.type === 'security_report') ?? defaultReportTask;

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ops.title')}</h1>
          <p>{t('ops.subtitle')}</p>
        </div>
        <Button type="primary" icon={<Archive size={16} />} onClick={() => backup.mutate()} loading={backup.isPending}>
          {t('ops.backup')}
        </Button>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><Database size={16} /> {t('ops.storage')}</h2></div>
          <div className="resource-stack">
            <div><Database size={18} /><span>Data</span><Progress percent={Math.round((dataSize / total) * 100)} /><code>{formatBytes(dataSize)}</code></div>
            <div><Archive size={18} /><span>Logs</span><Progress percent={Math.round((logSize / total) * 100)} /><code>{formatBytes(logSize)}</code></div>
          </div>
          <Button icon={<RotateCcw size={16} />} onClick={() => cleanup.mutate()} loading={cleanup.isPending}>{t('ops.cleanup')}</Button>
        </section>
        <section className="panel">
          <div className="panel-heading"><h2>{t('ops.report')}</h2></div>
          <Form
            layout="vertical"
            initialValues={{
              enabled: reportTask.enabled,
              frequency: reportTask.frequency ?? 'daily',
              at: reportTask.at ?? '08:00',
              channel: reportTask.channel ?? 'file',
              recipient: reportTask.recipient ?? './data/reports',
              period: reportTask.period ?? 'daily',
            }}
            onSubmit={(values) => tasksMutation.mutate(upsertReportTask(tasks, { ...reportTask, ...values }))}
          >
            <Form.Item label={t('ops.report')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('ops.every')} field="frequency">
              <Select>
                <Select.Option value="daily">Daily</Select.Option>
                <Select.Option value="weekly">Weekly</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ops.at')} field="at"><Input placeholder="08:00" /></Form.Item>
            <Form.Item label={t('ops.channel')} field="channel">
              <Select>
                <Select.Option value="file">File</Select.Option>
                <Select.Option value="webhook">Webhook</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ops.recipient')} field="recipient"><Input /></Form.Item>
            <Button htmlType="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>
      </div>

      <section className="table-panel">
        <Table
          rowKey="id"
          pagination={false}
          data={tasks}
          columns={[
            { title: t('ops.task'), dataIndex: 'name' },
            { title: t('ops.type'), dataIndex: 'type', render: (type: string) => <Tag>{type}</Tag> },
            { title: t('ops.every'), dataIndex: 'every' },
            { title: t('ops.target'), dataIndex: 'target', render: (target: string) => <code>{target}</code> },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (enabled: boolean) => <Tag color={enabled ? 'green' : 'gray'}>{String(enabled)}</Tag> },
          ]}
        />
      </section>
    </section>
  );
}

const defaultReportTask: ScheduledTask = {
  id: 'security-daily-report',
  name: 'Security daily report',
  type: 'security_report',
  schedule: '',
  every: '24h',
  frequency: 'daily',
  at: '08:00',
  target: '',
  channel: 'file',
  recipient: './data/reports',
  period: 'daily',
  format: 'markdown',
  keep: 7,
  enabled: false,
};

function upsertReportTask(tasks: ScheduledTask[], next: ScheduledTask) {
  const normalized = {
    ...defaultReportTask,
    ...next,
    period: next.period ?? next.frequency ?? 'daily',
    format: next.format ?? 'markdown',
    name: next.name || 'Security report',
  };
  const found = tasks.some((task) => task.id === normalized.id);
  if (found) {
    return tasks.map((task) => (task.id === normalized.id ? normalized : task));
  }
  return [...tasks, normalized];
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}
