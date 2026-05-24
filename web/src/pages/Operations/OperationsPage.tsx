import { Button, Progress, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Archive, Database, RotateCcw } from 'lucide-react';
import { cleanupStorage, exportBackup, fetchStorageStats, fetchTaskHistory, fetchTasks } from '../../api/client';

export default function OperationsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: tasks = [] } = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks, retry: false });
  const { data: history = [] } = useQuery({ queryKey: ['task-history'], queryFn: fetchTaskHistory, retry: false });
  const { data: storage } = useQuery({ queryKey: ['storage'], queryFn: fetchStorageStats, retry: false });
  const cleanup = useMutation({ mutationFn: cleanupStorage, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['storage'] }) });
  const backup = useMutation({ mutationFn: exportBackup });
  const dataSize = storage?.data ?? 0;
  const logSize = storage?.logs ?? 0;
  const total = Math.max(dataSize + logSize, 1);

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
          <div className="panel-heading"><h2>{t('ops.history')}</h2></div>
          <Table
            rowKey="task_id"
            pagination={false}
            data={history}
            columns={[
              { title: 'Task', dataIndex: 'task_id' },
              { title: 'Result', dataIndex: 'success', render: (success: boolean) => <Tag color={success ? 'green' : 'red'}>{String(success)}</Tag> },
              { title: 'Duration', dataIndex: 'duration' },
            ]}
          />
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

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}
