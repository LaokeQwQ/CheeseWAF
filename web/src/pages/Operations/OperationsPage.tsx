import { Button, Form, Input, Modal, Progress, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Archive, Database, Edit3, RotateCcw, Trash2 } from 'lucide-react';
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
  const [editingTask, setEditingTask] = useState<ScheduledTask | null>(null);
  const persistTasks = (next: ScheduledTask[]) => tasksMutation.mutate(next);
  const patchTask = (id: string, patch: Partial<ScheduledTask>) => {
    persistTasks(tasks.map((task) => (task.id === id ? { ...task, ...patch } : task)));
  };
  const removeTask = (id: string) => {
    persistTasks(tasks.filter((task) => task.id !== id));
  };

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

      <div className="ops-grid">
        <section className="panel storage-ops-panel">
          <div className="panel-heading"><h2><Database size={16} /> {t('ops.storage')}</h2></div>
          <div className="resource-stack">
            <div><Database size={18} /><span>Data</span><Progress percent={Math.round((dataSize / total) * 100)} /><code className="resource-value">{formatBytes(dataSize)}</code></div>
            <div><Archive size={18} /><span>Logs</span><Progress percent={Math.round((logSize / total) * 100)} /><code className="resource-value">{formatBytes(logSize)}</code></div>
          </div>
          <div className="panel-actions">
            <Button icon={<RotateCcw size={16} />} onClick={() => cleanup.mutate()} loading={cleanup.isPending}>{t('ops.cleanup')}</Button>
          </div>
        </section>
        <section className="panel ops-report-panel">
          <div className="panel-heading"><h2>{t('ops.report')}</h2></div>
          <Form
            className="ops-report-form"
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
            <Form.Item label={t('ops.report')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
            <Form.Item label={t('ops.every')} field="frequency">
              <Select>
                <Select.Option value="daily">{t('ops.daily')}</Select.Option>
                <Select.Option value="weekly">{t('ops.weekly')}</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ops.at')} field="at"><Input placeholder="08:00" /></Form.Item>
            <Form.Item label={t('ops.channel')} field="channel">
              <Select>
                <Select.Option value="file">{t('ops.file')}</Select.Option>
                <Select.Option value="webhook">Webhook</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ops.recipient')} field="recipient"><Input /></Form.Item>
            <Form.Item className="wide-field">
              <Button type="primary" htmlType="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
            </Form.Item>
          </Form>
        </section>
      </div>

      <section className="table-panel ops-task-panel">
        <div className="panel-heading">
          <h2>{t('ops.taskList')}</h2>
        </div>
        <div className="desktop-table-wrap">
          <Table
            rowKey="id"
            pagination={false}
            className="ops-task-table"
            data={tasks}
            columns={[
              { title: t('ops.task'), dataIndex: 'name' },
              { title: t('ops.type'), dataIndex: 'type', render: (type: string) => <span className="status-group"><Tag>{taskTypeLabel(type, t)}</Tag></span> },
              { title: t('ops.every'), dataIndex: 'every' },
              { title: t('ops.target'), dataIndex: 'target', render: (target: string) => <code className="table-code" title={target || '-'}>{target || '-'}</code> },
              {
                title: t('rules.enabled'),
                dataIndex: 'enabled',
                render: (enabled: boolean, record: ScheduledTask) => (
                  <Switch
                    size="small"
                    checked={enabled}
                    loading={tasksMutation.isPending}
                    onChange={(next) => patchTask(record.id, { enabled: next })}
                  />
                ),
              },
              {
                title: t('common.actions'),
                dataIndex: 'actions',
                render: (_: unknown, record: ScheduledTask) => (
                  <span className="table-action-group ops-task-actions">
                    <Button size="mini" icon={<Edit3 size={13} />} onClick={() => setEditingTask(record)}>{t('common.edit')}</Button>
                    <Button
                      size="mini"
                      status="danger"
                      icon={<Trash2 size={13} />}
                      disabled={tasksMutation.isPending}
                      onClick={() => removeTask(record.id)}
                    >
                      {t('common.delete')}
                    </Button>
                  </span>
                ),
              },
            ]}
          />
        </div>
        <div className="mobile-card-list ops-task-cards">
          {tasks.map((task) => (
            <TaskCard
              key={task.id}
              task={task}
              busy={tasksMutation.isPending}
              onToggle={(enabled) => patchTask(task.id, { enabled })}
              onEdit={() => setEditingTask(task)}
              onDelete={() => removeTask(task.id)}
              t={t}
            />
          ))}
        </div>
      </section>
      <Modal
        title={t('ops.editTask')}
        visible={Boolean(editingTask)}
        footer={null}
        onCancel={() => setEditingTask(null)}
        className="ops-task-modal"
      >
        {editingTask && (
          <Form
            key={editingTask.id}
            layout="vertical"
            initialValues={editingTask}
            onSubmit={(values) => {
              patchTask(editingTask.id, {
                name: values.name,
                every: values.every,
                target: values.target,
                enabled: values.enabled,
              });
              setEditingTask(null);
            }}
          >
            <Form.Item label={t('ops.task')} field="name"><Input /></Form.Item>
            <Form.Item label={t('ops.every')} field="every"><Input /></Form.Item>
            <Form.Item label={t('ops.target')} field="target"><Input /></Form.Item>
            <Form.Item label={t('rules.enabled')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
            <div className="form-action-row">
              <Button onClick={() => setEditingTask(null)}>{t('common.close')}</Button>
              <Button type="primary" htmlType="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
            </div>
          </Form>
        )}
      </Modal>
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

function taskTypeLabel(type: string, t: (key: string, options?: Record<string, unknown>) => string) {
  if (type === 'security_report') {
    return t('ops.report');
  }
  if (type === 'cleanup') {
    return t('ops.cleanup');
  }
  return type || '-';
}

function TaskCard({
  task,
  busy,
  onToggle,
  onEdit,
  onDelete,
  t,
}: {
  task: ScheduledTask;
  busy: boolean;
  onToggle: (enabled: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <article className="mobile-data-card">
      <header>
        <strong>{task.name}</strong>
        <Tag>{taskTypeLabel(task.type, t)}</Tag>
      </header>
      <dl>
        <div>
          <dt>{t('ops.every')}</dt>
          <dd>{task.every || '-'}</dd>
        </div>
        <div>
          <dt>{t('ops.target')}</dt>
          <dd><code className="table-code" title={task.target || '-'}>{task.target || '-'}</code></dd>
        </div>
        <div>
          <dt>{t('rules.enabled')}</dt>
          <dd>
            <Switch size="small" checked={task.enabled} loading={busy} onChange={onToggle} />
          </dd>
        </div>
      </dl>
      <div className="mobile-card-actions">
        <Button icon={<Edit3 size={14} />} onClick={onEdit}>{t('common.edit')}</Button>
        <Button status="danger" icon={<Trash2 size={14} />} disabled={busy} onClick={onDelete}>
          {t('common.delete')}
        </Button>
      </div>
    </article>
  );
}
