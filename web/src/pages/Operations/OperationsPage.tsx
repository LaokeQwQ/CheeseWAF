import { Button, Form, Input, InputNumber, Message as ArcoMessage, Modal, Progress, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Archive, Database, Edit3, Plus, RotateCcw, Trash2 } from 'lucide-react';
import { cleanupStorage, exportBackup, fetchStorageStats, fetchTasks, updateTasks } from '../../api/client';
import type { ScheduledTask } from '../../types/api';

type DurationUnit = 'm' | 'h' | 'd';

type TaskFormValues = ScheduledTask & {
  everyValue?: number;
  everyUnit?: DurationUnit;
};

const durationUnitOptions: DurationUnit[] = ['m', 'h', 'd'];
const taskTypeOptions = ['cleanup', 'backup', 'security_report', 'ai_self_learning'];
const taskFrequencyOptions = ['interval', 'daily', 'weekly', 'monthly'];

export default function OperationsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: tasks = [] } = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks, retry: false });
  const { data: storage } = useQuery({ queryKey: ['storage'], queryFn: fetchStorageStats, retry: false });
  const cleanup = useMutation({
    mutationFn: cleanupStorage,
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['storage'] });
      ArcoMessage.success(t('ops.cleanupDone', { removed: result.removed, scanned: result.scanned }));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const backup = useMutation({ mutationFn: exportBackup });
  const tasksMutation = useMutation({
    mutationFn: updateTasks,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['tasks'] });
      ArcoMessage.success(t('ops.tasksSaved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const dataSize = storage?.data ?? 0;
  const logSize = storage?.logs ?? 0;
  const total = Math.max(dataSize + logSize, 1);
  const reportTask = tasks.find((task) => task.type === 'security_report') ?? defaultReportTask;
  const [editingTask, setEditingTask] = useState<ScheduledTask | null>(null);
  const persistTasks = (next: ScheduledTask[]) => tasksMutation.mutate(next);
  const patchTask = (id: string, patch: Partial<ScheduledTask>) => {
    persistTasks(tasks.map((task) => (task.id === id ? { ...task, ...patch } : task)));
  };
  const saveTask = (task: ScheduledTask, patch: Partial<ScheduledTask>) => {
    const nextTask = { ...task, ...patch };
    const exists = tasks.some((item) => item.id === task.id);
    persistTasks(exists ? tasks.map((item) => (item.id === task.id ? nextTask : item)) : [...tasks, nextTask]);
  };
  const removeTask = (id: string) => {
    Modal.confirm({
      title: t('common.confirmDeleteTitle'),
      content: t('common.confirmDeleteEntry'),
      okText: t('common.delete'),
      cancelText: t('common.cancel'),
      okButtonProps: { status: 'danger' },
      onOk: () => persistTasks(tasks.filter((task) => task.id !== id)),
    });
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
            <div><Database size={18} /><span>{t('ops.dataDir')}</span><Progress percent={Math.round((dataSize / total) * 100)} status={dataSize / total > 0.9 ? 'error' : 'normal'} /><code className="resource-value">{formatBytes(dataSize)}</code></div>
            <div><Archive size={18} /><span>{t('ops.logsDir')}</span><Progress percent={Math.round((logSize / total) * 100)} status={logSize / total > 0.9 ? 'error' : 'normal'} /><code className="resource-value">{formatBytes(logSize)}</code></div>
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
                <Select.Option value="monthly">{t('ops.monthly')}</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('ops.at')} field="at"><Input placeholder="08:00" /></Form.Item>
            <Form.Item label={t('ops.channel')} field="channel">
              <Select>
                <Select.Option value="file">{t('ops.file')}</Select.Option>
                <Select.Option value="webhook">Webhook</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item className="ops-report-recipient" label={t('ops.recipient')} field="recipient"><Input /></Form.Item>
            <Form.Item className="ops-report-actions">
              <Button type="primary" htmlType="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
            </Form.Item>
          </Form>
        </section>
      </div>

      <section className="table-panel ops-task-panel">
        <div className="panel-heading">
          <h2>{t('ops.taskList')}</h2>
          <Button icon={<Plus size={15} />} onClick={() => setEditingTask(newScheduledTask())}>{t('common.add')}</Button>
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
              { title: t('ops.every'), dataIndex: 'every', render: (_: unknown, record: ScheduledTask) => formatTaskSchedule(record, t) },
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
            className="ops-task-form"
            layout="vertical"
            initialValues={taskToFormValues(editingTask)}
            onSubmit={(values: TaskFormValues) => {
              saveTask(editingTask, normalizeTaskFormValues(editingTask, values));
              setEditingTask(null);
            }}
          >
            <div className="ops-task-form-grid">
              <Form.Item label={t('ops.task')} field="name" rules={[{ required: true }]}>
                <Input placeholder={t('ops.taskNamePlaceholder')} />
              </Form.Item>
              <Form.Item label={t('ops.type')} field="type" rules={[{ required: true }]}>
                <Select>
                  {taskTypeOptions.map((type) => <Select.Option key={type} value={type}>{taskTypeLabel(type, t)}</Select.Option>)}
                </Select>
              </Form.Item>
              <Form.Item label={t('ops.frequency')} field="frequency" rules={[{ required: true }]}>
                <Select>
                  {taskFrequencyOptions.map((frequency) => <Select.Option key={frequency} value={frequency}>{frequencyLabel(frequency, t)}</Select.Option>)}
                </Select>
              </Form.Item>
              <Form.Item label={t('ops.at')} field="at"><Input placeholder="08:00" /></Form.Item>
              <Form.Item label={t('ops.everyValue')} field="everyValue">
                <InputNumber min={1} max={31 * 24 * 60} />
              </Form.Item>
              <Form.Item label={t('ops.everyUnit')} field="everyUnit">
                <Select>
                  {durationUnitOptions.map((unit) => <Select.Option key={unit} value={unit}>{durationUnitLabel(unit, t)}</Select.Option>)}
                </Select>
              </Form.Item>
              <Form.Item label={t('ops.target')} field="target"><Input placeholder="./logs" /></Form.Item>
              <Form.Item label={t('ops.keep')} field="keep"><InputNumber min={1} max={365} /></Form.Item>
              <Form.Item label={t('ops.channel')} field="channel">
                <Select allowClear>
                  <Select.Option value="file">{t('ops.file')}</Select.Option>
                  <Select.Option value="webhook">Webhook</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={t('ops.recipient')} field="recipient"><Input placeholder="./data/reports" /></Form.Item>
            </div>
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
    frequency: next.frequency || 'daily',
    schedule: next.frequency || 'daily',
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
  if (type === 'backup') {
    return t('ops.backupTask');
  }
  if (type === 'ai_self_learning' || type === 'self_learning_rules') {
    return t('ops.aiSelfLearning');
  }
  return type || '-';
}

function frequencyLabel(frequency: string, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (frequency) {
    case 'daily':
      return t('ops.daily');
    case 'weekly':
      return t('ops.weekly');
    case 'monthly':
      return t('ops.monthly');
    case 'interval':
      return t('ops.interval');
    default:
      return frequency || t('common.unknown');
  }
}

function taskToFormValues(task: ScheduledTask): TaskFormValues {
  const duration = parseDuration(task.every);
  return {
    ...task,
    type: task.type || 'cleanup',
    frequency: task.frequency || task.schedule || 'interval',
    at: task.at || '08:00',
    everyValue: duration.value,
    everyUnit: duration.unit,
    keep: task.keep || 7,
  };
}

function normalizeTaskFormValues(base: ScheduledTask, values: TaskFormValues): Partial<ScheduledTask> {
  const frequency = values.frequency || 'interval';
  return {
    name: values.name,
    type: values.type || 'cleanup',
    frequency,
    schedule: frequency,
    at: values.at || '08:00',
    every: durationToString(values.everyValue, values.everyUnit),
    target: values.target || base.target || '',
    channel: values.channel || '',
    recipient: values.recipient || '',
    keep: Number(values.keep || 7),
    enabled: values.enabled,
  };
}

function formatTaskSchedule(task: ScheduledTask, t: (key: string, options?: Record<string, unknown>) => string) {
  const frequency = task.frequency || task.schedule;
  if (frequency === 'daily' || frequency === 'weekly' || frequency === 'monthly') {
    return `${frequencyLabel(frequency, t)} ${task.at || '08:00'}`;
  }
  const duration = parseDuration(task.every);
  return t('ops.intervalEvery', { value: duration.value, unit: durationUnitLabel(duration.unit, t) });
}

function parseDuration(value: number | string | undefined): { value: number; unit: DurationUnit } {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return minutesToDurationUnit(Math.max(1, Math.round(value / 60_000_000_000)));
  }
  const text = String(value ?? '').trim().toLowerCase();
  const match = text.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/);
  if (!match) {
    return { value: 24, unit: 'h' };
  }
  const amount = Number(match[1]);
  const unit = match[2];
  if (unit === 'd') return { value: Math.max(1, Math.round(amount)), unit: 'd' };
  if (unit === 'h') return { value: Math.max(1, Math.round(amount)), unit: 'h' };
  if (unit === 'm') return { value: Math.max(1, Math.round(amount)), unit: 'm' };
  if (unit === 's') return minutesToDurationUnit(Math.max(1, Math.round(amount / 60)));
  if (unit === 'ms') return minutesToDurationUnit(Math.max(1, Math.round(amount / 60_000)));
  return { value: 24, unit: 'h' };
}

function minutesToDurationUnit(minutes: number): { value: number; unit: DurationUnit } {
  if (minutes % (24 * 60) === 0) {
    return { value: Math.max(1, minutes / (24 * 60)), unit: 'd' };
  }
  if (minutes % 60 === 0) {
    return { value: Math.max(1, minutes / 60), unit: 'h' };
  }
  return { value: Math.max(1, minutes), unit: 'm' };
}

function durationToString(value: number | undefined, unit: DurationUnit | undefined) {
  const amount = Math.max(1, Number(value || 1));
  switch (unit) {
    case 'd':
      return `${amount}d`;
    case 'h':
      return `${amount}h`;
    case 'm':
    default:
      return `${amount}m`;
  }
}

function newScheduledTask(): ScheduledTask {
  const stamp = Date.now();
  return {
    id: `cleanup-${stamp}`,
    name: 'Log cleanup',
    type: 'cleanup',
    schedule: 'interval',
    every: '24h',
    frequency: 'interval',
    at: '08:00',
    target: './logs',
    channel: '',
    recipient: '',
    period: '',
    format: '',
    keep: 14,
    enabled: true,
  };
}

function durationUnitLabel(unit: DurationUnit, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (unit) {
    case 'd':
      return t('ops.days');
    case 'h':
      return t('ops.hours');
    case 'm':
    default:
      return t('ops.minutes');
  }
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
          <dd>{formatTaskSchedule(task, t)}</dd>
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
