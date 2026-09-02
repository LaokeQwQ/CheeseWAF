import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Archive, Database, Edit3, History, Plus, RotateCcw, Trash2 } from 'lucide-react';
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Empty,
  Input,
  Label,
  Progress,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import {
  cleanupStorage,
  exportBackup,
  fetchStorageStats,
  fetchTaskHistory,
  fetchTasks,
  updateTasks,
} from '../../api/client';
import type { ScheduledTask, ScheduledTaskHistoryEntry } from '../../types/api';
import './OperationsPage.css';

type DurationUnit = 'm' | 'h' | 'd';

type TaskFormValues = ScheduledTask & {
  everyValue?: number;
  everyUnit?: DurationUnit;
};

const durationUnitOptions: DurationUnit[] = ['m', 'h', 'd'];
const taskTypeOptions = ['cleanup', 'backup', 'security_report', 'ai_self_learning'];
const taskFrequencyOptions = ['interval', 'daily', 'weekly', 'monthly'];

export default function OperationsPage() {
  const { t, i18n } = useTranslation();
  const locale = i18n?.resolvedLanguage;
  const queryClient = useQueryClient();
  const tasksQuery = useQuery({ queryKey: ['tasks'], queryFn: fetchTasks, retry: false });
  const storageQuery = useQuery({ queryKey: ['storage'], queryFn: fetchStorageStats, retry: false });
  const historyQuery = useQuery({ queryKey: ['taskHistory'], queryFn: fetchTaskHistory, retry: false });
  const tasks = tasksQuery.data ?? [];
  const storage = storageQuery.data;
  const history = historyQuery.data ?? [];
  const taskNames = useMemo(
    () => new Map((tasksQuery.data ?? []).map((task) => [task.id, task.name])),
    [tasksQuery.data],
  );
  const cleanup = useMutation({
    mutationFn: cleanupStorage,
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['storage'] });
      toast.success(t('ops.cleanupDone', { removed: result.removed, scanned: result.scanned }));
    },
    onError: (error) => toast.error(error.message),
  });
  const backup = useMutation({
    mutationFn: exportBackup,
    onSuccess: (result) => {
      const destination = typeof result.path === 'string' ? `: ${result.path}` : '';
      toast.success(`${t('ops.backup')}${destination}`);
    },
    onError: (error) => toast.error(error.message),
  });
  const tasksMutation = useMutation({
    mutationFn: updateTasks,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['tasks'] });
      toast.success(t('ops.tasksSaved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const dataSize = storage?.data ?? 0;
  const logSize = storage?.logs ?? 0;
  const total = Math.max(dataSize + logSize, 1);
  const dataShare = Math.round((dataSize / total) * 100);
  const logShare = Math.round((logSize / total) * 100);
  const reportTask = tasks.find((task) => task.type === 'security_report') ?? defaultReportTask(t);
  const [editingTask, setEditingTask] = useState<ScheduledTask | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [reportForm, setReportForm] = useState({
    enabled: reportTask.enabled,
    frequency: reportTask.frequency ?? 'daily',
    at: reportTask.at ?? '08:00',
    channel: reportTask.channel ?? 'file',
    recipient: reportTask.recipient ?? './data/reports',
    period: reportTask.period ?? 'daily',
  });
  const [taskForm, setTaskForm] = useState<TaskFormValues | null>(null);

  useEffect(() => {
    setReportForm({
      enabled: reportTask.enabled,
      frequency: reportTask.frequency ?? 'daily',
      at: reportTask.at ?? '08:00',
      channel: reportTask.channel ?? 'file',
      recipient: reportTask.recipient ?? './data/reports',
      period: reportTask.period ?? 'daily',
    });
  }, [reportTask.id, reportTask.enabled, reportTask.frequency, reportTask.at, reportTask.channel, reportTask.recipient, reportTask.period]);

  useEffect(() => {
    if (editingTask) {
      setTaskForm(taskToFormValues(editingTask));
    } else {
      setTaskForm(null);
    }
  }, [editingTask]);

  const busyTaskId = tasksMutation.isPending
    ? (() => {
        const next = tasksMutation.variables ?? [];
        if (!Array.isArray(next)) return null;
        if (next.length !== tasks.length) {
          const deleted = tasks.find((task) => !next.some((item) => item.id === task.id));
          if (deleted) return deleted.id;
          const added = next.find((task) => !tasks.some((item) => item.id === task.id));
          if (added) return added.id;
        }
        const changed = next.find((task) => {
          const prev = tasks.find((item) => item.id === task.id);
          return prev && JSON.stringify(prev) !== JSON.stringify(task);
        });
        return changed?.id ?? null;
      })()
    : null;
  const persistTasks = (next: ScheduledTask[], onSuccess?: () => void) => tasksMutation.mutate(next, { onSuccess });
  const patchTask = async (id: string, patch: Partial<ScheduledTask>) => {
    const latest = queryClient.getQueryData<ScheduledTask[]>(['tasks']) ?? tasks;
    const next = latest.map((task) => (task.id === id ? { ...task, ...patch } : task));
    persistTasks(next);
  };
  const saveTask = (task: ScheduledTask, patch: Partial<ScheduledTask>, onSuccess?: () => void) => {
    const latest = queryClient.getQueryData<ScheduledTask[]>(['tasks']) ?? tasks;
    const nextTask = { ...task, ...patch };
    const exists = latest.some((item) => item.id === task.id);
    persistTasks(exists ? latest.map((item) => (item.id === task.id ? nextTask : item)) : [...latest, nextTask], onSuccess);
  };
  const removeTask = (id: string) => setDeleteTarget(id);
  const confirmRemoveTask = () => {
    if (!deleteTarget) return;
    const id = deleteTarget;
    setDeleteTarget(null);
    const latest = queryClient.getQueryData<ScheduledTask[]>(['tasks']) ?? tasks;
    persistTasks(latest.filter((task) => task.id !== id));
  };

  const submitReport = (event: FormEvent) => {
    event.preventDefault();
    const latest = queryClient.getQueryData<ScheduledTask[]>(['tasks']) ?? tasks;
    tasksMutation.mutate(upsertReportTask(latest, { ...reportTask, ...reportForm }, t));
  };

  const submitTaskForm = (event: FormEvent) => {
    event.preventDefault();
    if (!editingTask || !taskForm) return;
    saveTask(editingTask, normalizeTaskFormValues(editingTask, taskForm), () => setEditingTask(null));
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ops.title')}</h1>
          <p>{t('ops.subtitle')}</p>
        </div>
        <Button onClick={() => backup.mutate()} loading={backup.isPending}>
          <Archive size={16} />
          {t('ops.backup')}
        </Button>
      </header>

      <div className="ops-grid">
        <section className="panel storage-ops-panel">
          <div className="panel-heading"><h2><Database size={16} /> {t('ops.storage')}</h2></div>
          {storageQuery.isLoading ? <div className="skeleton-list" /> : storageQuery.isError ? (
            <QueryError error={storageQuery.error} onRetry={() => storageQuery.refetch()} retryLabel={t('common.retry')} fallbackMessage={t('common.noData')} />
          ) : (
            <>
              <div className="resource-stack">
                <div title={t('ops.shareHint')}>
                  <Database size={18} /><span>{t('ops.dataDir')}</span>
                  <Progress value={dataShare} />
                  <code className="resource-value">{formatBytes(dataSize)}</code>
                </div>
                <div title={t('ops.shareHint')}>
                  <Archive size={18} /><span>{t('ops.logsDir')}</span>
                  <Progress value={logShare} />
                  <code className="resource-value">{formatBytes(logSize)}</code>
                </div>
              </div>
              <div className="panel-actions">
                <Button variant="outline" onClick={() => cleanup.mutate()} loading={cleanup.isPending}>
                  <RotateCcw size={16} />
                  {t('ops.cleanup')}
                </Button>
              </div>
            </>
          )}
        </section>
        <section className="panel ops-report-panel">
          <div className="panel-heading"><h2>{t('ops.report')}</h2></div>
          {tasksQuery.isLoading ? <div className="skeleton-list" /> : tasksQuery.isError ? (
            <QueryError error={tasksQuery.error} onRetry={() => tasksQuery.refetch()} retryLabel={t('common.retry')} fallbackMessage={t('common.noData')} />
          ) : (
            <form className="ops-report-form" onSubmit={submitReport}>
              <div className="field-stack">
                <Label>{t('ops.report')}</Label>
                <Switch
                  checked={reportForm.enabled}
                  onCheckedChange={(enabled) => setReportForm((c) => ({ ...c, enabled }))}
                />
              </div>
              <div className="field-stack">
                <Label>{t('ops.every')}</Label>
                <Select
                  value={reportForm.frequency}
                  onValueChange={(frequency) => setReportForm((c) => ({ ...c, frequency }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">{t('ops.daily')}</SelectItem>
                    <SelectItem value="weekly">{t('ops.weekly')}</SelectItem>
                    <SelectItem value="monthly">{t('ops.monthly')}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="field-stack">
                <Label htmlFor="ops-report-at">{t('ops.at')}</Label>
                <Input
                  id="ops-report-at"
                  placeholder="08:00"
                  value={reportForm.at}
                  required
                  pattern="(?:[01]\d|2[0-3]):[0-5]\d"
                  title="HH:mm"
                  onChange={(e) => setReportForm((c) => ({ ...c, at: e.target.value }))}
                />
              </div>
              <div className="field-stack">
                <Label>{t('ops.channel')}</Label>
                <Select
                  value={reportForm.channel}
                  onValueChange={(channel) => setReportForm((c) => ({ ...c, channel }))}
                >
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="file">{t('ops.file')}</SelectItem>
                    <SelectItem value="webhook">Webhook</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="field-stack ops-report-recipient">
                <Label htmlFor="ops-report-recipient">{t('ops.recipient')}</Label>
                <Input
                  id="ops-report-recipient"
                  value={reportForm.recipient}
                  onChange={(e) => setReportForm((c) => ({ ...c, recipient: e.target.value }))}
                />
              </div>
              <div className="ops-report-actions">
                <Button type="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
              </div>
            </form>
          )}
        </section>
      </div>

      <section className="table-panel ops-task-panel">
        <div className="panel-heading">
          <h2>{t('ops.taskList')}</h2>
          <Button
            variant="outline"
            disabled={tasksQuery.isLoading || tasksQuery.isError || tasksMutation.isPending}
            onClick={() => setEditingTask(newScheduledTask(t))}
          >
            <Plus size={15} />
            {t('common.add')}
          </Button>
        </div>
        {tasksQuery.isLoading ? <div className="skeleton-list" /> : tasksQuery.isError ? (
          <QueryError error={tasksQuery.error} onRetry={() => tasksQuery.refetch()} retryLabel={t('common.retry')} fallbackMessage={t('common.noData')} />
        ) : tasks.length === 0 ? <Empty description={t('common.noData')} /> : (
          <>
            <div className="desktop-table-wrap">
              <Table className="ops-task-table">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">{t('ops.task')}</TableHead>
                    <TableHead className="w-[124px]">{t('ops.type')}</TableHead>
                    <TableHead className="w-[156px]">{t('ops.every')}</TableHead>
                    <TableHead className="w-[242px]">{t('ops.target')}</TableHead>
                    <TableHead className="w-[64px]">{t('rules.enabled')}</TableHead>
                    <TableHead className="w-[200px]">{t('common.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tasks.map((record) => (
                    <TableRow key={record.id}>
                      <TableCell>
                        <span className="ops-task-name" title={record.name}>{record.name}</span>
                      </TableCell>
                      <TableCell>
                        <span className="status-group"><Badge variant="secondary">{taskTypeLabel(record.type, t)}</Badge></span>
                      </TableCell>
                      <TableCell>
                        <span className="ops-task-schedule">{formatTaskSchedule(record, t)}</span>
                      </TableCell>
                      <TableCell>
                        <code className="table-code ops-task-target" title={record.target || '-'}>{record.target || '-'}</code>
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={record.enabled}
                          disabled={busyTaskId === record.id}
                          onCheckedChange={(next) => void patchTask(record.id, { enabled: next })}
                        />
                      </TableCell>
                      <TableCell>
                        <span className="table-action-group ops-task-actions">
                          <Button size="sm" variant="outline" onClick={() => setEditingTask(record)}>
                            <Edit3 size={13} />
                            {t('common.edit')}
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            disabled={tasksMutation.isPending}
                            loading={busyTaskId === record.id}
                            onClick={() => removeTask(record.id)}
                          >
                            <Trash2 size={13} />
                            {t('common.delete')}
                          </Button>
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="mobile-card-list ops-task-cards">
              {tasks.map((task) => (
                <TaskCard
                  key={task.id}
                  task={task}
                  busy={busyTaskId === task.id}
                  onToggle={(enabled) => void patchTask(task.id, { enabled })}
                  onEdit={() => setEditingTask(task)}
                  onDelete={() => removeTask(task.id)}
                  t={t}
                />
              ))}
            </div>
          </>
        )}
      </section>

      <section className="table-panel ops-history-panel">
        <div className="panel-heading">
          <h2><History size={16} /> {t('ops.history')}</h2>
        </div>
        {historyQuery.isLoading ? <div className="skeleton-list" /> : historyQuery.isError ? (
          <QueryError error={historyQuery.error} onRetry={() => historyQuery.refetch()} retryLabel={t('common.retry')} fallbackMessage={t('common.loadFailed')} />
        ) : history.length === 0 ? <Empty description={t('ops.historyEmpty')} /> : (
          <div className="desktop-table-wrap">
            <Table className="ops-history-table">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('ops.task')}</TableHead>
                  <TableHead>{t('ops.historyStarted')}</TableHead>
                  <TableHead>{t('ops.historyDuration')}</TableHead>
                  <TableHead>{t('common.status')}</TableHead>
                  <TableHead>{t('ops.historyError')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history.map((entry, index) => (
                  <HistoryRow
                    key={`${entry.task_id}-${entry.started_at}-${index}`}
                    entry={entry}
                    taskName={taskNames.get(entry.task_id) ?? entry.task_id}
                    locale={locale}
                    t={t}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <Dialog open={Boolean(editingTask)} onOpenChange={(open) => { if (!open) setEditingTask(null); }}>
        <DialogContent className="ops-task-modal max-w-2xl">
          <DialogHeader>
            <DialogTitle>{t('ops.editTask')}</DialogTitle>
          </DialogHeader>
          {editingTask && taskForm && (
            <form className="ops-task-form" onSubmit={submitTaskForm}>
              <div className="ops-task-form-grid">
                <div className="field-stack">
                  <Label htmlFor="task-name">{t('ops.task')}</Label>
                  <Input
                    id="task-name"
                    required
                    placeholder={t('ops.taskNamePlaceholder')}
                    value={taskForm.name}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, name: e.target.value } : c))}
                  />
                </div>
                <div className="field-stack">
                  <Label>{t('ops.type')}</Label>
                  <Select
                    value={taskForm.type || 'cleanup'}
                    onValueChange={(type) => setTaskForm((c) => (c ? { ...c, type } : c))}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {taskTypeOptions.map((type) => (
                        <SelectItem key={type} value={type}>{taskTypeLabel(type, t)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="field-stack">
                  <Label>{t('ops.frequency')}</Label>
                  <Select
                    value={taskForm.frequency || 'interval'}
                    onValueChange={(frequency) => setTaskForm((c) => (c ? { ...c, frequency } : c))}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {taskFrequencyOptions.map((frequency) => (
                        <SelectItem key={frequency} value={frequency}>{frequencyLabel(frequency, t)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="field-stack">
                  <Label htmlFor="task-at">{t('ops.at')}</Label>
                  <Input
                    id="task-at"
                    placeholder="08:00"
                    required
                    pattern="(?:[01]\d|2[0-3]):[0-5]\d"
                    title="HH:mm"
                    value={taskForm.at || ''}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, at: e.target.value } : c))}
                  />
                </div>
                <div className="field-stack">
                  <Label htmlFor="task-every-value">{t('ops.everyValue')}</Label>
                  <Input
                    id="task-every-value"
                    type="number"
                    min={1}
                    max={31 * 24 * 60}
                    value={taskForm.everyValue ?? 1}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, everyValue: Number(e.target.value || 1) } : c))}
                  />
                </div>
                <div className="field-stack">
                  <Label>{t('ops.everyUnit')}</Label>
                  <Select
                    value={taskForm.everyUnit || 'h'}
                    onValueChange={(everyUnit) => setTaskForm((c) => (c ? { ...c, everyUnit: everyUnit as DurationUnit } : c))}
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {durationUnitOptions.map((unit) => (
                        <SelectItem key={unit} value={unit}>{durationUnitLabel(unit, t)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="field-stack">
                  <Label htmlFor="task-target">{t('ops.target')}</Label>
                  <Input
                    id="task-target"
                    placeholder="./logs"
                    value={taskForm.target || ''}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, target: e.target.value } : c))}
                  />
                </div>
                <div className="field-stack">
                  <Label htmlFor="task-keep">{t('ops.keep')}</Label>
                  <Input
                    id="task-keep"
                    type="number"
                    min={1}
                    max={365}
                    value={taskForm.keep ?? 7}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, keep: Number(e.target.value || 7) } : c))}
                  />
                </div>
                <div className="field-stack">
                  <Label>{t('ops.channel')}</Label>
                  <Select
                    value={taskForm.channel || '__none__'}
                    onValueChange={(channel) => setTaskForm((c) => (c ? { ...c, channel: channel === '__none__' ? '' : channel } : c))}
                  >
                    <SelectTrigger><SelectValue placeholder={t('ops.channel')} /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__none__">—</SelectItem>
                      <SelectItem value="file">{t('ops.file')}</SelectItem>
                      <SelectItem value="webhook">Webhook</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="field-stack">
                  <Label htmlFor="task-recipient">{t('ops.recipient')}</Label>
                  <Input
                    id="task-recipient"
                    placeholder="./data/reports"
                    value={taskForm.recipient || ''}
                    onChange={(e) => setTaskForm((c) => (c ? { ...c, recipient: e.target.value } : c))}
                  />
                </div>
              </div>
              <div className="field-stack">
                <Label>{t('rules.enabled')}</Label>
                <Switch
                  checked={Boolean(taskForm.enabled)}
                  onCheckedChange={(enabled) => setTaskForm((c) => (c ? { ...c, enabled } : c))}
                />
              </div>
              <DialogFooter className="form-action-row">
                <Button type="button" variant="outline" onClick={() => setEditingTask(null)} disabled={tasksMutation.isPending}>
                  {t('common.close')}
                </Button>
                <Button type="submit" loading={tasksMutation.isPending}>{t('common.save')}</Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(deleteTarget)} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('common.confirmDeleteTitle')}</DialogTitle>
            <DialogDescription>{t('common.confirmDeleteEntry')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDeleteTarget(null)}>{t('common.cancel')}</Button>
            <Button type="button" variant="destructive" onClick={confirmRemoveTask}>{t('common.delete')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

type Translate = (key: string, options?: Record<string, unknown>) => string;

function defaultReportTask(t: Translate): ScheduledTask {
  return {
    id: 'security-daily-report',
    name: t('ops.defaultDailyReport'),
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
}

function upsertReportTask(tasks: ScheduledTask[], next: ScheduledTask, t: Translate) {
  const base = defaultReportTask(t);
  const normalized = {
    ...base,
    ...next,
    period: next.period ?? next.frequency ?? 'daily',
    format: next.format ?? 'markdown',
    name: next.name || t('ops.defaultSecurityReport'),
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
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function taskTypeLabel(type: string, t: (key: string, options?: Record<string, unknown>) => string) {
  if (type === 'security_report') return t('ops.report');
  if (type === 'cleanup') return t('ops.cleanup');
  if (type === 'backup') return t('ops.backupTask');
  if (type === 'ai_self_learning' || type === 'self_learning_rules') return t('ops.aiSelfLearning');
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

function newScheduledTask(t: Translate): ScheduledTask {
  const stamp = Date.now();
  return {
    id: `cleanup-${stamp}`,
    name: t('ops.defaultLogCleanup'),
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

function HistoryRow({
  entry,
  taskName,
  locale,
  t,
}: {
  entry: ScheduledTaskHistoryEntry;
  taskName: string;
  locale?: string;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <TableRow className={entry.success ? undefined : 'ops-history-row-failed'}>
      <TableCell>
        <span className="ops-history-task" title={taskName}>{taskName}</span>
      </TableCell>
      <TableCell>
        <time className="ops-history-time" dateTime={entry.started_at}>{formatHistoryTime(entry.started_at, locale)}</time>
      </TableCell>
      <TableCell>
        <code className="table-code">{formatNanoseconds(entry.duration)}</code>
      </TableCell>
      <TableCell>
        <Badge variant={entry.success ? 'success' : 'destructive'}>
          {entry.success ? t('ops.historySuccess') : t('ops.historyFailed')}
        </Badge>
      </TableCell>
      <TableCell>
        {entry.error ? <span className="ops-history-error" title={entry.error}>{entry.error}</span> : <span>-</span>}
      </TableCell>
    </TableRow>
  );
}

/** Go time.Duration arrives as raw nanoseconds; render it Go-style (e.g. `340ms`, `1.2s`, `2m5s`). */
function formatNanoseconds(value: number) {
  const ns = Number(value);
  if (!Number.isFinite(ns) || ns < 0) return '-';
  if (ns < 1_000) return `${Math.round(ns)}ns`;
  if (ns < 1_000_000) return `${trimUnit(ns / 1_000)}µs`;
  if (ns < 1_000_000_000) return `${trimUnit(ns / 1_000_000)}ms`;
  const seconds = ns / 1_000_000_000;
  if (seconds < 60) return `${trimUnit(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const restSeconds = trimUnit(seconds % 60);
  if (minutes < 60) {
    return restSeconds === '0' ? `${minutes}m` : `${minutes}m${restSeconds}s`;
  }
  const hours = Math.floor(minutes / 60);
  const restMinutes = minutes % 60;
  return restMinutes === 0 ? `${hours}h` : `${hours}h${restMinutes}m`;
}

function trimUnit(value: number) {
  return String(Number(value.toFixed(1)));
}

function formatHistoryTime(value: string, locale?: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString(locale);
}

function QueryError({
  error,
  fallbackMessage,
  onRetry,
  retryLabel,
}: {
  error: unknown;
  fallbackMessage: string;
  onRetry: () => void;
  retryLabel: string;
}) {
  const message = error instanceof Error && error.message.trim() ? error.message : fallbackMessage;
  return (
    <div className="inline-error ops-query-error" role="alert">
      <span>{message}</span>
      <Button size="sm" variant="outline" onClick={onRetry}>{retryLabel}</Button>
    </div>
  );
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
        <strong className="ops-task-card-title" title={task.name}>{task.name}</strong>
        <Badge variant="secondary">{taskTypeLabel(task.type, t)}</Badge>
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
            <Switch checked={task.enabled} disabled={busy} onCheckedChange={onToggle} />
          </dd>
        </div>
      </dl>
      <div className="mobile-card-actions">
        <Button variant="outline" onClick={onEdit}><Edit3 size={14} />{t('common.edit')}</Button>
        <Button variant="destructive" disabled={busy} onClick={onDelete}>
          <Trash2 size={14} />
          {t('common.delete')}
        </Button>
      </div>
    </article>
  );
}
