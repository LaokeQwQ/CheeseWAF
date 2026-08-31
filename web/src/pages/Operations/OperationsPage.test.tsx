import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScheduledTask, ScheduledTaskHistoryEntry } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  cleanupStorage: vi.fn(),
  exportBackup: vi.fn(),
  fetchStorageStats: vi.fn(),
  fetchTaskHistory: vi.fn(),
  fetchTasks: vi.fn(),
  updateTasks: vi.fn(),
}));

const toastMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('sonner', () => ({
  toast: Object.assign(vi.fn(), toastMocks),
  Toaster: () => null,
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, options?: Record<string, unknown>) => options ? `${key}:${JSON.stringify(options)}` : key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import { APIRequestError } from '../../api/client';
import OperationsPage from './OperationsPage';

const cleanupTask: ScheduledTask = {
  id: 'cleanup-1',
  name: 'Cleanup fixture',
  type: 'cleanup',
  schedule: 'interval',
  frequency: 'interval',
  every: '12h',
  at: '08:00',
  target: './logs',
  channel: '',
  recipient: '',
  period: '',
  format: '',
  keep: 14,
  enabled: true,
};

const reportTask: ScheduledTask = {
  id: 'security-daily-report',
  name: 'Security report fixture',
  type: 'security_report',
  schedule: 'weekly',
  frequency: 'weekly',
  every: '7d',
  at: '21:45',
  target: '',
  channel: 'webhook',
  recipient: 'https://reports.example.test/hook',
  period: 'weekly',
  format: 'markdown',
  keep: 7,
  enabled: true,
};

function renderOperations() {
  const client = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  });
  render(
    <QueryClientProvider client={client}>
      <OperationsPage />
    </QueryClientProvider>,
  );
  return client;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function historyPanel() {
  const panel = document.querySelector('.ops-history-panel');
  if (!panel) {
    throw new Error('Task history panel was not rendered');
  }
  return panel as HTMLElement;
}

function desktopTaskRow(name: string) {
  const match = screen.getAllByText(name).find((element) => element.closest('tr'));
  const row = match?.closest('tr');
  if (!row) {
    throw new Error('Task table row was not rendered');
  }
  return row;
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchTasks.mockResolvedValue([structuredClone(cleanupTask), structuredClone(reportTask)]);
  apiMocks.fetchStorageStats.mockResolvedValue({ data: 1024, logs: 2048 });
  apiMocks.cleanupStorage.mockResolvedValue({ removed: 1, scanned: 2 });
  apiMocks.exportBackup.mockResolvedValue({ path: './backup.tar.gz' });
  apiMocks.fetchTaskHistory.mockResolvedValue([]);
  apiMocks.updateTasks.mockImplementation(async (tasks: ScheduledTask[]) => tasks);
});

afterEach(() => cleanup());

describe('OperationsPage query states', () => {
  it('does not expose task writes while the task request is pending', async () => {
    const pending = deferred<ScheduledTask[]>();
    apiMocks.fetchTasks.mockReturnValue(pending.promise);
    renderOperations();

    const addButton = screen.getByRole('button', { name: 'common.add' }) as HTMLButtonElement;
    expect(addButton.disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'common.save' })).toBeNull();
    expect(apiMocks.updateTasks).not.toHaveBeenCalled();

    pending.resolve([]);
    expect(await screen.findByText('common.noData')).toBeTruthy();
  });

  it('shows a retryable error instead of a writable empty task list', async () => {
    apiMocks.fetchTasks.mockRejectedValue(new APIRequestError('task list unavailable', 'TASK_READ_FAILED', 503));
    renderOperations();

    const alerts = await screen.findAllByRole('alert');
    expect(alerts.some((alert) => alert.textContent?.includes('task list unavailable'))).toBe(true);
    expect((screen.getByRole('button', { name: 'common.add' }) as HTMLButtonElement).disabled).toBe(true);
    expect(apiMocks.updateTasks).not.toHaveBeenCalled();
  });

  it('mounts the report form with values from an asynchronously loaded task', async () => {
    const pending = deferred<ScheduledTask[]>();
    apiMocks.fetchTasks.mockReturnValue(pending.promise);
    renderOperations();
    pending.resolve([structuredClone(cleanupTask), structuredClone(reportTask)]);

    expect(await screen.findByDisplayValue('21:45')).toBeTruthy();
    expect(screen.getByDisplayValue('https://reports.example.test/hook')).toBeTruthy();
    const reportPanel = document.querySelector('.ops-report-panel');
    expect(reportPanel?.querySelector('[role="switch"][data-state="checked"]')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(apiMocks.updateTasks).toHaveBeenCalledTimes(1));
    expect(apiMocks.updateTasks.mock.calls[0]?.[0]).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: 'security-daily-report',
        at: '21:45',
        channel: 'webhook',
        frequency: 'weekly',
        recipient: 'https://reports.example.test/hook',
      }),
    ]));
  });
});

describe('OperationsPage task mutations', () => {
  it('keeps the edit modal and draft open when saving fails', async () => {
    apiMocks.updateTasks.mockRejectedValue(new APIRequestError('task save failed', 'TASK_WRITE_FAILED', 500));
    renderOperations();
    await screen.findAllByText('Cleanup fixture');
    fireEvent.click(within(desktopTaskRow('Cleanup fixture')).getByRole('button', { name: 'common.edit' }));

    const dialog = await screen.findByRole('dialog');
    const nameInput = within(dialog).getByDisplayValue('Cleanup fixture') as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Edited cleanup draft' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'common.save' }));

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('task save failed'));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(nameInput.value).toBe('Edited cleanup draft');
  });

  it('reports backup failures instead of failing silently', async () => {
    apiMocks.exportBackup.mockRejectedValue(new APIRequestError('backup failed', 'BACKUP_FAILED', 500));
    renderOperations();

    fireEvent.click(screen.getByRole('button', { name: 'ops.backup' }));

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('backup failed'));
    expect(toastMocks.success).not.toHaveBeenCalled();
  });
});

describe('OperationsPage task history', () => {
  it('renders execution history with task names, readable times, durations and statuses', async () => {
    const entries: ScheduledTaskHistoryEntry[] = [
      { task_id: 'cleanup-1', started_at: '2026-08-29T02:03:04Z', duration: 1_200_000_000, success: true },
      {
        task_id: 'security-daily-report',
        started_at: '2026-08-29T03:04:05Z',
        duration: 340_000_000,
        success: false,
        error: 'disk quota exceeded',
      },
      { task_id: 'deleted-task', started_at: '2026-08-29T04:00:00Z', duration: 65_000_000_000, success: true },
    ];
    apiMocks.fetchTaskHistory.mockResolvedValue(entries);
    renderOperations();

    await waitFor(() => expect(document.querySelector('.ops-history-table')).toBeTruthy());
    const panel = historyPanel();

    // task_id is resolved to the task name when the task still exists, and falls back to the raw id
    expect(within(panel).getByText('Cleanup fixture')).toBeTruthy();
    expect(within(panel).getByText('Security report fixture')).toBeTruthy();
    expect(within(panel).getByText('deleted-task')).toBeTruthy();

    // nanoseconds are converted instead of being shown raw
    expect(within(panel).getByText('1.2s')).toBeTruthy();
    expect(within(panel).getByText('340ms')).toBeTruthy();
    expect(within(panel).getByText('1m5s')).toBeTruthy();
    expect(panel.textContent).not.toContain('1200000000');

    expect(within(panel).getAllByText('ops.historySuccess')).toHaveLength(2);
    expect(within(panel).getAllByText('ops.historyFailed')).toHaveLength(1);
    expect(within(panel).getByText('disk quota exceeded')).toBeTruthy();

    expect(panel.querySelector('time[datetime="2026-08-29T02:03:04Z"]')).toBeTruthy();
    expect(panel.querySelector('.ops-history-row-failed')).toBeTruthy();
  });

  it('formats sub-second and hour-scale durations', async () => {
    apiMocks.fetchTaskHistory.mockResolvedValue([
      { task_id: 'cleanup-1', started_at: '2026-08-29T02:03:04Z', duration: 900, success: true },
      { task_id: 'cleanup-1', started_at: '2026-08-29T02:03:05Z', duration: 12_000, success: true },
      { task_id: 'cleanup-1', started_at: '2026-08-29T02:03:06Z', duration: 3_900_000_000_000, success: true },
    ] as ScheduledTaskHistoryEntry[]);
    renderOperations();

    await waitFor(() => expect(document.querySelector('.ops-history-table')).toBeTruthy());
    const panel = historyPanel();
    expect(within(panel).getByText('900ns')).toBeTruthy();
    expect(within(panel).getByText('12µs')).toBeTruthy();
    expect(within(panel).getByText('1h5m')).toBeTruthy();
  });

  it('shows a friendly empty state when the scheduler has no history yet', async () => {
    apiMocks.fetchTaskHistory.mockResolvedValue([]);
    renderOperations();

    expect(await screen.findByText('ops.historyEmpty')).toBeTruthy();
    expect(document.querySelector('.ops-history-table')).toBeNull();
  });

  it('surfaces a retryable error when history cannot be loaded', async () => {
    apiMocks.fetchTaskHistory.mockRejectedValue(new APIRequestError('history unavailable', 'TASK_HISTORY_FAILED', 500));
    renderOperations();

    const alerts = await screen.findAllByRole('alert');
    expect(alerts.some((alert) => alert.textContent?.includes('history unavailable'))).toBe(true);
    expect(document.querySelector('.ops-history-table')).toBeNull();
    expect(screen.queryByText('ops.historyEmpty')).toBeNull();
  });
});
