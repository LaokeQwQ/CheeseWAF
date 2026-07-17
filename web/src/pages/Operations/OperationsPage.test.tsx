import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScheduledTask } from '../../types/api';

const apiMocks = vi.hoisted(() => ({
  cleanupStorage: vi.fn(),
  exportBackup: vi.fn(),
  fetchStorageStats: vi.fn(),
  fetchTasks: vi.fn(),
  updateTasks: vi.fn(),
}));

const messageMocks = vi.hoisted(() => ({
  error: vi.fn(),
  success: vi.fn(),
  warning: vi.fn(),
}));

vi.mock('@arco-design/web-react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@arco-design/web-react')>();
  return { ...actual, Message: messageMocks };
});

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
    expect(document.querySelector('.ops-report-panel .arco-switch-checked')).toBeTruthy();

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

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith('task save failed'));
    expect(screen.getByRole('dialog')).toBeTruthy();
    expect(nameInput.value).toBe('Edited cleanup draft');
  });

  it('reports backup failures instead of failing silently', async () => {
    apiMocks.exportBackup.mockRejectedValue(new APIRequestError('backup failed', 'BACKUP_FAILED', 500));
    renderOperations();

    fireEvent.click(screen.getByRole('button', { name: 'ops.backup' }));

    await waitFor(() => expect(messageMocks.error).toHaveBeenCalledWith('backup failed'));
    expect(messageMocks.success).not.toHaveBeenCalled();
  });
});
