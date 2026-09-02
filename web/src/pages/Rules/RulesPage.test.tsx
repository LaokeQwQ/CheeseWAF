import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  createRule: vi.fn(),
  exportCustomRules: vi.fn(),
  fetchRules: vi.fn(),
  fetchRulesExample: vi.fn(),
  fetchSites: vi.fn(),
  importCustomRules: vi.fn(),
  updateRule: vi.fn(),
  deleteRule: vi.fn(),
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
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, ...apiMocks };
});

import RulesPage from './RulesPage';

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RulesPage />
    </QueryClientProvider>,
  );
  return client;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal('URL', {
    createObjectURL: vi.fn(() => 'blob:custom-rules'),
    revokeObjectURL: vi.fn(),
  });
  apiMocks.fetchSites.mockResolvedValue([{ id: 'default', name: 'default' }]);
  apiMocks.fetchRules.mockResolvedValue([
    {
      id: 'rule-1',
      name: 'Block admin',
      pattern: '^/admin',
      location: 'uri',
      action: 'block',
      severity: 'high',
      priority: 50,
      enabled: true,
    },
  ]);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('RulesPage', () => {
  it('loads and renders existing rules', async () => {
    renderPage();
    expect(await screen.findByText('Block admin')).toBeTruthy();
    expect(screen.getByText('^/admin')).toBeTruthy();
  });

  it('shows load failure with retry', async () => {
    apiMocks.fetchRules.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce([]);
    renderPage();
    expect(await screen.findByText('rules.loadFailed')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));
    await waitFor(() => expect(apiMocks.fetchRules).toHaveBeenCalledTimes(2));
  });

  it('creates a rule after template selection and valid draft', async () => {
    apiMocks.createRule.mockResolvedValue({ id: 'rule-2' });
    const client = renderPage();
    const invalidate = vi.spyOn(client, 'invalidateQueries');
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'rules.create' }));
    // Apply SQLi template
    fireEvent.click(await screen.findByRole('button', { name: 'rules.templateSQLi' }));
    fireEvent.change(screen.getByPlaceholderText('rules.namePlaceholder'), { target: { value: 'SQLi guard' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(apiMocks.createRule).toHaveBeenCalled());
    expect(apiMocks.createRule.mock.calls[0]?.[0]).toEqual(expect.objectContaining({
      name: 'SQLi guard',
      action: 'block',
      severity: 'medium',
    }));
    expect(String(apiMocks.createRule.mock.calls[0]?.[0].pattern)).toMatch(/union/i);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['rules'] });
  });

  it('toggles an existing rule through the update API', async () => {
    apiMocks.updateRule.mockResolvedValue({ id: 'rule-1', enabled: false });
    renderPage();
    await screen.findByText('Block admin');
    const toggle = screen.getByRole('switch', { name: 'common.enabled' });
    fireEvent.click(toggle);
    await waitFor(() => expect(apiMocks.updateRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({
      enabled: false,
      site_id: 'default',
    })));
  });

  it('opens an existing rule for editing and deletes it from the table', async () => {
    apiMocks.updateRule.mockResolvedValue({ id: 'rule-1' });
    apiMocks.deleteRule.mockResolvedValue({ deleted: true });
    const client = renderPage();
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'common.edit Block admin' }));
    expect(screen.getByDisplayValue('Block admin')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(apiMocks.updateRule).toHaveBeenCalledWith('rule-1', expect.objectContaining({ name: 'Block admin' })));
    // Deleting is destructive, so the row button only opens a confirmation step.
    fireEvent.click(screen.getByRole('button', { name: 'common.delete Block admin' }));
    expect(apiMocks.deleteRule).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole('button', { name: 'common.delete' }));
    await waitFor(() => expect(apiMocks.deleteRule).toHaveBeenCalledWith('rule-1'));
    expect(client).toBeTruthy();
  });

  it('opens import dialog with example download buttons', async () => {
    apiMocks.fetchRulesExample.mockResolvedValue(new Blob(['custom_rules: []']));
    renderPage();
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'rules.import' }));
    expect(await screen.findByText('rules.importTitle')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'rules.downloadExampleYaml' }));
    await waitFor(() => expect(apiMocks.fetchRulesExample).toHaveBeenCalledWith('yaml'));
    expect(screen.getByText('Block admin')).toBeTruthy();
  });

  it('keeps existing rules when import fails', async () => {
    apiMocks.importCustomRules.mockRejectedValueOnce(new Error('bad rules'));
    renderPage();
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'rules.import' }));
    const fileInput = await screen.findByLabelText('rules.importFile');
    const file = new File(['custom_rules:\n  - id: x\n    pattern: "("\n'], 'bad.yaml', { type: 'application/yaml' });
    fireEvent.change(fileInput, { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: 'rules.importConfirm' }));
    await waitFor(() => expect(apiMocks.importCustomRules).toHaveBeenCalled());
    expect(screen.getByText('Block admin')).toBeTruthy();
    expect(toastMocks.error).toHaveBeenCalled();
  });

  it('blocks create when pattern is empty', async () => {
    renderPage();
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'rules.create' }));
    fireEvent.change(screen.getByPlaceholderText('rules.namePlaceholder'), { target: { value: 'empty' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(toastMocks.warning).toHaveBeenCalled());
    expect(apiMocks.createRule).not.toHaveBeenCalled();
  });
});
