import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  createRule: vi.fn(),
  fetchRules: vi.fn(),
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

  it('blocks create when pattern is empty', async () => {
    renderPage();
    await screen.findByText('Block admin');
    fireEvent.click(screen.getByRole('button', { name: 'rules.create' }));
    fireEvent.change(screen.getByPlaceholderText('rules.namePlaceholder'), { target: { value: 'empty' } });
    fireEvent.click(screen.getByRole('button', { name: 'common.save' }));
    await waitFor(() => expect(messageMocks.warning).toHaveBeenCalled());
    expect(apiMocks.createRule).not.toHaveBeenCalled();
  });
});
