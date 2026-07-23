import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const apiMocks = vi.hoisted(() => ({
  fetchClusterStatus: vi.fn(),
  fetchClusterJoinTokens: vi.fn(),
  fetchClusterNodes: vi.fn(),
  fetchClusterDeploymentTasks: vi.fn(),
  fetchClusterAudit: vi.fn(),
  createClusterJoinToken: vi.fn(),
  revokeClusterJoinToken: vi.fn(),
  generateClusterAnsiblePackage: vi.fn(),
  startClusterDeploymentTask: vi.fn(),
  fetchClusterDeploymentTask: vi.fn(),
  rotateClusterNodeCertificate: vi.fn(),
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

import ClusterPage from './ClusterPage';

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <ClusterPage />
    </QueryClientProvider>,
  );
  return client;
}

const statusFixture = {
  enabled: true,
  mode: 'controller',
  product_mode_label: 'Controller',
  can_write_config: true,
  can_receive_traffic: true,
  majority_confirmed: true,
  node_count: 3,
  waf_node_count: 2,
  monitor_node_count: 1,
  consensus_provider: 'raft',
  protection_mode_reason: '',
};

beforeEach(() => {
  vi.clearAllMocks();
  apiMocks.fetchClusterStatus.mockResolvedValue(statusFixture);
  apiMocks.fetchClusterJoinTokens.mockResolvedValue({
    items: [
      {
        id: 'tok-1',
        role: 'waf',
        max_uses: 2,
        used_count: 0,
        expires_at: '2099-01-01T00:00:00Z',
        revoked: false,
        value: '',
      },
    ],
  });
  apiMocks.fetchClusterNodes.mockResolvedValue({
    items: [
      {
        node_id: 'waf-1',
        role: 'waf',
        advertise_addr: '10.0.0.1:9444',
        revoked: false,
        last_heartbeat: '2026-07-01T00:00:00Z',
        runtime_state: 'online',
      },
    ],
  });
  apiMocks.fetchClusterDeploymentTasks.mockResolvedValue({ items: [] });
  apiMocks.fetchClusterAudit.mockResolvedValue({ items: [] });
});

afterEach(() => {
  cleanup();
});

describe('ClusterPage', () => {
  it('loads cluster status, tokens, and nodes with business metrics', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());
    await waitFor(() => expect(apiMocks.fetchClusterJoinTokens).toHaveBeenCalled());
    await waitFor(() => expect(apiMocks.fetchClusterNodes).toHaveBeenCalled());

    expect(await screen.findByText('cluster.title')).toBeTruthy();
    expect(screen.getByText('cluster.allowed')).toBeTruthy();
    expect(screen.getByText('cluster.receiving')).toBeTruthy();
    expect(screen.getByText('cluster.confirmed')).toBeTruthy();
    expect(screen.getByText('cluster.totalNodes')).toBeTruthy();
    expect(screen.getAllByText('3').length).toBeGreaterThan(0);
    expect(screen.getAllByText('tok-1').length).toBeGreaterThan(0);
    expect(screen.getAllByText('waf-1').length).toBeGreaterThan(0);
    expect(screen.getAllByText('10.0.0.1:9444').length).toBeGreaterThan(0);
  });

  it('creates a join token and surfaces the secret once', async () => {
    apiMocks.createClusterJoinToken.mockResolvedValue({
      id: 'tok-new',
      role: 'waf',
      max_uses: 1,
      used_count: 0,
      expires_at: '2099-01-01T00:00:00Z',
      revoked: false,
      value: 'join-secret-value',
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());

    fireEvent.click(screen.getByRole('button', { name: 'cluster.createToken' }));
    await waitFor(() => expect(apiMocks.createClusterJoinToken).toHaveBeenCalledWith({
      role: 'waf',
      ttl: '15m',
      max_uses: 1,
    }));
    expect(await screen.findByText('join-secret-value')).toBeTruthy();
    expect(messageMocks.success).toHaveBeenCalledWith('cluster.tokenCreated');
  });

  it('disables create-token after secret is shown until cleared', async () => {
    apiMocks.createClusterJoinToken.mockResolvedValue({
      id: 'tok-new',
      role: 'waf',
      max_uses: 1,
      used_count: 0,
      expires_at: '2099-01-01T00:00:00Z',
      revoked: false,
      value: 'secret-a',
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());

    const createBtn = () => screen.getByRole('button', { name: 'cluster.createToken' }) as HTMLButtonElement;
    fireEvent.click(createBtn());
    await screen.findByText('secret-a');
    expect(createBtn().disabled || createBtn().className.includes('disabled')).toBe(true);
    expect(apiMocks.createClusterJoinToken).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole('button', { name: 'cluster.clearToken' }));
    await waitFor(() => expect(messageMocks.success).toHaveBeenCalledWith('cluster.tokenCleared'));
    expect(createBtn().disabled).toBe(false);
  });

  it('shows status load failure and allows retry', async () => {
    apiMocks.fetchClusterStatus.mockRejectedValueOnce(new Error('cluster down'));
    renderPage();
    expect(await screen.findByText('cluster.statusLoadFailed')).toBeTruthy();
    expect(screen.getByText('cluster down')).toBeTruthy();

    apiMocks.fetchClusterStatus.mockResolvedValue(statusFixture);
    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('cluster.allowed')).toBeTruthy();
  });

  it('shows standalone mode when cluster is disabled', async () => {
    apiMocks.fetchClusterStatus.mockResolvedValue({
      ...statusFixture,
      enabled: false,
      can_write_config: false,
      can_receive_traffic: false,
      majority_confirmed: false,
      node_count: 1,
      waf_node_count: 1,
      monitor_node_count: 0,
    });
    renderPage();
    expect(await screen.findByText('cluster.standalone')).toBeTruthy();
    expect(screen.getByText('cluster.protected')).toBeTruthy();
    expect(screen.getByText('cluster.singleNodeHint')).toBeTruthy();
  });
});
