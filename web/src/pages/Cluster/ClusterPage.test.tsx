import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
  fetchClusterConsensus: vi.fn(),
  fetchClusterRollingUpgrade: vi.fn(),
  createClusterBootstrapPlan: vi.fn(),
  startClusterRollingUpgrade: vi.fn(),
  startClusterRollingRollback: vi.fn(),
  fetchClusterTrafficPeers: vi.fn(),
  checkClusterDeployment: vi.fn(),
  fetchClusterRollingUpgrades: vi.fn(),
  reportClusterTrafficPeer: vi.fn(),
  proposeClusterConfigVersion: vi.fn(),
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

import ClusterPage, { fetchRollingJob } from './ClusterPage';

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
  apiMocks.fetchClusterConsensus.mockResolvedValue(null);
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
  apiMocks.fetchClusterRollingUpgrades.mockResolvedValue({ items: [], total: 0 });
  apiMocks.fetchClusterTrafficPeers.mockResolvedValue({ mode: 'least_conn', peers: [], healthy: [], ok: false });
});

/** Fills the SSH wizard fields required by every deploy/precheck mutation. */
async function fillSSHWizard() {
  const host = await screen.findByPlaceholderText('192.0.2.10');
  fireEvent.change(host, { target: { value: 'waf-a.example' } });
  const hostKey = screen.getByPlaceholderText('SHA256:...');
  fireEvent.change(hostKey, { target: { value: 'SHA256:abc123' } });
}

async function openSSHWizard() {
  fireEvent.click(screen.getByRole('radio', { name: /cluster\.deployWizardMethodSSH/ }));
  await fillSSHWizard();
}

afterEach(() => {
  cleanup();
});

describe('ClusterPage', () => {
  it('returns the rolling job fetched for a polling query', async () => {
    const rollingJob = { id: 'rolling-1', status: 'running', steps: [] };
    apiMocks.fetchClusterRollingUpgrade.mockResolvedValue(rollingJob);

    await expect(fetchRollingJob('rolling-1')).resolves.toEqual(rollingJob);
    expect(apiMocks.fetchClusterRollingUpgrade).toHaveBeenCalledWith('rolling-1');
  });

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
    expect(toastMocks.success).toHaveBeenCalledWith('cluster.tokenCreated');
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
    await waitFor(() => expect(toastMocks.success).toHaveBeenCalledWith('cluster.tokenCleared'));
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

describe('ClusterPage quick SSH precheck', () => {
  const precheckResponse = {
    result: {
      ok: true,
      host: 'waf-a.example',
      user: 'root',
      port: 22,
      command: ['ssh', '-p', '22', 'root@waf-a.example'],
      message: 'SSH check completed',
      checked_at: '2026-08-29T02:00:00Z',
    },
    authorization: { handle: 'auth-handle-1', expires_at: '2026-08-29T02:05:00Z' },
  };

  it('runs the synchronous precheck and renders the result', async () => {
    apiMocks.checkClusterDeployment.mockResolvedValue(precheckResponse);
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());
    await openSSHWizard();

    fireEvent.click(screen.getByRole('button', { name: 'cluster.quickPrecheck' }));
    await waitFor(() => expect(apiMocks.checkClusterDeployment).toHaveBeenCalledWith({
      host: 'waf-a.example',
      user: 'root',
      port: 22,
      action: 'check',
      host_key_sha256: 'SHA256:abc123',
    }));

    expect(await screen.findByText('cluster.precheckResultTitle')).toBeTruthy();
    expect(screen.getByText('cluster.precheckOk')).toBeTruthy();
    expect(screen.getByText('cluster.precheckAuthorization')).toBeTruthy();
  });

  it('surfaces a failed precheck without showing an authorization', async () => {
    apiMocks.checkClusterDeployment.mockRejectedValue(new Error('ssh host key fingerprint mismatch'));
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());
    await openSSHWizard();

    fireEvent.click(screen.getByRole('button', { name: 'cluster.quickPrecheck' }));
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith('ssh host key fingerprint mismatch'));
    expect(screen.queryByText('cluster.precheckResultTitle')).toBeNull();
  });

  it('uses the quick precheck authorization to run the fixed action', async () => {
    apiMocks.checkClusterDeployment.mockResolvedValue(precheckResponse);
    apiMocks.startClusterDeploymentTask.mockResolvedValue({ id: 'task-9', action: 'install', status: 'pending' });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());
    await openSSHWizard();

    const runButton = () => screen.getByRole('button', { name: 'cluster.deployWizardStartAction' }) as HTMLButtonElement;
    expect(runButton().disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'cluster.quickPrecheck' }));
    await screen.findByText('cluster.precheckResultTitle');
    expect(runButton().disabled).toBe(false);

    fireEvent.click(runButton());
    await waitFor(() => expect(apiMocks.startClusterDeploymentTask).toHaveBeenCalledWith({
      host: 'waf-a.example',
      user: 'root',
      port: 22,
      action: 'install',
      host_key_sha256: 'SHA256:abc123',
      authorization: 'auth-handle-1',
    }));
  });

  it('locks the fixed action again once the checked target no longer matches', async () => {
    apiMocks.checkClusterDeployment.mockResolvedValue(precheckResponse);
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());
    await openSSHWizard();

    fireEvent.click(screen.getByRole('button', { name: 'cluster.quickPrecheck' }));
    await screen.findByText('cluster.precheckResultTitle');

    fireEvent.change(screen.getByPlaceholderText('SHA256:...'), { target: { value: 'SHA256:other' } });
    const runButton = screen.getByRole('button', { name: 'cluster.deployWizardStartAction' }) as HTMLButtonElement;
    expect(runButton.disabled).toBe(true);
  });
});

describe('ClusterPage rolling upgrade job list', () => {
  it('lists rolling jobs and opens the selected one', async () => {
    apiMocks.fetchClusterRollingUpgrades.mockResolvedValue({
      items: [
        { id: 'rolling-old', status: 'succeeded', steps: [{ index: 0, host: 'waf-a', stage: 'healthy', status: 'healthy', updated_at: '2026-08-29T01:00:00Z' }], started_at: '2026-08-29T01:00:00Z', updated_at: '2026-08-29T01:05:00Z', stop_on_failure: true, restart_service: true },
        { id: 'rolling-new', status: 'running', steps: [{ index: 0, host: 'waf-b', stage: 'installing', status: 'running', updated_at: '2026-08-29T02:00:00Z' }], started_at: '2026-08-29T02:00:00Z', updated_at: '2026-08-29T02:10:00Z', stop_on_failure: true, restart_service: true },
      ],
      total: 2,
    });
    apiMocks.fetchClusterRollingUpgrade.mockResolvedValue({
      id: 'rolling-new', status: 'running', steps: [], started_at: '2026-08-29T02:00:00Z', updated_at: '2026-08-29T02:10:00Z', stop_on_failure: true, restart_service: true,
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterRollingUpgrades).toHaveBeenCalled());
    expect((await screen.findAllByText('rolling-old')).length).toBeGreaterThan(0);

    // Sorted newest-first: the running job must precede the finished one.
    const rows = screen.getAllByRole('row');
    const listedIDs = rows.map((row) => row.textContent || '').filter((text) => text.includes('rolling-'));
    expect(listedIDs[0]).toContain('rolling-new');

    fireEvent.click(screen.getAllByRole('button', { name: 'cluster.rollingJobView' })[0]);
    await waitFor(() => expect(apiMocks.fetchClusterRollingUpgrade).toHaveBeenCalledWith('rolling-new'));
  });

  it('shows a retryable error when the job list fails to load', async () => {
    apiMocks.fetchClusterRollingUpgrades.mockRejectedValue(new Error('rolling service down'));
    renderPage();
    expect(await screen.findByText('cluster.rollingJobsLoadFailed')).toBeTruthy();
    expect(screen.getByText('rolling service down')).toBeTruthy();

    apiMocks.fetchClusterRollingUpgrades.mockResolvedValue({ items: [], total: 0 });
    fireEvent.click(screen.getByRole('button', { name: 'common.retry' }));
    await waitFor(() => expect(apiMocks.fetchClusterRollingUpgrades).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('cluster.rollingJobsEmptyTitle')).toBeTruthy();
  });
});

describe('ClusterPage traffic probe reports', () => {
  it('reports a successful probe after confirmation', async () => {
    apiMocks.reportClusterTrafficPeer.mockResolvedValue({ ok: true, node_id: 'waf-1', report: 'success' });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterNodes).toHaveBeenCalled());

    fireEvent.click((await screen.findAllByRole('button', { name: 'cluster.trafficReportSuccess' }))[0]);
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'cluster.trafficReportSuccess' }));

    await waitFor(() => expect(apiMocks.reportClusterTrafficPeer).toHaveBeenCalledWith('waf-1', 'success'));
    expect(toastMocks.success).toHaveBeenCalledWith('cluster.trafficReportSuccessToast');
  });

  it('reports a failed probe and surfaces backend rejection', async () => {
    apiMocks.reportClusterTrafficPeer.mockRejectedValue(new Error('node_id must be a registered cluster node'));
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterNodes).toHaveBeenCalled());

    fireEvent.click((await screen.findAllByRole('button', { name: 'cluster.trafficReportFailure' }))[0]);
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'cluster.trafficReportFailure' }));

    await waitFor(() => expect(apiMocks.reportClusterTrafficPeer).toHaveBeenCalledWith('waf-1', 'failure'));
    expect(toastMocks.error).toHaveBeenCalledWith('node_id must be a registered cluster node');
    expect(await screen.findByText('node_id must be a registered cluster node')).toBeTruthy();
  });
});

describe('ClusterPage config version proposals', () => {
  it('proposes a configuration version and renders the record', async () => {
    apiMocks.proposeClusterConfigVersion.mockResolvedValue({
      version: '2026-08-29-01',
      leader_id: 'waf-1',
      message: 'tightened rule set',
      created_at: '2026-08-29T03:00:00Z',
    });
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());

    fireEvent.change(screen.getByPlaceholderText('cluster.configVersionPlaceholder'), { target: { value: '2026-08-29-01' } });
    fireEvent.change(screen.getByPlaceholderText('cluster.configVersionMessagePlaceholder'), { target: { value: 'tightened rule set' } });
    fireEvent.click(screen.getByRole('button', { name: 'cluster.configVersionSubmit' }));

    await waitFor(() => expect(apiMocks.proposeClusterConfigVersion).toHaveBeenCalledWith({
      version: '2026-08-29-01',
      message: 'tightened rule set',
    }));
    expect(await screen.findByText('cluster.configVersionResultTitle')).toBeTruthy();
    expect(screen.getByText('2026-08-29-01')).toBeTruthy();
    expect(toastMocks.success).toHaveBeenCalledWith('cluster.configVersionProposed');
  });

  it('rejects an empty version locally and surfaces a consensus rejection', async () => {
    renderPage();
    await waitFor(() => expect(apiMocks.fetchClusterStatus).toHaveBeenCalled());

    fireEvent.click(screen.getByRole('button', { name: 'cluster.configVersionSubmit' }));
    await waitFor(() => expect(toastMocks.warning).toHaveBeenCalledWith('cluster.configVersionRequired'));
    expect(apiMocks.proposeClusterConfigVersion).not.toHaveBeenCalled();

    apiMocks.proposeClusterConfigVersion.mockRejectedValue(new Error('only the cluster leader may propose config versions'));
    fireEvent.change(screen.getByPlaceholderText('cluster.configVersionPlaceholder'), { target: { value: '2026-08-29-02' } });
    fireEvent.click(screen.getByRole('button', { name: 'cluster.configVersionSubmit' }));

    await waitFor(() => expect(apiMocks.proposeClusterConfigVersion).toHaveBeenCalledWith({
      version: '2026-08-29-02',
      message: undefined,
    }));
    expect(await screen.findByText('cluster.configVersionFailed')).toBeTruthy();
    expect(screen.getByText('only the cluster leader may propose config versions')).toBeTruthy();
  });
});
