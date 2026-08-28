import { useEffect, useState } from 'react';
import {
  Badge,
  Button,
  Card,
  CardDescription,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  RadioGroup,
  RadioGroupItem,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
  toast,
} from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, Download, KeyRound, Network, PackageCheck, Play, Plus, RotateCcw, ShieldCheck, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { createClusterBootstrapPlan, createClusterJoinToken, fetchClusterAudit, fetchClusterConsensus, fetchClusterDeploymentTask, fetchClusterDeploymentTasks, fetchClusterJoinTokens, fetchClusterNodes, fetchClusterRollingUpgrade, fetchClusterStatus, fetchClusterTrafficPeers, generateClusterAnsiblePackage, revokeClusterJoinToken, rotateClusterNodeCertificate, startClusterDeploymentTask, startClusterRollingRollback, startClusterRollingUpgrade } from '../../api/client';
import type { ClusterAnsibleHost, ClusterAnsiblePackage, ClusterAuditEntry, ClusterBootstrapPlan, ClusterDeploymentRequest, ClusterDeploymentTask, ClusterDeploymentTaskEvent, ClusterJoinToken, ClusterJoinTokenCreateRequest, ClusterNodeCertificateRotateResponse, ClusterNodeRegistration, ClusterRollingJob, ClusterTrafficPeersResponse } from '../../types/api';
import { usePollingVisibility } from '../../hooks/usePollingVisibility';

type ClusterDeployForm = {
  host?: string;
  user?: string;
  port?: number;
  password?: string;
  privateKey?: string;
  hostKeySHA256?: string;
  action?: string;
};

type ClusterAnsibleForm = {
  clusterId?: string;
  channel?: string;
};

type ClusterTokenForm = {
  role?: string;
  ttl?: string;
  maxUses?: number;
  controllerUrl?: string;
  nodeId?: string;
  advertiseAddr?: string;
};

type JoinCommandFields = Pick<ClusterTokenForm, 'controllerUrl' | 'nodeId' | 'advertiseAddr'>;

type ClusterCertificateForm = {
  nodeId?: string;
  csr?: string;
};

type ClusterBootstrapForm = {
  role?: string;
  nodeId?: string;
  controllerUrl?: string;
  advertiseAddr?: string;
};

type ClusterRollingForm = {
  hosts?: string;
  user?: string;
};

type DeployMethod = 'ansible' | 'ssh';
type DeployAuthMethod = 'agent' | 'password' | 'private_key';


type Translate = (key: string, options?: Record<string, unknown>) => string;

export async function fetchRollingJob(id: string): Promise<ClusterRollingJob> {
  const job = await fetchClusterRollingUpgrade(id);
  if (job.rollback_job_id && job.status === 'failed') {
    try {
      return await fetchClusterRollingUpgrade(job.rollback_job_id);
    } catch {
      return job;
    }
  }
  return job;
}

export default function ClusterPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [deployForm, setDeployForm] = useState<ClusterDeployForm>({ user: 'root', port: 22, action: 'install' });
  const [ansibleForm, setAnsibleForm] = useState<ClusterAnsibleForm>({ clusterId: 'cheesewaf-mesh', channel: 'canary' });
  const [tokenForm, setTokenForm] = useState<ClusterTokenForm>({ role: 'waf', ttl: '15m', maxUses: 1 });
  const [certificateForm, setCertificateForm] = useState<ClusterCertificateForm>({});
  const [bootstrapForm, setBootstrapForm] = useState<ClusterBootstrapForm>({ role: 'waf' });
  const [rollingForm, setRollingForm] = useState<ClusterRollingForm>({ user: 'root' });
  const [deployMethod, setDeployMethod] = useState<DeployMethod>('ansible');
  const [deployWizardStep, setDeployWizardStep] = useState(0);
  const [deployAuthMethod, setDeployAuthMethod] = useState<DeployAuthMethod>('agent');
  const [ansibleNodes, setAnsibleNodes] = useState<ClusterAnsibleHost[]>([
    { name: 'waf-a', address: '', role: 'waf', ssh_port: 22 },
  ]);
  const [ansiblePackage, setAnsiblePackage] = useState<ClusterAnsiblePackage | null>(null);
  const [selectedAnsibleFile, setSelectedAnsibleFile] = useState('README.md');
  const [activeDeployTaskId, setActiveDeployTaskId] = useState<string | null>(null);
  const [submittedDeployTask, setSubmittedDeployTask] = useState<ClusterDeploymentTask | null>(null);
  const [latestToken, setLatestToken] = useState<ClusterJoinToken | null>(null);
  const [joinCommandFields, setJoinCommandFields] = useState<JoinCommandFields>({});
  const [latestCertificate, setLatestCertificate] = useState<ClusterNodeCertificateRotateResponse | null>(null);
  const [tokenOperationError, setTokenOperationError] = useState<string | null>(null);
  const [revokingTokenID, setRevokingTokenID] = useState<string | null>(null);
  const [revokeConfirmID, setRevokeConfirmID] = useState<string | null>(null);
  const [bootstrapPlan, setBootstrapPlan] = useState<ClusterBootstrapPlan | null>(null);
  const [rollingJob, setRollingJob] = useState<ClusterRollingJob | null>(null);
  const [trafficPeers, setTrafficPeers] = useState<ClusterTrafficPeersResponse | null>(null);
  const statusRefreshInterval = usePollingVisibility(15_000);
  const tokensRefreshInterval = usePollingVisibility(15_000);
  const nodesRefreshInterval = usePollingVisibility(15_000);
  const deployTasksRefreshInterval = usePollingVisibility(3000);
  const auditRefreshInterval = usePollingVisibility(12_000);
  const [auditPage, setAuditPage] = useState(0);
  const { data, isLoading, refetch, isFetching, isError: isStatusError, error: statusError } = useQuery({
    queryKey: ['cluster-status'],
    queryFn: fetchClusterStatus,
    refetchInterval: statusRefreshInterval,
    staleTime: 10_000,
    retry: false,
  });
  const { data: consensus } = useQuery({
    queryKey: ['cluster-consensus'],
    queryFn: fetchClusterConsensus,
    refetchInterval: statusRefreshInterval,
    staleTime: 10_000,
    retry: false,
  });
  const rollingJobID = rollingJob?.id;
  const rollingNeedsPoll = Boolean(
    rollingJobID && (rollingJob?.status === 'pending' || rollingJob?.status === 'running' || rollingJob?.rollback_job_id),
  );
  const rollingRefreshInterval = usePollingVisibility(rollingNeedsPoll ? 2000 : false);
  const { data: polledRollingJob } = useQuery({
    queryKey: ['cluster-rolling-job', rollingJobID],
    queryFn: () => fetchRollingJob(rollingJobID as string),
    enabled: rollingNeedsPoll,
    refetchInterval: rollingRefreshInterval,
    retry: false,
  });
  useEffect(() => {
    if (polledRollingJob) {
      setRollingJob(polledRollingJob);
    }
  }, [polledRollingJob]);
  const { data: tokens, isFetching: isFetchingTokens, isError: isTokensError, error: tokensError, refetch: refetchTokens } = useQuery({
    queryKey: ['cluster-join-tokens'],
    queryFn: fetchClusterJoinTokens,
    refetchInterval: tokensRefreshInterval,
    retry: false,
  });
  const { data: nodes, isFetching: isFetchingNodes, isError: isNodesError, error: nodesError, refetch: refetchNodes } = useQuery({
    queryKey: ['cluster-nodes'],
    queryFn: fetchClusterNodes,
    refetchInterval: nodesRefreshInterval,
    retry: false,
  });
  const { data: deployTasks, isFetching: isFetchingDeployTasks, refetch: refetchDeployTasks } = useQuery({
    queryKey: ['cluster-deploy-tasks'],
    queryFn: fetchClusterDeploymentTasks,
    refetchInterval: deployTasksRefreshInterval,
    retry: false,
  });
  const { data: clusterAudit, isFetching: isFetchingAudit, isError: isAuditError, error: auditError, refetch: refetchAudit } = useQuery({
    queryKey: ['cluster-audit'],
    queryFn: fetchClusterAudit,
    refetchInterval: auditRefreshInterval,
    staleTime: 10_000,
    retry: false,
  });
  const selectedDeployTask = activeDeployTaskId ? deployTasks?.items.find((item) => item.id === activeDeployTaskId) : null;
  const activeDeployTask = selectedDeployTask ?? (submittedDeployTask?.id === activeDeployTaskId ? submittedDeployTask : null);
  const auditEntries = clusterAudit?.items || [];
  const createTokenMutation = useMutation({
    mutationFn: (payload: ClusterJoinTokenCreateRequest) => createClusterJoinToken(payload),
    onMutate: () => {
      setTokenOperationError(null);
    },
    onSuccess: (token) => {
      setLatestToken(token);
      void queryClient.invalidateQueries({ queryKey: ['cluster-join-tokens'] });
      toast.success(t('cluster.tokenCreated'));
    },
    onError: (error) => {
      setTokenOperationError(error.message);
      toast.error(error.message);
    },
  });
  const revokeTokenMutation = useMutation({
    mutationFn: (id: string) => revokeClusterJoinToken(id),
    onMutate: (id) => {
      setTokenOperationError(null);
      setRevokingTokenID(id);
    },
    onSuccess: (_result, id) => {
      setLatestToken((current) => (current?.id === id ? null : current));
      void queryClient.invalidateQueries({ queryKey: ['cluster-join-tokens'] });
      toast.success(t('cluster.tokenRevoked'));
    },
    onError: (error) => {
      setTokenOperationError(error.message);
      toast.error(error.message);
    },
    onSettled: () => {
      setRevokingTokenID(null);
    },
  });
  const deployTaskMutation = useMutation({
    mutationFn: (payload: ClusterDeploymentRequest) => startClusterDeploymentTask(payload),
    onSuccess: (task) => {
      setActiveDeployTaskId(task.id);
      setSubmittedDeployTask(task);
      setDeployWizardStep((current) => Math.max(current, 3));
      setDeployForm((current) => ({ ...current, password: '', privateKey: '' }));
      void queryClient.invalidateQueries({ queryKey: ['cluster-deploy-tasks'] });
      void queryClient.invalidateQueries({ queryKey: ['cluster-status'] });
      toast.success(t('cluster.deployTaskStarted'));
    },
    onError: (error) => {
      setDeployForm((current) => ({ ...current, password: '', privateKey: '' }));
      toast.error(error.message);
    },
  });
  const ansiblePackageMutation = useMutation({
    mutationFn: () => {
      const values = ansibleForm;
      const normalizedNodes = normalizeAnsibleNodes(ansibleNodes);
      if (!normalizedNodes.length) {
        throw new Error(t('cluster.deployWizardAnsibleNodeRequired'));
      }
      const invalidNode = normalizedNodes.find((node) => !node.name || !node.address || !node.role || !node.ssh_port);
      if (invalidNode) {
        throw new Error(t('cluster.deployWizardAnsibleNodeInvalid'));
      }
      return generateClusterAnsiblePackage({
        cluster_id: String(values.clusterId || 'cheesewaf-mesh').trim(),
        channel: String(values.channel || 'canary').trim(),
        nodes: normalizedNodes,
      });
    },
    onSuccess: (pkg) => {
      setAnsiblePackage(pkg);
      const files = Object.keys(pkg.files || {}).sort();
      setSelectedAnsibleFile(files.includes('README.md') ? 'README.md' : files[0] || '');
      setDeployWizardStep(3);
      toast.success(t('cluster.deployWizardAnsibleGenerated'));
    },
    onError: (error) => {
      toast.error(errorMessage(error));
    },
  });
  const rotateCertificateMutation = useMutation({
    mutationFn: (payload: { nodeID: string; csr: string }) => rotateClusterNodeCertificate(payload.nodeID, { csr: payload.csr }),
    onMutate: () => {
      setLatestCertificate(null);
    },
    onSuccess: (result) => {
      setLatestCertificate(result);
      setCertificateForm((current) => ({ ...current, csr: '' }));
      void queryClient.invalidateQueries({ queryKey: ['cluster-nodes'] });
      toast.success(t('cluster.certSigned'));
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const submitToken = async () => {
    if (latestToken?.value) {
      const message = t('cluster.tokenClearBeforeCreate');
      setTokenOperationError(message);
      toast.warning(message);
      return;
    }
    const values = tokenForm;
    createTokenMutation.mutate({
      role: String(values.role || 'waf'),
      ttl: String(values.ttl || '15m'),
      max_uses: Number(values.maxUses || 1),
    });
  };

  const submitDeployment = async (mode: 'check' | 'run') => {
    const values = deployForm;
    if (!String(values.host || '').trim()) {
      toast.warning(t('cluster.deployHostRequired'));
      return;
    }
    if (!String(values.user || '').trim()) {
      toast.warning(t('cluster.deployUserRequired'));
      return;
    }
    if (!values.port) {
      toast.warning(t('cluster.deployPortRequired'));
      return;
    }
    const action = String(values.action || 'install');
    const payload: ClusterDeploymentRequest = {
      host: String(values.host || '').trim(),
      user: String(values.user || 'root').trim(),
      port: Number(values.port || 22),
      action: mode === 'check' ? 'check' : action,
    };
    const password = String(values.password || '').trim();
    const privateKey = String(values.privateKey || '').trim();
    if (deployAuthMethod === 'password' && !password) {
      toast.warning(t('cluster.deployPasswordRequired'));
      return;
    }
    if (deployAuthMethod === 'private_key' && !privateKey) {
      toast.warning(t('cluster.deployPrivateKeyRequired'));
      return;
    }
    if (deployAuthMethod === 'password' && password) {
      payload.password = password;
    }
    if (deployAuthMethod === 'private_key' && privateKey) {
      payload.private_key = privateKey;
    }
    const hostKeySHA256 = String(values.hostKeySHA256 || '').trim();
    if (!hostKeySHA256) {
      toast.warning(t('cluster.deployHostKeyRequired'));
      return;
    }
    if (hostKeySHA256) {
      payload.host_key_sha256 = hostKeySHA256;
    }
    if (mode === 'check') {
      setDeployWizardStep(2);
      deployTaskMutation.mutate(payload);
    } else {
      if (!activeDeployTask || activeDeployTask.action !== 'check' || activeDeployTask.status !== 'succeeded') {
        toast.warning(t('cluster.deployWizardPrecheckRequired'));
        return;
      }
      const checkedTask = await fetchClusterDeploymentTask(activeDeployTask.id);
      if (checkedTask.action !== 'check' || checkedTask.status !== 'succeeded' || !checkedTask.authorization?.handle) {
        toast.warning(t('cluster.deployWizardPrecheckRequired'));
        return;
      }
      payload.authorization = checkedTask.authorization.handle;
      setDeployWizardStep(3);
      deployTaskMutation.mutate(payload);
    }
  };

  const addAnsibleNode = () => {
    setAnsibleNodes((items) => [
      ...items,
      { name: `waf-${items.length + 1}`, address: '', role: 'waf', ssh_port: 22 },
    ]);
  };

  const updateAnsibleNode = (index: number, patch: Partial<ClusterAnsibleHost>) => {
    setAnsibleNodes((items) => items.map((item, itemIndex) => (itemIndex === index ? { ...item, ...patch } : item)));
  };

  const removeAnsibleNode = (index: number) => {
    setAnsibleNodes((items) => (items.length <= 1 ? items : items.filter((_, itemIndex) => itemIndex !== index)));
  };

  const resetDeploymentWizard = () => {
    setDeployForm({ user: 'root', port: 22, action: 'install' });
    setAnsibleForm({ clusterId: 'cheesewaf-mesh', channel: 'canary' });
    setDeployWizardStep(0);
    setDeployMethod('ansible');
    setDeployAuthMethod('agent');

    setActiveDeployTaskId(null);
    setSubmittedDeployTask(null);
    setAnsiblePackage(null);
    setSelectedAnsibleFile('README.md');
  };

  const bootstrapMutation = useMutation({
    mutationFn: createClusterBootstrapPlan,
    onSuccess: (plan) => {
      setBootstrapPlan(plan);
      toast.success(t('cluster.bootstrapPlanReady'));
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const rollingMutation = useMutation({
    mutationFn: startClusterRollingUpgrade,
    onSuccess: (job) => {
      setRollingJob(job);
      toast.success(t('cluster.rollingStarted'));
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const submitBootstrapPlan = async () => {
    const values = bootstrapForm;
    if (!String(values.nodeId || '').trim() || !String(values.controllerUrl || '').trim() || !String(values.advertiseAddr || '').trim()) {
      toast.warning(t('cluster.bootstrapFieldsRequired'));
      return;
    }
    bootstrapMutation.mutate({
      role: values.role || 'waf',
      node_id: String(values.nodeId || '').trim(),
      controller_url: String(values.controllerUrl || '').trim(),
      advertise_addr: String(values.advertiseAddr || '').trim(),
      token_ttl: '15m',
      token_max_uses: 1,
    });
  };

  const submitRollingUpgrade = async () => {
    const values = rollingForm;
    const user = String(values.user || 'root').trim();
    const hosts = String(values.hosts || '')
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (hosts.length === 0) {
      toast.warning(t('cluster.rollingHostsRequired'));
      return;
    }
    rollingMutation.mutate({
      targets: hosts.map((host) => ({ host, user })),
      pause_between: '3s',
      stop_on_failure: true,
      restart_service: true,
      auto_rollback: true,
    });
  };

  const loadTrafficPeers = async (mode: string = 'least_conn') => {
    try {
      const result = await fetchClusterTrafficPeers(mode, undefined, mode === 'sticky' ? 'preview-session' : undefined);
      setTrafficPeers(result);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    }
  };

  const rollbackRollingJob = async () => {
    if (!rollingJob?.id) return;
    try {
      const job = await startClusterRollingRollback(rollingJob.id);
      setRollingJob(job);
      toast.success(t('cluster.rollbackStarted'));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : String(error));
    }
  };

  const submitCertificateSigning = async () => {
    const values = certificateForm;
    const nodeID = String(values.nodeId || '').trim();
    const csr = String(values.csr || '').trim();
    if (!nodeID) {
      toast.warning(t('cluster.certNodeRequired'));
      return;
    }
    if (!csr) {
      toast.warning(t('cluster.certCSRRequired'));
      return;
    }
    const node = nodes?.items.find((item) => item.node_id === nodeID);
    if (node?.revoked) {
      toast.warning(t('cluster.certRevokedNode'));
      return;
    }
    rotateCertificateMutation.mutate({ nodeID, csr });
  };


  return (
    <main className="page-surface cluster-page">
      <section className="page-header">
        <div>
          <h1>{t('cluster.title')}</h1>
          <p>{t('cluster.subtitle')}</p>
        </div>
        <Button variant="outline" loading={isLoading} onClick={() => void refetch()}>{t('cluster.refresh')}</Button>
      </section>

      {isStatusError && (
        <div className="cluster-result-note cluster-result-note-error cluster-status-error">
          <strong>{t('cluster.statusLoadFailed')}</strong>
          <span>{errorMessage(statusError)}</span>
          <Button size="sm" variant="outline" onClick={() => void refetch()}>{t('common.retry')}</Button>
        </div>
      )}

      {isLoading && !data ? <div className="flex justify-center p-8"><Spinner /></div> : null}

      <div>
        {data && (
          <section className="cluster-grid">
            <Card className="cluster-status-card">
              <div className="cluster-card-head">
                <span className="cluster-icon"><Network size={18} /></span>
                <div>
                  <CardTitle>{t('cluster.currentMode')}</CardTitle>
                  <CardDescription>{t('cluster.currentModeHint')}</CardDescription>
                </div>
                <Badge variant={data.enabled ? 'success' : 'secondary'}>{data.enabled ? t('common.enabled') : t('cluster.standalone')}</Badge>
              </div>
              <div className="cluster-status-main">
                <div><span>{t('cluster.mode')}</span><strong>{clusterModeLabel(data.mode, data.product_mode_label, t)}</strong></div>
                <div><span>{t('cluster.configWrites')}</span><strong>{data.can_write_config ? t('cluster.allowed') : t('cluster.protected')}</strong></div>
                <div><span>{t('cluster.traffic')}</span><strong>{data.can_receive_traffic ? t('cluster.receiving') : t('cluster.notReceiving')}</strong></div>
                <div><span>{t('cluster.majority')}</span><strong>{data.majority_confirmed ? t('cluster.confirmed') : t('cluster.unconfirmed')}</strong></div>
              </div>
              {data.protection_mode_reason && <div className="cluster-protection-note">{data.protection_mode_reason}</div>}
            </Card>

            <Card className="cluster-status-card">
              <div className="cluster-card-head">
                <span className="cluster-icon cluster-icon-safe"><ShieldCheck size={18} /></span>
                <div>
                  <CardTitle>{t('cluster.nodes')}</CardTitle>
                  <CardDescription>{t('cluster.nodesHint')}</CardDescription>
                </div>
              </div>
              <div className="cluster-node-summary">
                <div><span>{t('cluster.totalNodes')}</span><strong>{data.node_count}</strong></div>
                <div><span>{t('cluster.wafNodes')}</span><strong>{data.waf_node_count}</strong></div>
                <div><span>{t('cluster.monitorNodes')}</span><strong>{data.monitor_node_count}</strong></div>
                <div><span>{t('cluster.consistency')}</span><strong>{consensusLabel(data.consensus_provider, t)}</strong></div>
                {consensus && (
                  <>
                    <div><span>{t('cluster.leader')}</span><strong>{consensus.leader_id || '—'}</strong></div>
                    <div><span>{t('cluster.localRole')}</span><strong>{consensus.local_role || '—'}</strong></div>
                  </>
                )}
              </div>
              {!data.enabled && (
                <div className="cluster-empty-action">
                  <p>{t('cluster.singleNodeHint')}</p>
                  <Button variant="outline" onClick={() => document.getElementById('cluster-deploy-wizard')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>
                    {t('cluster.fullWizardPending')}
                  </Button>
                </div>
              )}
            </Card>
          </section>
        )}
        {!data && !isLoading && !isStatusError && (
          <section className="cluster-grid">
            <Card className="cluster-status-card">
              <div className="cluster-card-head">
                <span className="cluster-icon"><Network size={18} /></span>
                <div>
                  <CardTitle>{t('cluster.currentMode')}</CardTitle>
                  <CardDescription>{t('cluster.statusUnavailable')}</CardDescription>
                </div>
              </div>
            </Card>
          </section>
        )}

        <Card className="cluster-join-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><PackageCheck size={18} /></span>
            <div>
              <CardTitle>{t('cluster.bootstrapTitle')}</CardTitle>
              <CardDescription>{t('cluster.bootstrapHint')}</CardDescription>
            </div>
          </div>
          <div className="cluster-token-form">
            <div className="cluster-token-fields">
              <label>
                <span>{t('cluster.role')}</span>
                <Select value={bootstrapForm.role || 'waf'} onValueChange={(role) => setBootstrapForm((c) => ({ ...c, role }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="waf">waf</SelectItem>
                    <SelectItem value="monitor">monitor</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('cluster.nodeId')}</span>
                <Input placeholder="waf-b" value={bootstrapForm.nodeId || ''} onChange={(e) => setBootstrapForm((c) => ({ ...c, nodeId: e.target.value }))} />
              </label>
              <label>
                <span>{t('cluster.controllerUrl')}</span>
                <Input placeholder="https://controller.example:9443" value={bootstrapForm.controllerUrl || ''} onChange={(e) => setBootstrapForm((c) => ({ ...c, controllerUrl: e.target.value }))} />
              </label>
              <label>
                <span>{t('cluster.advertiseAddr')}</span>
                <Input placeholder="10.0.0.2:9444" value={bootstrapForm.advertiseAddr || ''} onChange={(e) => setBootstrapForm((c) => ({ ...c, advertiseAddr: e.target.value }))} />
              </label>
            </div>
            <Button loading={bootstrapMutation.isPending} onClick={() => void submitBootstrapPlan()}>
              {t('cluster.createBootstrapPlan')}
            </Button>
          </div>
          {bootstrapPlan && (
            <div className="cluster-result-note">
              <strong>{t('cluster.joinCommand')}</strong>
              <pre className="cluster-command">{bootstrapPlan.join_command}</pre>
              <p>{bootstrapPlan.install_hint}</p>
              <p>{bootstrapPlan.post_join_hint}</p>
            </div>
          )}
        </Card>

        <Card className="cluster-join-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><RotateCcw size={18} /></span>
            <div>
              <CardTitle>{t('cluster.rollingTitle')}</CardTitle>
              <CardDescription>{t('cluster.rollingHint')}</CardDescription>
            </div>
          </div>
          <div className="cluster-token-form">
            <label>
              <span>{t('cluster.rollingHosts')}</span>
              <Textarea rows={4} placeholder={'waf-a.example\nwaf-b.example'} value={rollingForm.hosts || ''} onChange={(e) => setRollingForm((c) => ({ ...c, hosts: e.target.value }))} />
            </label>
            <label>
              <span>{t('cluster.sshUser')}</span>
              <Input value={rollingForm.user || ''} onChange={(e) => setRollingForm((c) => ({ ...c, user: e.target.value }))} />
            </label>
            <Button loading={rollingMutation.isPending} onClick={() => void submitRollingUpgrade()}>
              {t('cluster.startRolling')}
            </Button>
          </div>
          {rollingJob && (
            <div className="cluster-result-note">
              <strong>{rollingJob.id}</strong> · {rollingJob.status}
              {rollingJob.rollback_of ? ` · rollback of ${rollingJob.rollback_of}` : ''}
              {rollingJob.rollback_job_id ? ` · rollback job ${rollingJob.rollback_job_id}` : ''}
              <ul>
                {rollingJob.steps?.map((step) => (
                  <li key={`${step.index}-${step.host}`}>{step.host}: {step.stage} / {step.status} {step.message ? `— ${step.message}` : ''}</li>
                ))}
              </ul>
              {(rollingJob.status === 'failed' || rollingJob.status === 'succeeded') && !rollingJob.rollback_of && (
                <Button className="mt-2" variant="outline" onClick={() => void rollbackRollingJob()}>
                  {t('cluster.startRollback')}
                </Button>
              )}
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => void loadTrafficPeers('least_conn')}>
              {t('cluster.loadTrafficPeers')}
            </Button>
            <Button variant="outline" onClick={() => void loadTrafficPeers('sticky')}>
              {t('cluster.loadStickyPeers')}
            </Button>
          </div>
          {trafficPeers && (
            <div className="cluster-result-note">
              <strong>{t('cluster.selectedPeer')}</strong>
              <span>{trafficPeers.selected?.node_id || '—'} {trafficPeers.selected?.advertise_addr || ''}</span>
              <span>{t('cluster.eligiblePeers')}: {trafficPeers.peers?.length ?? 0}</span>
              <span>{t('cluster.healthyPeers')}: {trafficPeers.healthy?.length ?? trafficPeers.peers?.length ?? 0}</span>
              <span>{t('cluster.trafficMode')}: {trafficPeers.mode}</span>
            </div>
          )}
        </Card>

        <Card className="cluster-join-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><KeyRound size={18} /></span>
            <div>
              <CardTitle>{t('cluster.joinTitle')}</CardTitle>
              <CardDescription>{t('cluster.joinHint')}</CardDescription>
            </div>
          </div>
          <div className="cluster-token-form">
            <div className="cluster-token-fields">
              <label>
                <span>{t('cluster.tokenRole')}</span>
                <Select value={tokenForm.role || 'waf'} onValueChange={(role) => setTokenForm((c) => ({ ...c, role }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="waf">{t('cluster.roleWaf')}</SelectItem>
                    <SelectItem value="monitor">{t('cluster.roleMonitor')}</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('cluster.tokenTTL')}</span>
                <Select value={tokenForm.ttl || '15m'} onValueChange={(ttl) => setTokenForm((c) => ({ ...c, ttl }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="15m">15m</SelectItem>
                    <SelectItem value="30m">30m</SelectItem>
                    <SelectItem value="1h">1h</SelectItem>
                    <SelectItem value="6h">6h</SelectItem>
                  </SelectContent>
                </Select>
                <em>{t('cluster.tokenTTLHint')}</em>
              </label>
              <label>
                <span>{t('cluster.tokenMaxUses')}</span>
                <Input type="number" min={1} max={100} value={tokenForm.maxUses ?? 1} onChange={(e) => setTokenForm((c) => ({ ...c, maxUses: Number(e.target.value || 1) }))} />
                <em>{t('cluster.tokenMaxUsesHint')}</em>
              </label>
              <label>
                <span>{t('cluster.joinControllerUrl')}</span>
                <Input placeholder="https://controller.example.com:9443" value={tokenForm.controllerUrl || ''} onChange={(e) => {
                  const controllerUrl = e.target.value;
                  setTokenForm((c) => ({ ...c, controllerUrl }));
                  setJoinCommandFields((c) => ({ ...c, controllerUrl }));
                }} />
                <em>{t('cluster.joinControllerUrlHint')}</em>
              </label>
              <label>
                <span>{t('cluster.joinNodeId')}</span>
                <Input placeholder="waf-1" value={tokenForm.nodeId || ''} onChange={(e) => {
                  const nodeId = e.target.value;
                  setTokenForm((c) => ({ ...c, nodeId }));
                  setJoinCommandFields((c) => ({ ...c, nodeId }));
                }} />
                <em>{t('cluster.joinNodeIdHint')}</em>
              </label>
              <label>
                <span>{t('cluster.joinAdvertiseAddr')}</span>
                <Input placeholder="192.168.6.250:9444" value={tokenForm.advertiseAddr || ''} onChange={(e) => {
                  const advertiseAddr = e.target.value;
                  setTokenForm((c) => ({ ...c, advertiseAddr }));
                  setJoinCommandFields((c) => ({ ...c, advertiseAddr }));
                }} />
                <em>{t('cluster.joinAdvertiseAddrHint')}</em>
              </label>
              <div>
                <Button
                  loading={createTokenMutation.isPending}
                  disabled={Boolean(latestToken?.value) || revokeTokenMutation.isPending}
                  onClick={() => void submitToken()}
                >
                  {t('cluster.createToken')}
                </Button>
              </div>
            </div>
          </div>
          {tokenOperationError && (
            <div className="cluster-result-note cluster-result-note-error cluster-inline-error">
              <strong>{t('cluster.tokenOperationFailed')}</strong>
              <span>{tokenOperationError}</span>
              <Button size="sm" variant="outline" onClick={() => setTokenOperationError(null)}>{t('common.close')}</Button>
            </div>
          )}
          {latestToken?.value && (
            <div className="cluster-result-note cluster-result-note-ok cluster-token-secret">
              <strong>{t('cluster.tokenSecretTitle')}</strong>
              <span>{t('cluster.tokenSecretHint')}</span>
              <code>{latestToken.value}</code>
              <div className="cluster-token-actions">
                <Button variant="outline" onClick={() => void copyText(latestToken.value || '', t('cluster.copied'), t('cluster.copyFailed'))}>
                  <Copy size={15} />{t('cluster.copyToken')}
                </Button>
                <Button variant="outline" onClick={() => {
                  setLatestToken(null);
                  toast.success(t('cluster.tokenCleared'));
                }}>
                  {t('cluster.clearToken')}
                </Button>
              </div>
              <JoinCommandBlock token={latestToken} fields={joinCommandFields} t={t} />
            </div>
          )}
          {(isTokensError || isNodesError) && (
            <div className="cluster-result-note cluster-result-note-error cluster-load-error">
              <strong>{t('cluster.loadFailed')}</strong>
              {isTokensError && <span>{t('cluster.tokenLoadFailed')}: {errorMessage(tokensError)}</span>}
              {isNodesError && <span>{t('cluster.nodeLoadFailed')}: {errorMessage(nodesError)}</span>}
              <Button size="sm" variant="outline" onClick={() => { void refetchTokens(); void refetchNodes(); }}>{t('common.retry')}</Button>
            </div>
          )}
          <div className="cluster-tables-grid">
            <div className="relative">
              {isFetchingTokens && <div className="absolute inset-0 z-10 bg-background/40" aria-busy />}
              <Table className="cluster-token-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('cluster.tokenID')}</TableHead>
                    <TableHead>{t('cluster.tokenRole')}</TableHead>
                    <TableHead>{t('cluster.tokenUsage')}</TableHead>
                    <TableHead>{t('cluster.tokenExpires')}</TableHead>
                    <TableHead>{t('common.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(tokens?.items || []).map((item) => (
                    <TableRow key={item.id}>
                      <TableCell><code>{item.id}</code></TableCell>
                      <TableCell>{roleTag(item.role, t)}</TableCell>
                      <TableCell>{item.used_count}/{item.max_uses}</TableCell>
                      <TableCell>{formatTimestamp(item.expires_at)}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={item.revoked || revokeTokenMutation.isPending}
                          loading={revokingTokenID === item.id}
                          onClick={() => setRevokeConfirmID(item.id)}
                        >
                          {item.revoked ? t('cluster.revoked') : t('cluster.revoke')}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="relative">
              {isFetchingNodes && <div className="absolute inset-0 z-10 bg-background/40" aria-busy />}
              <Table className="cluster-node-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('cluster.nodeID')}</TableHead>
                    <TableHead>{t('cluster.nodeRole')}</TableHead>
                    <TableHead>{t('cluster.nodeRuntimeState')}</TableHead>
                    <TableHead>{t('cluster.nodeAdvertise')}</TableHead>
                    <TableHead>{t('cluster.nodeLastHeartbeat')}</TableHead>
                    <TableHead>{t('cluster.nodeConfigVersion')}</TableHead>
                    <TableHead>{t('common.actions')}</TableHead>
                    <TableHead>{t('cluster.nodeJoined')}</TableHead>
                    <TableHead>{t('cluster.nodeCertExpiry')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(nodes?.items || []).map((item) => (
                    <TableRow key={item.node_id}>
                      <TableCell><code>{item.node_id}</code></TableCell>
                      <TableCell>{roleTag(item.role, t)}</TableCell>
                      <TableCell>{runtimeStateTag(item, t)}</TableCell>
                      <TableCell>{item.advertise_addr}</TableCell>
                      <TableCell>{formatRuntimeHeartbeat(item)}</TableCell>
                      <TableCell>{item.runtime?.config_version || '-'}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={item.revoked}
                          onClick={() => {
                            setCertificateForm((c) => ({ ...c, nodeId: item.node_id }));
                            setLatestCertificate(null);
                            document.getElementById('cluster-cert-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                          }}
                        >
                          {t('cluster.certSign')}
                        </Button>
                      </TableCell>
                      <TableCell>{formatTimestamp(item.joined_at)}</TableCell>
                      <TableCell>{formatTimestamp(item.certificate_expiry)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
          <div className="cluster-mobile-cards">
            <section className="cluster-mobile-list" aria-label={t('cluster.joinTokenList')}>
              <h3>{t('cluster.joinTokenList')}</h3>
              {(tokens?.items || []).length ? (tokens?.items || []).map((item) => (
                <article className="cluster-mobile-card" key={item.id}>
                  <div className="cluster-mobile-card-head">
                    <code>{item.id}</code>
                    {roleTag(item.role, t)}
                  </div>
                  <dl>
                    <div><dt>{t('cluster.tokenUsage')}</dt><dd>{item.used_count}/{item.max_uses}</dd></div>
                    <div><dt>{t('cluster.tokenExpires')}</dt><dd>{formatTimestamp(item.expires_at)}</dd></div>
                  </dl>
                  <div className="cluster-mobile-actions">
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={item.revoked || revokeTokenMutation.isPending}
                      loading={revokingTokenID === item.id}
                      onClick={() => setRevokeConfirmID(item.id)}
                    >
                      {item.revoked ? t('cluster.revoked') : t('cluster.revoke')}
                    </Button>
                  </div>
                </article>
              )) : <div className="cluster-mobile-empty">{t('common.noData')}</div>}
            </section>
            <section className="cluster-mobile-list" aria-label={t('cluster.registeredNodeList')}>
              <h3>{t('cluster.registeredNodeList')}</h3>
              {(nodes?.items || []).length ? (nodes?.items || []).map((item) => (
                <article className="cluster-mobile-card" key={item.node_id}>
                  <div className="cluster-mobile-card-head">
                    <code>{item.node_id}</code>
                    {runtimeStateTag(item, t)}
                  </div>
                  <dl>
                    <div><dt>{t('cluster.nodeRole')}</dt><dd>{roleTag(item.role, t)}</dd></div>
                    <div><dt>{t('cluster.nodeAdvertise')}</dt><dd>{item.advertise_addr || '-'}</dd></div>
                    <div><dt>{t('cluster.nodeLastHeartbeat')}</dt><dd>{formatRuntimeHeartbeat(item)}</dd></div>
                    <div><dt>{t('cluster.nodeConfigVersion')}</dt><dd>{item.runtime?.config_version || '-'}</dd></div>
                  </dl>
                  <div className="cluster-mobile-actions">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={item.revoked}
                      onClick={() => {
                        setCertificateForm((c) => ({ ...c, nodeId: item.node_id }));
                        setLatestCertificate(null);
                        document.getElementById('cluster-cert-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                      }}
                    >
                      {t('cluster.certSign')}
                    </Button>
                  </div>
                </article>
              )) : <div className="cluster-mobile-empty">{t('common.noData')}</div>}
            </section>
          </div>

          <div id="cluster-cert-panel" className="cluster-cert-panel">
            <div className="cluster-cert-head">
              <div>
                <strong>{t('cluster.certTitle')}</strong>
                <span>{t('cluster.certHint')}</span>
              </div>
            </div>
            <div className="cluster-cert-form">
              <div className="cluster-cert-fields">
                <label>
                  <span>{t('cluster.certNode')}</span>
                  <Select value={certificateForm.nodeId || undefined} onValueChange={(nodeId) => setCertificateForm((c) => ({ ...c, nodeId }))}>
                    <SelectTrigger><SelectValue placeholder={t('cluster.certNodePlaceholder')} /></SelectTrigger>
                    <SelectContent>
                      {(nodes?.items || []).map((node) => (
                        <SelectItem key={node.node_id} value={node.node_id} disabled={node.revoked}>
                          {node.node_id} · {roleLabelText(node.role, t)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </label>
                <label>
                  <span>{t('cluster.certCSR')}</span>
                  <Textarea rows={5} placeholder="-----BEGIN CERTIFICATE REQUEST-----" value={certificateForm.csr || ''} onChange={(e) => setCertificateForm((c) => ({ ...c, csr: e.target.value }))} />
                </label>
              </div>
              <div className="cluster-cert-actions">
                <Button loading={rotateCertificateMutation.isPending} disabled={rotateCertificateMutation.isPending} onClick={() => void submitCertificateSigning()}>
                  <ShieldCheck size={16} />{t('cluster.certSubmit')}
                </Button>
              </div>
            </div>
            {latestCertificate && (
              <div className="cluster-result-note cluster-result-note-ok cluster-cert-result">
                <strong>{t('cluster.certResultTitle')}</strong>
                <span>{t('cluster.certResultHint')}</span>
                <span>{t('cluster.nodeID')}: <code>{latestCertificate.node.node_id}</code></span>
                <span>{t('cluster.certSerial')}: <code>{latestCertificate.node.certificate_serial}</code></span>
                <span>{t('cluster.nodeCertExpiry')}: {formatTimestamp(latestCertificate.node.certificate_expiry)}</span>
                <div className="cluster-cert-result-actions">
                  <Button variant="outline" onClick={() => void copyText(latestCertificate.certificates.cert, t('cluster.copied'), t('cluster.copyFailed'))}>
                    <Copy size={15} />{t('cluster.copyCertificate')}
                  </Button>
                  <Button variant="outline" onClick={() => void copyText(latestCertificate.certificates.ca, t('cluster.copied'), t('cluster.copyFailed'))}>
                    <Copy size={15} />{t('cluster.copyCA')}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </Card>

        <Card id="cluster-deploy-wizard" className="cluster-deploy-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><PackageCheck size={18} /></span>
            <div>
              <CardTitle>{t('cluster.deployWizardTitle')}</CardTitle>
              <CardDescription>{t('cluster.deployWizardHint')}</CardDescription>
            </div>
          </div>
          <div className="cluster-deploy-steps flex flex-wrap gap-2 mb-4">
            {[
              t('cluster.deployWizardStepMethod'),
              t('cluster.deployWizardStepTarget'),
              deployMethod === 'ssh' ? t('cluster.deployWizardStepPrecheck') : t('cluster.deployWizardStepPackage'),
              t('cluster.deployWizardStepResult'),
            ].map((title, index) => (
              <div key={title} className={`rounded-md border px-3 py-1 text-sm ${index <= deployWizardStep ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}`}>
                {index + 1}. {title}
              </div>
            ))}
          </div>

          <div className="cluster-deploy-methods" role="radiogroup" aria-label={t('cluster.deployWizardMethodLabel')}>
            <button type="button" role="radio" aria-checked={deployMethod === 'ansible'} className={`cluster-deploy-method ${deployMethod === 'ansible' ? 'cluster-deploy-method-active' : ''}`} onClick={() => { setDeployMethod('ansible'); setDeployWizardStep(0); }}>
              <strong>{t('cluster.deployWizardMethodAnsible')}</strong>
              <span>{t('cluster.deployWizardMethodAnsibleHint')}</span>
            </button>
            <button type="button" role="radio" aria-checked={deployMethod === 'ssh'} className={`cluster-deploy-method ${deployMethod === 'ssh' ? 'cluster-deploy-method-active' : ''}`} onClick={() => { setDeployMethod('ssh'); setDeployWizardStep(0); }}>
              <strong>{t('cluster.deployWizardMethodSSH')}</strong>
              <span>{t('cluster.deployWizardMethodSSHHint')}</span>
            </button>
          </div>

          {deployMethod === 'ansible' ? (
            <div className="cluster-wizard-panel">
              <div className="cluster-deploy-form">
                <div className="cluster-ansible-summary">
                  <label>
                    <span>{t('cluster.deployWizardClusterID')}</span>
                    <Input placeholder="cheesewaf-mesh" value={ansibleForm.clusterId || ''} onChange={(e) => setAnsibleForm((c) => ({ ...c, clusterId: e.target.value }))} />
                    <em>{t('cluster.deployWizardClusterIDHint')}</em>
                  </label>
                  <label>
                    <span>{t('cluster.deployWizardChannel')}</span>
                    <Select value={ansibleForm.channel || 'canary'} onValueChange={(channel) => setAnsibleForm((c) => ({ ...c, channel }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="dev">{t('cluster.channelDev')}</SelectItem>
                        <SelectItem value="canary">{t('cluster.channelCanary')}</SelectItem>
                        <SelectItem value="stable">{t('cluster.channelStable')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <em>{t('cluster.deployWizardChannelHint')}</em>
                  </label>
                </div>
              </div>
              <div className="cluster-ansible-node-list">
                <div className="cluster-section-title">
                  <strong>{t('cluster.deployWizardAnsibleNodes')}</strong>
                  <Button size="sm" variant="outline" onClick={addAnsibleNode}><Plus size={15} />{t('cluster.deployWizardAddNode')}</Button>
                </div>
                {ansibleNodes.map((node, index) => (
                  <div className="cluster-ansible-node" key={node.name ? `ansible-node-${node.name}-${index}` : `ansible-node-${index}`}>
                    <Input value={node.name} placeholder={t('cluster.deployWizardNodeName')} onChange={(e) => updateAnsibleNode(index, { name: e.target.value })} />
                    <Input value={node.address} placeholder={t('cluster.deployWizardNodeAddress')} onChange={(e) => updateAnsibleNode(index, { address: e.target.value })} />
                    <Select value={node.role} onValueChange={(role) => updateAnsibleNode(index, { role })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="waf">{t('cluster.roleWaf')}</SelectItem>
                        <SelectItem value="monitor">{t('cluster.roleMonitor')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input type="number" min={1} max={65535} value={node.ssh_port} onChange={(e) => updateAnsibleNode(index, { ssh_port: Number(e.target.value || 22) })} />
                    <Input value={node.region || ''} placeholder={t('cluster.deployWizardNodeRegion')} onChange={(e) => updateAnsibleNode(index, { region: e.target.value })} />
                    <Button variant="outline" disabled={ansibleNodes.length <= 1} onClick={() => removeAnsibleNode(index)}><Trash2 size={15} />{t('common.delete')}</Button>
                  </div>
                ))}
              </div>
              <div className="cluster-deploy-actions">
                <Button loading={ansiblePackageMutation.isPending} disabled={ansiblePackageMutation.isPending} onClick={() => ansiblePackageMutation.mutate()}>
                  <PackageCheck size={16} />{t('cluster.deployWizardGeneratePackage')}
                </Button>
                <Button variant="outline" onClick={resetDeploymentWizard}><RotateCcw size={16} />{t('common.reset')}</Button>
              </div>
              {ansiblePackage && (
                <AnsiblePackageViewer pkg={ansiblePackage} selectedFile={selectedAnsibleFile} setSelectedFile={setSelectedAnsibleFile} t={t} />
              )}
            </div>
          ) : (
            <div className="cluster-wizard-panel">
              <div className="cluster-deploy-form">
                <div className="cluster-deploy-fields">
                  <label>
                    <span>{t('cluster.deployHost')}</span>
                    <Input placeholder="192.0.2.10" value={deployForm.host || ''} onFocus={() => setDeployWizardStep(1)} onChange={(e) => setDeployForm((c) => ({ ...c, host: e.target.value }))} />
                    <em>{t('cluster.deployWizardHostHint')}</em>
                  </label>
                  <label>
                    <span>{t('cluster.deployUser')}</span>
                    <Input placeholder="root" value={deployForm.user || ''} onFocus={() => setDeployWizardStep(1)} onChange={(e) => setDeployForm((c) => ({ ...c, user: e.target.value }))} />
                  </label>
                  <label>
                    <span>{t('cluster.deployPort')}</span>
                    <Input type="number" min={1} max={65535} value={deployForm.port ?? 22} onFocus={() => setDeployWizardStep(1)} onChange={(e) => setDeployForm((c) => ({ ...c, port: Number(e.target.value || 22) }))} />
                  </label>
                  <label>
                    <span>{t('cluster.deployAction')}</span>
                    <Select value={deployForm.action || 'install'} onValueChange={(action) => { setDeployForm((c) => ({ ...c, action })); setDeployWizardStep(1); }}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="install">{t('cluster.deployActionInstall')}</SelectItem>
                        <SelectItem value="rollback-install">{t('cluster.deployActionRollbackInstall')}</SelectItem>
                        <SelectItem value="restart-service">{t('cluster.deployActionRestart')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <em>{t('cluster.deployWizardActionHint')}</em>
                  </label>
                </div>
                <div className="cluster-credential-panel">
                  <div className="cluster-section-title">
                    <strong>{t('cluster.deployWizardAuthTitle')}</strong>
                    <span>{t('cluster.deployWizardAuthHint')}</span>
                  </div>
                  <RadioGroup className="flex flex-wrap gap-4" value={deployAuthMethod} onValueChange={(value) => setDeployAuthMethod(value as DeployAuthMethod)}>
                    <label className="flex items-center gap-2"><RadioGroupItem value="agent" id="auth-agent" /><span>{t('cluster.deployWizardAuthAgent')}</span></label>
                    <label className="flex items-center gap-2"><RadioGroupItem value="password" id="auth-password" /><span>{t('cluster.deployWizardAuthPassword')}</span></label>
                    <label className="flex items-center gap-2"><RadioGroupItem value="private_key" id="auth-key" /><span>{t('cluster.deployWizardAuthPrivateKey')}</span></label>
                  </RadioGroup>
                  {deployAuthMethod === 'password' && (
                    <label>
                      <span>{t('cluster.deployPassword')}</span>
                      <Input type="password" autoComplete="new-password" placeholder={t('cluster.deployPasswordPlaceholder')} value={deployForm.password || ''} onChange={(e) => setDeployForm((c) => ({ ...c, password: e.target.value }))} />
                      <em>{t('cluster.deployPasswordHint')}</em>
                    </label>
                  )}
                  {deployAuthMethod === 'private_key' && (
                    <label>
                      <span>{t('cluster.deployPrivateKey')}</span>
                      <Textarea rows={4} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" value={deployForm.privateKey || ''} onChange={(e) => setDeployForm((c) => ({ ...c, privateKey: e.target.value }))} />
                      <em>{t('cluster.deployPrivateKeyHint')}</em>
                    </label>
                  )}
                </div>
                <div className="cluster-hostkey-panel">
                  <div className="cluster-section-title">
                    <strong>{t('cluster.deployWizardHostKeyTitle')}</strong>
                    <span>{t('cluster.deployWizardHostKeyHint')}</span>
                  </div>
                  <label>
                    <span>{t('cluster.deployHostKey')}</span>
                    <Input placeholder="SHA256:..." value={deployForm.hostKeySHA256 || ''} onChange={(e) => setDeployForm((c) => ({ ...c, hostKeySHA256: e.target.value }))} />
                    <em>{t('cluster.deployHostKeyHint')}</em>
                  </label>
                </div>
                <div className="cluster-deploy-actions">
                  <Button variant="outline" loading={deployTaskMutation.isPending} disabled={deployTaskMutation.isPending} onClick={() => void submitDeployment('check')}>
                    <ShieldCheck size={16} />{t('cluster.deployWizardRunPrecheck')}
                  </Button>
                  <Button loading={deployTaskMutation.isPending} disabled={deployTaskMutation.isPending || !activeDeployTask || activeDeployTask.action !== 'check' || activeDeployTask.status !== 'succeeded'} onClick={() => void submitDeployment('run')}>
                    <Play size={16} />{t('cluster.deployWizardStartAction')}
                  </Button>
                  <Button variant="outline" disabled={deployTaskMutation.isPending} onClick={resetDeploymentWizard}>
                    <RotateCcw size={16} />{t('common.reset')}
                  </Button>
                </div>
              </div>
              <DeploymentTaskPanel
                activeDeployTask={activeDeployTask}
                deployTasks={deployTasks?.items || []}
                isFetchingDeployTasks={isFetchingDeployTasks}
                setActiveDeployTaskId={setActiveDeployTaskId}
                refetchDeployTasks={refetchDeployTasks}
                t={t}
              />
            </div>
          )}
        </Card>

        <Card className="cluster-audit-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon cluster-icon-safe"><ShieldCheck size={18} /></span>
            <div>
              <CardTitle>{t('cluster.auditTitle')}</CardTitle>
              <CardDescription>{t('cluster.auditHint')}</CardDescription>
            </div>
          </div>
          <div className="cluster-audit-toolbar">
            <Badge variant="default">{t('cluster.auditScopeTag')}</Badge>
            <Button size="sm" variant="outline" loading={isFetchingAudit} onClick={() => void refetchAudit()}>{t('cluster.auditRefresh')}</Button>
          </div>
          {isAuditError && (
            <div className="cluster-result-note cluster-result-note-error cluster-inline-error">
              <strong>{t('cluster.auditLoadFailed')}</strong>
              <span>{errorMessage(auditError)}</span>
              <Button size="sm" variant="outline" onClick={() => void refetchAudit()}>{t('common.retry')}</Button>
            </div>
          )}
          {!isAuditError && !auditEntries.length && !isFetchingAudit && (
            <div className="cluster-result-note cluster-result-note-muted">
              <strong>{t('cluster.auditEmptyTitle')}</strong>
              <span>{t('cluster.auditEmptyHint')}</span>
            </div>
          )}
          <div className="table-scroll cluster-audit-table">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('cluster.auditTime')}</TableHead>
                  <TableHead>{t('cluster.auditSourceType')}</TableHead>
                  <TableHead>{t('cluster.auditAction')}</TableHead>
                  <TableHead>{t('cluster.auditActor')}</TableHead>
                  <TableHead>{t('cluster.auditStatus')}</TableHead>
                  <TableHead>{t('cluster.auditMessage')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(auditEntries.length > 10 ? auditEntries.slice(auditPage * 10, (auditPage + 1) * 10) : auditEntries).map((entry) => (
                  <TableRow key={clusterAuditRowKey(entry)}>
                    <TableCell><span className="nowrap-cell" title={entry.timestamp}>{formatTimestamp(entry.timestamp) || '-'}</span></TableCell>
                    <TableCell><ClusterAuditSourceCell entry={entry} t={t} /></TableCell>
                    <TableCell><span className="cluster-audit-text">{clusterAuditAction(entry, t)}</span></TableCell>
                    <TableCell><span className="cluster-audit-text">{clusterAuditActor(entry, t)}</span></TableCell>
                    <TableCell>{clusterAuditStatusTag(entry, t)}</TableCell>
                    <TableCell><span className="cluster-audit-message">{clusterAuditMessage(entry, t)}</span></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {auditEntries.length > 10 && (
              <div className="flex justify-end gap-2 py-2">
                <Button size="sm" variant="outline" disabled={auditPage <= 0} onClick={() => setAuditPage((p) => p - 1)}>{t('common.prev')}</Button>
                <span className="text-sm text-muted-foreground">{auditPage + 1}/{Math.ceil(auditEntries.length / 10)}</span>
                <Button size="sm" variant="outline" disabled={auditPage >= Math.ceil(auditEntries.length / 10) - 1} onClick={() => setAuditPage((p) => p + 1)}>{t('common.next')}</Button>
              </div>
            )}
          </div>
          <div className="mobile-card-list cluster-audit-cards">
            {auditEntries.map((entry) => (
              <ClusterAuditEntryCard key={clusterAuditRowKey(entry)} entry={entry} t={t} />
            ))}
          </div>
        </Card>
      </div>

      <Dialog open={Boolean(revokeConfirmID)} onOpenChange={(open) => { if (!open) setRevokeConfirmID(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('cluster.revokeConfirmTitle')}</DialogTitle>
            <DialogDescription>{t('cluster.revokeConfirmContent')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeConfirmID(null)}>{t('common.cancel')}</Button>
            <Button
              variant="destructive"
              loading={Boolean(revokingTokenID)}
              onClick={() => {
                if (revokeConfirmID) {
                  revokeTokenMutation.mutate(revokeConfirmID);
                  setRevokeConfirmID(null);
                }
              }}
            >
              {t('common.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}

function clusterModeLabel(mode: string | undefined, fallback: string | undefined, t: Translate) {
  switch (mode) {
    case 'standalone':
    case 'single-node':
      return t('cluster.modeStandalone');
    case 'dual-node-load-balancing':
      return t('cluster.modeDualNodeLoadBalancing');
    case 'minimum-ha':
      return t('cluster.modeMinimumHA');
    case 'multi-node-ha':
      return t('cluster.modeMultiNodeHA');
    case 'protection':
      return t('cluster.modeProtection');
    default:
      return fallback || t('cluster.modeInitializing');
  }
}

function consensusLabel(provider: string | undefined, t: Translate) {
  switch (provider) {
    case '':
    case undefined:
    case 'builtin':
      return t('cluster.consistencyBuiltin');
    case 'etcd':
      return t('cluster.consistencyEtcd');
    default:
      return provider;
  }
}

function roleTag(role: string, t: Translate) {
  if (role === 'monitor') {
    return <Badge variant="default">{t('cluster.roleMonitor')}</Badge>;
  }
  if (role === 'waf') {
    return <Badge variant="success">{t('cluster.roleWaf')}</Badge>;
  }
  return <Badge variant="secondary">{role ? t('cluster.roleUnknown', { role }) : t('common.unknown')}</Badge>;
}

function runtimeStateTag(item: ClusterNodeRegistration, t: Translate) {
  const state = item.runtime?.state || 'unknown';
  switch (state) {
    case 'online':
      return <Badge variant="success">{item.runtime?.local ? t('cluster.nodeStateLocal') : t('cluster.nodeStateOnline')}</Badge>;
    case 'stale':
      return <Badge variant="warning">{t('cluster.nodeStateStale')}</Badge>;
    case 'unknown':
      return <Badge variant="secondary">{t('cluster.nodeStateUnknown')}</Badge>;
    default:
      return <Badge variant="secondary">{state}</Badge>;
  }
}

function formatRuntimeHeartbeat(item: ClusterNodeRegistration) {
  if (item.runtime?.last_heartbeat_at) {
    return formatTimestamp(item.runtime.last_heartbeat_at);
  }
  if (item.runtime?.local) {
    return '-';
  }
  return item.runtime?.reason || '-';
}

function roleLabelText(role: string, t: Translate) {
  if (role === 'monitor') {
    return t('cluster.roleMonitor');
  }
  if (role === 'waf') {
    return t('cluster.roleWaf');
  }
  return role ? t('cluster.roleUnknown', { role }) : t('common.unknown');
}

function deployTaskResultClass(status: string) {
  switch (status) {
    case 'succeeded':
      return 'cluster-result-note-ok';
    case 'failed':
      return 'cluster-result-note-error';
    default:
      return 'cluster-result-note-muted';
  }
}

function DeploymentTaskTimeline({ task, t }: { task: ClusterDeploymentTask; t: Translate }) {
  const events = (task.events || []).filter(hasDeploymentEventDetail);
  if (!events.length) {
    return (
      <div className="cluster-task-timeline cluster-task-timeline-empty">
        <strong>{t('cluster.deployTimelineTitle')}</strong>
        <span>{t('cluster.deployTimelineEmpty')}</span>
      </div>
    );
  }

  return (
    <div className="cluster-task-timeline">
      <div className="cluster-task-timeline-head">
        <strong>{t('cluster.deployTimelineTitle')}</strong>
        <span>{t('cluster.deployTimelineCount', { count: events.length })}</span>
      </div>
      <ol className="cluster-task-events">
        {events.map((event, index) => {
          const eventTime = deploymentEventTime(event);
          return (
            <li className="cluster-task-event" key={`${eventTime}-${event.event || event.stage || 'event'}-${index}`}>
              <span className="cluster-task-event-dot" aria-hidden="true" />
              <div className="cluster-task-event-body">
                <div className="cluster-task-event-head">
                  <strong>{deploymentEventTitle(event, t)}</strong>
                  {deployTaskStatusTag(event.status || task.status, t)}
                </div>
                {eventTime && (
                  <time dateTime={eventTime}>{formatTimestamp(eventTime)}</time>
                )}
                {deploymentEventMessage(event, t) ? <p>{deploymentEventMessage(event, t)}</p> : null}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function hasDeploymentEventDetail(event: ClusterDeploymentTaskEvent) {
  return Boolean(event.at || event.timestamp || event.event || event.stage || event.status || event.message);
}

function deploymentEventTime(event: ClusterDeploymentTaskEvent) {
  return event.at || event.timestamp || '';
}

function deploymentEventTitle(event: ClusterDeploymentTaskEvent, t: Translate) {
  if (event.event === 'credentials_discarded') {
    return t('cluster.deployStageCredentialsDiscarded');
  }
  if (isCompensationEvent(event.event || event.stage || '')) {
    return t('cluster.deployStageCompensation');
  }
  return deployStageLabel(event.stage || event.event || '', t);
}

function deploymentEventMessage(event: ClusterDeploymentTaskEvent, t: Translate) {
  const normalized = (event.message || '').trim();
  const fallback = defaultDeploymentEventMessage(event.event || event.stage || '', t);
  if (!normalized || isKnownDeploymentBackendMessage(normalized)) {
    return fallback;
  }
  return displayTaskText(normalized);
}

function defaultDeploymentEventMessage(event: string, t: Translate) {
  switch (event) {
    case 'queued':
      return t('cluster.deployEventQueued');
    case 'validating':
      return t('cluster.deployEventValidating');
    case 'connecting':
      return t('cluster.deployEventConnecting');
    case 'checked':
      return t('cluster.deployEventChecked');
    case 'deployed':
      return t('cluster.deployEventDeployed');
    case 'compensating':
      return t('cluster.deployEventCompensating');
    case 'compensated':
      return t('cluster.deployEventCompensated');
    case 'compensation_failed':
      return t('cluster.deployEventCompensationFailed');
    case 'compensation_not_applicable':
      return t('cluster.deployEventCompensationNotApplicable');
    case 'credentials_discarded':
      return t('cluster.deployEventCredentialsDiscarded');
    default:
      return '';
  }
}

function DeploymentCompensationResult({ task, t }: { task: ClusterDeploymentTask; t: Translate }) {
  const result = task.compensation_result;
  if (!result) {
    return null;
  }
  return (
    <div className="cluster-result-note cluster-result-note-muted">
      <strong>{t('cluster.deployCompensationTitle')}</strong>
      <span>{t('cluster.deployCompensationStatus')}: {compensationStatusLabel(result.status, t)}</span>
      {result.action ? <span>{t('cluster.deployCompensationAction')}: {compensationActionLabel(result.action, t)}</span> : null}
      {result.message ? <span>{displayTaskText(result.message)}</span> : null}
      {result.started_at ? <span>{t('cluster.deployCompensationStarted')}: {formatTimestamp(result.started_at)}</span> : null}
      {result.finished_at ? <span>{t('cluster.deployCompensationFinished')}: {formatTimestamp(result.finished_at)}</span> : null}
      {result.output ? <pre>{displayTaskText(result.output)}</pre> : null}
      {result.error ? <pre>{displayTaskText(result.error)}</pre> : null}
      {result.output_truncated ? <small>{t('cluster.deployOutputTruncated')}</small> : null}
    </div>
  );
}

function DeploymentTaskPanel({
  activeDeployTask,
  deployTasks,
  isFetchingDeployTasks,
  setActiveDeployTaskId,
  refetchDeployTasks,
  t,
}: {
  activeDeployTask: ClusterDeploymentTask | null;
  deployTasks: ClusterDeploymentTask[];
  isFetchingDeployTasks: boolean;
  setActiveDeployTaskId: (id: string) => void;
  refetchDeployTasks: () => void | Promise<unknown>;
  t: Translate;
}) {
  return (
    <div className="cluster-deploy-results">
      {activeDeployTask ? (
        <div className={`cluster-result-note ${deployTaskResultClass(activeDeployTask.status)}`}>
          <div className="cluster-task-summary-line">
            <strong>{t('cluster.deployTaskCurrent')}</strong>
            {deployTaskStatusTag(activeDeployTask.status, t)}
          </div>
          <span>{activeDeployTask.user}@{activeDeployTask.host}:{activeDeployTask.port} · {deployActionLabel(activeDeployTask.action, t)} · {deployStageLabel(activeDeployTask.stage, t)}</span>
          <span>{t('cluster.deployTaskID')}: <code>{activeDeployTask.id}</code></span>
          <DeploymentTaskTimeline task={activeDeployTask} t={t} />
          {activeDeployTask.command?.length ? <code>{activeDeployTask.command.join(' ')}</code> : null}
          {activeDeployTask.message ? <span>{displayTaskText(activeDeployTask.message)}</span> : null}
          {activeDeployTask.output ? <pre>{displayTaskText(activeDeployTask.output)}</pre> : null}
          {activeDeployTask.error ? <pre>{displayTaskText(activeDeployTask.error)}</pre> : null}
          {activeDeployTask.output_truncated && <small>{t('cluster.deployOutputTruncated')}</small>}
          <DeploymentCompensationResult task={activeDeployTask} t={t} />
        </div>
      ) : (
        <div className="cluster-result-note cluster-result-note-muted">
          <strong>{t('cluster.deployTasksEmpty')}</strong>
          <span>{t('cluster.deployTasksEmptyHint')}</span>
        </div>
      )}
      <div className="table-scroll cluster-deploy-task-table relative">
        {isFetchingDeployTasks && !deployTasks.length && <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/40"><Spinner /></div>}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('cluster.deployTaskID')}</TableHead>
              <TableHead>{t('cluster.deployHost')}</TableHead>
              <TableHead>{t('cluster.deployAction')}</TableHead>
              <TableHead>{t('cluster.deployTaskStatus')}</TableHead>
              <TableHead>{t('cluster.deployTaskUpdated')}</TableHead>
              <TableHead>{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {deployTasks.map((item) => (
              <TableRow key={item.id}>
                <TableCell><code>{item.id}</code></TableCell>
                <TableCell>{item.user}@{item.host}:{item.port}</TableCell>
                <TableCell>{deployActionLabel(item.action, t)}</TableCell>
                <TableCell>{deployTaskStatusTag(item.status, t)}</TableCell>
                <TableCell>{formatTimestamp(item.updated_at)}</TableCell>
                <TableCell>
                  <Button size="sm" variant="outline" onClick={() => setActiveDeployTaskId(item.id)}>{t('cluster.deployTaskView')}</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="mobile-card-list cluster-deploy-task-cards">
        {deployTasks.map((task) => (
          <DeploymentTaskCard key={task.id} task={task} setActiveDeployTaskId={setActiveDeployTaskId} t={t} />
        ))}
      </div>
      <Button size="sm" loading={isFetchingDeployTasks} onClick={() => void refetchDeployTasks()}>{t('cluster.deployTaskRefresh')}</Button>
    </div>
  );
}

function DeploymentTaskCard({ task, setActiveDeployTaskId, t }: { task: ClusterDeploymentTask; setActiveDeployTaskId: (id: string) => void; t: Translate }) {
  return (
    <article className="mobile-data-card cluster-deploy-task-card-mobile">
      <header>
        <strong>{task.host}</strong>
        {deployTaskStatusTag(task.status, t)}
      </header>
      <dl>
        <div><dt>{t('cluster.deployTaskID')}</dt><dd><code className="table-code">{task.id}</code></dd></div>
        <div><dt>{t('cluster.deployHost')}</dt><dd>{task.user}@{task.host}:{task.port}</dd></div>
        <div><dt>{t('cluster.deployAction')}</dt><dd>{deployActionLabel(task.action, t)}</dd></div>
        <div><dt>{t('cluster.deployTaskUpdated')}</dt><dd>{formatTimestamp(task.updated_at)}</dd></div>
      </dl>
      <Button size="sm" onClick={() => setActiveDeployTaskId(task.id)}>{t('cluster.deployTaskView')}</Button>
    </article>
  );
}

function AnsiblePackageViewer({
  pkg,
  selectedFile,
  setSelectedFile,
  t,
}: {
  pkg: ClusterAnsiblePackage;
  selectedFile: string;
  setSelectedFile: (file: string) => void;
  t: Translate;
}) {
  const files = Object.keys(pkg.files || {}).sort();
  const activeFile = selectedFile && pkg.files[selectedFile] !== undefined ? selectedFile : files[0] || '';
  const content = activeFile ? pkg.files[activeFile] || '' : '';
  return (
    <div className="cluster-ansible-package">
      <div className="cluster-section-title">
        <div>
          <strong>{t('cluster.deployWizardPackageReady')}</strong>
          <span>{t('cluster.deployWizardPackageReadyHint')}</span>
        </div>
        <div className="cluster-ansible-package-actions">
          <Button variant="outline" disabled={!activeFile} onClick={() => downloadTextFile(activeFile, content)}><Download size={15} />{t('cluster.deployWizardDownloadFile')}</Button>
          <Button variant="outline" onClick={() => downloadAnsiblePackage(pkg)}><Download size={15} />{t('cluster.deployWizardDownloadPackage')}</Button>
        </div>
      </div>
      <div className="cluster-ansible-file-picker">
        <Select value={activeFile} onValueChange={(value) => setSelectedFile(value)}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            {files.map((file) => (
              <SelectItem key={file} value={file}>{file}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" disabled={!content} onClick={() => void copyText(content, t('cluster.copied'), t('cluster.copyFailed'))}>
          <Copy size={15} />{t('common.copy')}
        </Button>
      </div>
      <pre className="cluster-ansible-preview">{content || t('cluster.deployWizardPackageEmpty')}</pre>
    </div>
  );
}

function ClusterAuditSourceCell({ entry, t }: { entry: ClusterAuditEntry; t: Translate }) {
  return (
    <span className="cluster-audit-source">
      <Badge variant={clusterAuditSourceVariant(entry.source)}>{clusterAuditSourceLabel(entry.source, t)}</Badge>
      <span className="cluster-audit-type">{clusterAuditEventTypeLabel(entry.event_type, t)}</span>
    </span>
  );
}

function ClusterAuditEntryCard({ entry, t }: { entry: ClusterAuditEntry; t: Translate }) {
  return (
    <article className="mobile-data-card cluster-audit-card-mobile">
      <header>
        <strong>{clusterAuditAction(entry, t)}</strong>
        {clusterAuditStatusTag(entry, t)}
      </header>
      <dl>
        <div><dt>{t('cluster.auditTime')}</dt><dd>{formatTimestamp(entry.timestamp) || '-'}</dd></div>
        <div><dt>{t('cluster.auditSourceType')}</dt><dd><ClusterAuditSourceCell entry={entry} t={t} /></dd></div>
        <div><dt>{t('cluster.auditActor')}</dt><dd>{clusterAuditActor(entry, t)}</dd></div>
        <div><dt>{t('cluster.auditTarget')}</dt><dd><code className="table-code" title={clusterAuditTarget(entry)}>{clusterAuditTarget(entry) || '-'}</code></dd></div>
        <div><dt>{t('cluster.auditRemoteIP')}</dt><dd>{entry.remote_ip || '-'}</dd></div>
        <div><dt>{t('cluster.auditMessage')}</dt><dd>{clusterAuditMessage(entry, t)}</dd></div>
      </dl>
    </article>
  );
}

function clusterAuditRowKey(entry: ClusterAuditEntry) {
  return entry.id || [entry.timestamp, entry.source, entry.event_type, entry.task_id, entry.path].filter(Boolean).join('-');
}

function clusterAuditAction(entry: ClusterAuditEntry, t: Translate) {
  const action = String(entry.action || '').trim();
  if (action) {
    return clusterAuditActionLabel(action, entry, t);
  }
  if (entry.method) {
    return entry.method;
  }
  return clusterAuditEventTypeLabel(entry.event_type, t);
}

function clusterAuditActionLabel(action: string, entry: ClusterAuditEntry, t: Translate) {
  if (isDeployAuditSource(entry.source)) {
    switch (action) {
      case 'check':
      case 'install':
      case 'restart-service':
        return deployActionLabel(action, t);
      default:
        return deployStageLabel(action, t);
    }
  }
  switch (action) {
    case 'view_status':
      return t('cluster.auditActionViewStatus');
    case 'list_nodes':
      return t('cluster.auditActionListNodes');
    case 'generate_ansible_package':
      return t('cluster.auditActionGeneratePackage');
    case 'ssh_precheck':
      return t('cluster.auditActionSSHPrecheck');
    case 'ssh_run':
      return t('cluster.auditActionSSHRun');
    case 'start_deploy_task':
      return t('cluster.auditActionStartDeployTask');
    case 'view_deploy_task':
      return t('cluster.auditActionViewDeployTask');
    case 'create_join_token':
      return t('cluster.auditActionCreateJoinToken');
    case 'revoke_join_token':
      return t('cluster.auditActionRevokeJoinToken');
    case 'rotate_node_certificate':
      return t('cluster.auditActionRotateNodeCertificate');
    case 'revoke_node':
      return t('cluster.auditActionRevokeNode');
    case 'join_cluster':
      return t('cluster.auditActionJoinCluster');
    default:
      return displayTaskText(action.replace(/_/g, ' ')) || t('common.unknown');
  }
}

function clusterAuditActor(entry: ClusterAuditEntry, t: Translate) {
  const actor = String(entry.actor || '').trim();
  const role = String(entry.role || '').trim();
  if (actor && role) {
    return `${actor} / ${role}`;
  }
  if (actor) {
    return actor;
  }
  if (role) {
    return role;
  }
  return isDeployAuditSource(entry.source) ? t('cluster.auditActorSystem') : '-';
}

function clusterAuditTarget(entry: ClusterAuditEntry) {
  if (entry.target) {
    return entry.target;
  }
  if (entry.path) {
    return entry.path;
  }
  if (entry.node_id) {
    return entry.node_id;
  }
  if (entry.task_id) {
    return entry.task_id;
  }
  return '';
}

function clusterAuditMessage(entry: ClusterAuditEntry, t: Translate) {
  const message = displayTaskText(String(entry.message || '').trim());
  if (isDeployAuditSource(entry.source)) {
    const event = entry.action || entry.event_type || '';
    const fallback = defaultDeploymentEventMessage(event, t) || clusterAuditEventTypeLabel(entry.event_type, t);
    if (!message || isKnownDeploymentBackendMessage(message)) {
      return fallback || '-';
    }
  }
  if (message) {
    return message;
  }
  if (typeof entry.latency_ms === 'number' && entry.latency_ms >= 0) {
    return t('cluster.auditLatencyMessage', { ms: entry.latency_ms });
  }
  return '-';
}

function clusterAuditStatusTag(entry: ClusterAuditEntry, t: Translate) {
  const status = String(entry.status || '').trim();
  const numericStatus = Number(status);
  if (status && Number.isFinite(numericStatus) && numericStatus > 0) {
    return httpStatusTag(numericStatus);
  }
  switch (status.toLowerCase()) {
    case 'pending':
    case 'running':
    case 'succeeded':
    case 'failed':
    case 'cancelled':
      return deployTaskStatusTag(status.toLowerCase(), t);
    case 'ok':
    case 'success':
      return <Badge variant="success">{t('cluster.auditStatusOK')}</Badge>;
    case 'error':
    case 'rejected':
      return <Badge variant="destructive">{t('cluster.auditStatusFailed')}</Badge>;
    default:
      break;
  }
  if (typeof entry.status_code === 'number' && entry.status_code > 0) {
    return httpStatusTag(entry.status_code);
  }
  return status ? <Badge variant="secondary">{status}</Badge> : <Badge variant="secondary">-</Badge>;
}

function httpStatusTag(status: number) {
  return <Badge variant={status >= 400 ? 'destructive' : 'success'}>{status}</Badge>;
}

function clusterAuditSourceLabel(source: string, t: Translate) {
  switch (source) {
    case 'management_api':
    case 'management-api':
    case 'api':
      return t('cluster.auditSourceManagementAPI');
    case 'deploy_task':
    case 'deployment_task':
    case 'deployment-task':
      return t('cluster.auditSourceDeploymentTask');
    case 'cluster_join':
    case 'node_join':
      return t('cluster.auditSourceClusterJoin');
    default:
      return source || t('common.unknown');
  }
}

function clusterAuditSourceVariant(source: string): 'success' | 'default' | 'secondary' {
  if (isDeployAuditSource(source)) {
    return 'success';
  }
  if (source === 'cluster_join' || source === 'node_join') {
    return 'default';
  }
  return 'default';
}

function clusterAuditEventTypeLabel(eventType: string, t: Translate) {
  switch (eventType) {
    case 'management_api':
    case 'management_request':
    case 'request':
      return t('cluster.auditTypeManagementRequest');
    case 'deploy_task':
    case 'deployment_task':
    case 'deployment_task_event':
      return t('cluster.auditTypeDeploymentEvent');
    case 'cluster_join':
    case 'node_join':
    case 'node_enrollment':
    case 'node_enrolled':
      return t('cluster.auditTypeNodeEnrollment');
    default:
      return deployStageLabel(eventType || '', t);
  }
}

function isDeployAuditSource(source: string) {
  return source === 'deploy_task' || source === 'deployment_task' || source === 'deployment-task';
}

function isCompensationEvent(event: string) {
  return event === 'compensating' || event === 'compensated' || event === 'compensation_failed' || event === 'compensation_not_applicable';
}

function compensationStatusLabel(status: string, t: Translate) {
  switch (status) {
    case 'succeeded':
      return t('cluster.deployCompensationSucceeded');
    case 'failed':
      return t('cluster.deployCompensationFailed');
    case 'not_applicable':
      return t('cluster.deployCompensationNotApplicable');
    default:
      return status || t('common.unknown');
  }
}

function compensationActionLabel(action: string, t: Translate) {
  switch (action) {
    case 'start-service':
      return t('cluster.deployCompensationActionStartService');
    case 'none':
      return t('cluster.deployCompensationActionNone');
    default:
      return displayTaskText(action || t('common.unknown'));
  }
}

function deployTaskStatusTag(status: string, t: Translate) {
  switch (status) {
    case 'pending':
      return <Badge variant="secondary">{t('cluster.deployTaskPending')}</Badge>;
    case 'running':
      return <Badge variant="default">{t('cluster.deployTaskRunning')}</Badge>;
    case 'succeeded':
      return <Badge variant="success">{t('cluster.deployTaskSucceeded')}</Badge>;
    case 'failed':
      return <Badge variant="destructive">{t('cluster.deployTaskFailed')}</Badge>;
    case 'cancelled':
      return <Badge variant="warning">{t('cluster.deployTaskCancelled')}</Badge>;
    default:
      return <Badge variant="secondary">{status || t('common.unknown')}</Badge>;
  }
}

function deployActionLabel(action: string, t: Translate) {
  switch (action) {
    case 'check':
      return t('cluster.deployActionCheck');
    case 'install':
      return t('cluster.deployActionInstall');
    case 'rollback-install':
      return t('cluster.deployActionRollbackInstall');
    case 'restart-service':
      return t('cluster.deployActionRestart');
    default:
      return action || t('common.unknown');
  }
}

function deployStageLabel(stage: string, t: Translate) {
  switch (stage) {
    case 'queued':
      return t('cluster.deployStageQueued');
    case 'validating':
      return t('cluster.deployStageValidating');
    case 'connecting':
      return t('cluster.deployStageConnecting');
    case 'checked':
      return t('cluster.deployStageChecked');
    case 'deployed':
      return t('cluster.deployStageDeployed');
    case 'compensating':
    case 'compensated':
    case 'compensation_failed':
    case 'compensation_not_applicable':
      return t('cluster.deployStageCompensation');
    case 'failed':
      return t('cluster.deployStageFailed');
    case 'credentials_discarded':
      return t('cluster.deployStageCredentialsDiscarded');
    default:
      return stage || t('common.unknown');
  }
}

function isKnownDeploymentBackendMessage(message: string) {
  return [
    'Task queued',
    'Validating request locally',
    'Connecting to remote host',
    'SSH check completed',
    ['Deployment', 'completed'].join(' '),
    'Attempting deployment compensation',
    'One-time SSH credentials discarded',
  ].includes(String(message || '').trim());
}

function JoinCommandBlock({ token, fields, t }: { token: ClusterJoinToken; fields: JoinCommandFields; t: Translate }) {
  const joinCommand = buildJoinCommand(token, fields);
  const missingFields = missingJoinCommandFields(token, fields, t);
  return (
    <>
      <span>{t('cluster.joinCommand')}</span>
      {joinCommand ? (
        <>
          <code>{joinCommand}</code>
          <Button variant="outline" onClick={() => void copyText(joinCommand, t('cluster.copied'), t('cluster.copyFailed'))}><Copy size={15} />
            {t('cluster.copyJoinCommand')}
          </Button>
        </>
      ) : (
        <div className="cluster-result-note cluster-result-note-muted">
          <strong>{t('cluster.joinCommandMissingTitle')}</strong>
          <span>{t('cluster.joinCommandMissingFields', { fields: missingFields.join(', ') })}</span>
        </div>
      )}
    </>
  );
}

function missingJoinCommandFields(token: ClusterJoinToken, fields: JoinCommandFields, t: Translate) {
  const missing: string[] = [];
  if (!String(fields.controllerUrl || '').trim()) {
    missing.push(t('cluster.joinControllerUrl'));
  }
  if (!String(fields.nodeId || '').trim()) {
    missing.push(t('cluster.joinNodeId'));
  }
  if (!String(fields.advertiseAddr || '').trim()) {
    missing.push(t('cluster.joinAdvertiseAddr'));
  }
  if (!String(token.value || '').trim()) {
    missing.push(t('cluster.copyToken'));
  }
  return missing;
}

function buildJoinCommand(token: ClusterJoinToken, fields: JoinCommandFields) {
  const controllerUrl = String(fields.controllerUrl || '').trim();
  const nodeID = String(fields.nodeId || '').trim();
  const advertiseAddr = String(fields.advertiseAddr || '').trim();
  const tokenValue = String(token.value || '').trim();
  if (!controllerUrl || !nodeID || !advertiseAddr || !tokenValue) {
    return '';
  }
  const role = token.role === 'waf' || token.role === 'monitor' ? token.role : 'waf';
  const parts = [
    'cheesewaf',
    'cluster',
    'join',
    '--controller',
    shellArg(controllerUrl),
    '--token',
    shellArg(tokenValue),
    '--node-id',
    shellArg(nodeID),
    '--role',
    shellArg(role),
    '--advertise-addr',
    shellArg(advertiseAddr),
  ];
  return parts.join(' ');
}

function normalizeAnsibleNodes(nodes: ClusterAnsibleHost[]) {
  return nodes
    .map((node) => ({
      name: String(node.name || '').trim(),
      address: String(node.address || '').trim(),
      role: String(node.role || 'waf').trim(),
      ssh_port: Number(node.ssh_port || 22),
      region: String(node.region || '').trim() || undefined,
    }))
    .filter((node) => node.name || node.address);
}

function downloadAnsiblePackage(pkg: ClusterAnsiblePackage) {
  const files = pkg.files || {};
  const payload = JSON.stringify({ files }, null, 2);
  downloadTextFile('cheesewaf-cluster-ansible-package.json', payload, 'application/json;charset=utf-8');
}

function downloadTextFile(filename: string, content: string, type = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename.replace(/[\\/]/g, '_') || 'cheesewaf-cluster-file.txt';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function shellArg(value: string) {
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

function displayTaskText(value: string) {
  const oldRecoveryTerm = ['roll', 'back'].join('');
  return value
    .replace(new RegExp(`${oldRecoveryTerm}s?`, 'gi'), 'recovery attempts')
    .replace(new RegExp(['回', '滚'].join(''), 'g'), '恢复尝试');
}

async function copyText(value: string, successMessage: string, failureMessage: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(successMessage);
  } catch {
    toast.error(failureMessage);
  }
}

function formatTimestamp(value: string) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error || '');
}
