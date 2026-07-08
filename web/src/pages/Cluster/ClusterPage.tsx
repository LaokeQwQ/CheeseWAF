import { useState } from 'react';
import { Button, Card, Form, Input, InputNumber, Message as ArcoMessage, Popconfirm, Radio, Select, Spin, Steps, Table, Tag, Typography } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, Download, KeyRound, Network, PackageCheck, Play, Plus, RotateCcw, ShieldCheck, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { createClusterJoinToken, fetchClusterAudit, fetchClusterDeploymentTasks, fetchClusterJoinTokens, fetchClusterNodes, fetchClusterStatus, generateClusterAnsiblePackage, revokeClusterJoinToken, rotateClusterNodeCertificate, startClusterDeploymentTask } from '../../api/client';
import type { ClusterAnsibleHost, ClusterAnsiblePackage, ClusterAuditEntry, ClusterDeploymentRequest, ClusterDeploymentTask, ClusterDeploymentTaskEvent, ClusterJoinToken, ClusterJoinTokenCreateRequest, ClusterNodeCertificateRotateResponse } from '../../types/api';

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

type DeployMethod = 'ansible' | 'ssh';
type DeployAuthMethod = 'agent' | 'password' | 'private_key';
type DeployHostKeyMode = 'known_hosts' | 'fingerprint';

type Translate = (key: string, options?: Record<string, unknown>) => string;

export default function ClusterPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [form] = Form.useForm<ClusterDeployForm>();
  const [ansibleForm] = Form.useForm<ClusterAnsibleForm>();
  const [tokenForm] = Form.useForm<ClusterTokenForm>();
  const [certificateForm] = Form.useForm<ClusterCertificateForm>();
  const [deployMethod, setDeployMethod] = useState<DeployMethod>('ansible');
  const [deployWizardStep, setDeployWizardStep] = useState(0);
  const [deployAuthMethod, setDeployAuthMethod] = useState<DeployAuthMethod>('agent');
  const [deployHostKeyMode, setDeployHostKeyMode] = useState<DeployHostKeyMode>('known_hosts');
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
  const { data, isLoading, refetch, isFetching, isError: isStatusError, error: statusError } = useQuery({
    queryKey: ['cluster-status'],
    queryFn: fetchClusterStatus,
    refetchInterval: 15_000,
    staleTime: 10_000,
    retry: false,
  });
  const { data: tokens, isFetching: isFetchingTokens, isError: isTokensError, error: tokensError, refetch: refetchTokens } = useQuery({
    queryKey: ['cluster-join-tokens'],
    queryFn: fetchClusterJoinTokens,
    refetchInterval: 15_000,
    retry: false,
  });
  const { data: nodes, isFetching: isFetchingNodes, isError: isNodesError, error: nodesError, refetch: refetchNodes } = useQuery({
    queryKey: ['cluster-nodes'],
    queryFn: fetchClusterNodes,
    refetchInterval: 15_000,
    retry: false,
  });
  const { data: deployTasks, isFetching: isFetchingDeployTasks, refetch: refetchDeployTasks } = useQuery({
    queryKey: ['cluster-deploy-tasks'],
    queryFn: fetchClusterDeploymentTasks,
    refetchInterval: 3000,
    retry: false,
  });
  const { data: clusterAudit, isFetching: isFetchingAudit, isError: isAuditError, error: auditError, refetch: refetchAudit } = useQuery({
    queryKey: ['cluster-audit'],
    queryFn: fetchClusterAudit,
    refetchInterval: 12_000,
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
      ArcoMessage.success(t('cluster.tokenCreated'));
    },
    onError: (error) => {
      setTokenOperationError(error.message);
      ArcoMessage.error(error.message);
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
      ArcoMessage.success(t('cluster.tokenRevoked'));
    },
    onError: (error) => {
      setTokenOperationError(error.message);
      ArcoMessage.error(error.message);
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
      clearDeploySecrets(form);
      void queryClient.invalidateQueries({ queryKey: ['cluster-deploy-tasks'] });
      void queryClient.invalidateQueries({ queryKey: ['cluster-status'] });
      ArcoMessage.success(t('cluster.deployTaskStarted'));
    },
    onError: (error) => {
      clearDeploySecrets(form);
      ArcoMessage.error(error.message);
    },
  });
  const ansiblePackageMutation = useMutation({
    mutationFn: () => {
      const values = ansibleForm.getFieldsValue();
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
      ArcoMessage.success(t('cluster.deployWizardAnsibleGenerated'));
    },
    onError: (error) => {
      ArcoMessage.error(errorMessage(error));
    },
  });
  const rotateCertificateMutation = useMutation({
    mutationFn: (payload: { nodeID: string; csr: string }) => rotateClusterNodeCertificate(payload.nodeID, { csr: payload.csr }),
    onMutate: () => {
      setLatestCertificate(null);
    },
    onSuccess: (result) => {
      setLatestCertificate(result);
      certificateForm.setFieldValue('csr', '');
      void queryClient.invalidateQueries({ queryKey: ['cluster-nodes'] });
      ArcoMessage.success(t('cluster.certSigned'));
    },
    onError: (error) => {
      ArcoMessage.error(error.message);
    },
  });

  const submitToken = async () => {
    if (latestToken?.value) {
      const message = t('cluster.tokenClearBeforeCreate');
      setTokenOperationError(message);
      ArcoMessage.warning(message);
      return;
    }
    const values = tokenForm.getFieldsValue();
    createTokenMutation.mutate({
      role: String(values.role || 'waf'),
      ttl: String(values.ttl || '15m'),
      max_uses: Number(values.maxUses || 1),
    });
  };

  const submitDeployment = async (mode: 'check' | 'run') => {
    const values = await form.validate();
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
      ArcoMessage.warning(t('cluster.deployPasswordRequired'));
      return;
    }
    if (deployAuthMethod === 'private_key' && !privateKey) {
      ArcoMessage.warning(t('cluster.deployPrivateKeyRequired'));
      return;
    }
    if (deployAuthMethod === 'password' && password) {
      payload.password = password;
    }
    if (deployAuthMethod === 'private_key' && privateKey) {
      payload.private_key = privateKey;
    }
    const hostKeySHA256 = String(values.hostKeySHA256 || '').trim();
    if (deployHostKeyMode === 'fingerprint' && !hostKeySHA256) {
      ArcoMessage.warning(t('cluster.deployHostKeyRequired'));
      return;
    }
    if (deployHostKeyMode === 'fingerprint' && hostKeySHA256) {
      payload.host_key_sha256 = hostKeySHA256;
    }
    if (mode === 'check') {
      setDeployWizardStep(2);
      deployTaskMutation.mutate(payload);
    } else {
      if (!activeDeployTask || activeDeployTask.action !== 'check' || activeDeployTask.status !== 'succeeded') {
        ArcoMessage.warning(t('cluster.deployWizardPrecheckRequired'));
        return;
      }
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
    form.resetFields();
    ansibleForm.resetFields();
    setDeployWizardStep(0);
    setDeployMethod('ansible');
    setDeployAuthMethod('agent');
    setDeployHostKeyMode('known_hosts');
    setActiveDeployTaskId(null);
    setSubmittedDeployTask(null);
    setAnsiblePackage(null);
    setSelectedAnsibleFile('README.md');
  };

  const submitCertificateSigning = async () => {
    const values = await certificateForm.validate();
    const nodeID = String(values.nodeId || '').trim();
    const csr = String(values.csr || '').trim();
    const node = nodes?.items.find((item) => item.node_id === nodeID);
    if (node?.revoked) {
      ArcoMessage.warning(t('cluster.certRevokedNode'));
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
        <Button loading={isFetching} onClick={() => void refetch()}>{t('cluster.refresh')}</Button>
      </section>

      {isStatusError && (
        <div className="cluster-result-note cluster-result-note-error cluster-status-error">
          <strong>{t('cluster.statusLoadFailed')}</strong>
          <span>{errorMessage(statusError)}</span>
          <Button size="small" onClick={() => void refetch()}>{t('common.retry')}</Button>
        </div>
      )}

      <Spin loading={isLoading && !data}>
        {data && (
          <section className="cluster-grid">
            <Card className="cluster-status-card">
              <div className="cluster-card-head">
                <span className="cluster-icon"><Network size={18} /></span>
                <div>
                  <Typography.Title heading={5}>{t('cluster.currentMode')}</Typography.Title>
                  <Typography.Paragraph>{t('cluster.currentModeHint')}</Typography.Paragraph>
                </div>
                <Tag color={data.enabled ? 'green' : 'gray'}>{data.enabled ? t('common.enabled') : t('cluster.standalone')}</Tag>
              </div>

              <div className="cluster-status-main">
                <div>
                  <span>{t('cluster.mode')}</span>
                  <strong>{clusterModeLabel(data.mode, data.product_mode_label, t)}</strong>
                </div>
                <div>
                  <span>{t('cluster.configWrites')}</span>
                  <strong>{data.can_write_config ? t('cluster.allowed') : t('cluster.protected')}</strong>
                </div>
                <div>
                  <span>{t('cluster.traffic')}</span>
                  <strong>{data.can_receive_traffic ? t('cluster.receiving') : t('cluster.notReceiving')}</strong>
                </div>
                <div>
                  <span>{t('cluster.majority')}</span>
                  <strong>{data.majority_confirmed ? t('cluster.confirmed') : t('cluster.unconfirmed')}</strong>
                </div>
              </div>

              {data.protection_mode_reason && (
                <div className="cluster-protection-note">{data.protection_mode_reason}</div>
              )}
            </Card>

            <Card className="cluster-status-card">
              <div className="cluster-card-head">
                <span className="cluster-icon cluster-icon-safe"><ShieldCheck size={18} /></span>
                <div>
                  <Typography.Title heading={5}>{t('cluster.nodes')}</Typography.Title>
                  <Typography.Paragraph>{t('cluster.nodesHint')}</Typography.Paragraph>
                </div>
              </div>
              <div className="cluster-node-summary">
                <div><span>{t('cluster.totalNodes')}</span><strong>{data.node_count}</strong></div>
                <div><span>{t('cluster.wafNodes')}</span><strong>{data.waf_node_count}</strong></div>
                <div><span>{t('cluster.monitorNodes')}</span><strong>{data.monitor_node_count}</strong></div>
                <div><span>{t('cluster.consistency')}</span><strong>{consensusLabel(data.consensus_provider, t)}</strong></div>
              </div>
              {!data.enabled && (
                <div className="cluster-empty-action">
                  <p>{t('cluster.singleNodeHint')}</p>
                  <Button onClick={() => document.getElementById('cluster-deploy-wizard')?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>
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
                  <Typography.Title heading={5}>{t('cluster.currentMode')}</Typography.Title>
                  <Typography.Paragraph>{t('cluster.statusUnavailable')}</Typography.Paragraph>
                </div>
              </div>
            </Card>
          </section>
        )}

        <Card className="cluster-join-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><KeyRound size={18} /></span>
            <div>
              <Typography.Title heading={5}>{t('cluster.joinTitle')}</Typography.Title>
              <Typography.Paragraph>{t('cluster.joinHint')}</Typography.Paragraph>
            </div>
          </div>
          <Form
            form={tokenForm}
            layout="vertical"
            initialValues={{ role: 'waf', ttl: '15m', maxUses: 1 }}
            className="cluster-token-form"
            onValuesChange={(_, values) => {
              setJoinCommandFields({
                controllerUrl: values.controllerUrl,
                nodeId: values.nodeId,
                advertiseAddr: values.advertiseAddr,
              });
            }}
          >
            <div className="cluster-token-fields">
              <Form.Item label={t('cluster.tokenRole')} field="role">
                <Select>
                  <Select.Option value="waf">{t('cluster.roleWaf')}</Select.Option>
                  <Select.Option value="monitor">{t('cluster.roleMonitor')}</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={t('cluster.tokenTTL')} field="ttl" extra={t('cluster.tokenTTLHint')}>
                <Select allowCreate>
                  <Select.Option value="15m">15m</Select.Option>
                  <Select.Option value="30m">30m</Select.Option>
                  <Select.Option value="1h">1h</Select.Option>
                  <Select.Option value="6h">6h</Select.Option>
                </Select>
              </Form.Item>
              <Form.Item label={t('cluster.tokenMaxUses')} field="maxUses" extra={t('cluster.tokenMaxUsesHint')}>
                <InputNumber min={1} max={100} precision={0} />
              </Form.Item>
              <Form.Item label={t('cluster.joinControllerUrl')} field="controllerUrl" extra={t('cluster.joinControllerUrlHint')}>
                <Input placeholder="https://controller.example.com:9443" allowClear />
              </Form.Item>
              <Form.Item label={t('cluster.joinNodeId')} field="nodeId" extra={t('cluster.joinNodeIdHint')}>
                <Input placeholder="waf-1" allowClear />
              </Form.Item>
              <Form.Item label={t('cluster.joinAdvertiseAddr')} field="advertiseAddr" extra={t('cluster.joinAdvertiseAddrHint')}>
                <Input placeholder="192.168.6.250:9444" allowClear />
              </Form.Item>
              <Form.Item label=" ">
                <Button
                  type="primary"
                  loading={createTokenMutation.isPending}
                  disabled={Boolean(latestToken?.value) || revokeTokenMutation.isPending}
                  onClick={() => void submitToken()}
                >
                  {t('cluster.createToken')}
                </Button>
              </Form.Item>
            </div>
          </Form>
          {tokenOperationError && (
            <div className="cluster-result-note cluster-result-note-error cluster-inline-error">
              <strong>{t('cluster.tokenOperationFailed')}</strong>
              <span>{tokenOperationError}</span>
              <Button size="mini" onClick={() => setTokenOperationError(null)}>{t('common.close')}</Button>
            </div>
          )}
          {latestToken?.value && (
            <div className="cluster-result-note cluster-result-note-ok cluster-token-secret">
              <strong>{t('cluster.tokenSecretTitle')}</strong>
              <span>{t('cluster.tokenSecretHint')}</span>
              <code>{latestToken.value}</code>
              <div className="cluster-token-actions">
                <Button icon={<Copy size={15} />} onClick={() => void copyText(latestToken.value || '', t('cluster.copied'), t('cluster.copyFailed'))}>
                  {t('cluster.copyToken')}
                </Button>
                <Button onClick={() => {
                  setLatestToken(null);
                  ArcoMessage.success(t('cluster.tokenCleared'));
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
              <Button
                size="small"
                onClick={() => {
                  void refetchTokens();
                  void refetchNodes();
                }}
              >
                {t('common.retry')}
              </Button>
            </div>
          )}
          <div className="cluster-tables-grid">
            <Table
              rowKey="id"
              loading={isFetchingTokens}
              pagination={false}
              data={tokens?.items || []}
              columns={[
                { title: t('cluster.tokenID'), dataIndex: 'id', render: (value: string) => <code>{value}</code> },
                { title: t('cluster.tokenRole'), dataIndex: 'role', render: (value: string) => roleTag(value, t) },
                { title: t('cluster.tokenUsage'), render: (_: unknown, item: ClusterJoinToken) => `${item.used_count}/${item.max_uses}` },
                { title: t('cluster.tokenExpires'), dataIndex: 'expires_at', render: formatTimestamp },
                {
                  title: t('common.actions'),
                  render: (_: unknown, item: ClusterJoinToken) => (
                    <Popconfirm
                      title={t('cluster.revokeConfirmTitle')}
                      content={t('cluster.revokeConfirmContent')}
                      okText={t('common.confirm')}
                      cancelText={t('common.cancel')}
                      disabled={item.revoked || revokeTokenMutation.isPending}
                      onOk={() => revokeTokenMutation.mutate(item.id)}
                    >
                      <Button
                        size="mini"
                        status="danger"
                        disabled={item.revoked || revokeTokenMutation.isPending}
                        loading={revokingTokenID === item.id}
                      >
                        {item.revoked ? t('cluster.revoked') : t('cluster.revoke')}
                      </Button>
                    </Popconfirm>
                  ),
                },
              ]}
              scroll={{ x: 720 }}
            />
            <Table
              rowKey="node_id"
              loading={isFetchingNodes}
              pagination={false}
              data={nodes?.items || []}
              columns={[
                { title: t('cluster.nodeID'), dataIndex: 'node_id', render: (value: string) => <code>{value}</code> },
                { title: t('cluster.nodeRole'), dataIndex: 'role', render: (value: string) => roleTag(value, t) },
                { title: t('cluster.nodeAdvertise'), dataIndex: 'advertise_addr' },
                { title: t('cluster.nodeJoined'), dataIndex: 'joined_at', render: formatTimestamp },
                { title: t('cluster.nodeCertExpiry'), dataIndex: 'certificate_expiry', render: formatTimestamp },
                {
                  title: t('common.actions'),
                  render: (_: unknown, item) => (
                    <Button
                      size="mini"
                      disabled={item.revoked}
                      onClick={() => {
                        certificateForm.setFieldValue('nodeId', item.node_id);
                        setLatestCertificate(null);
                        document.getElementById('cluster-cert-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                      }}
                    >
                      {t('cluster.certSign')}
                    </Button>
                  ),
                },
              ]}
              scroll={{ x: 960 }}
            />
          </div>

          <div id="cluster-cert-panel" className="cluster-cert-panel">
            <div className="cluster-cert-head">
              <div>
                <strong>{t('cluster.certTitle')}</strong>
                <span>{t('cluster.certHint')}</span>
              </div>
            </div>
            <Form form={certificateForm} layout="vertical" className="cluster-cert-form">
              <div className="cluster-cert-fields">
                <Form.Item
                  label={t('cluster.certNode')}
                  field="nodeId"
                  rules={[{ required: true, message: t('cluster.certNodeRequired') }]}
                >
                  <Select placeholder={t('cluster.certNodePlaceholder')}>
                    {(nodes?.items || []).map((node) => (
                      <Select.Option key={node.node_id} value={node.node_id} disabled={node.revoked}>
                        {node.node_id} · {roleLabelText(node.role, t)}
                      </Select.Option>
                    ))}
                  </Select>
                </Form.Item>
                <Form.Item
                  label={t('cluster.certCSR')}
                  field="csr"
                  rules={[{ required: true, message: t('cluster.certCSRRequired') }]}
                >
                  <Input.TextArea autoSize={{ minRows: 5, maxRows: 10 }} placeholder="-----BEGIN CERTIFICATE REQUEST-----" />
                </Form.Item>
              </div>
              <div className="cluster-cert-actions">
                <Button
                  type="primary"
                  icon={<ShieldCheck size={16} />}
                  loading={rotateCertificateMutation.isPending}
                  disabled={rotateCertificateMutation.isPending}
                  onClick={() => void submitCertificateSigning()}
                >
                  {t('cluster.certSubmit')}
                </Button>
              </div>
            </Form>
            {latestCertificate && (
              <div className="cluster-result-note cluster-result-note-ok cluster-cert-result">
                <strong>{t('cluster.certResultTitle')}</strong>
                <span>{t('cluster.certResultHint')}</span>
                <span>{t('cluster.nodeID')}: <code>{latestCertificate.node.node_id}</code></span>
                <span>{t('cluster.certSerial')}: <code>{latestCertificate.node.certificate_serial}</code></span>
                <span>{t('cluster.nodeCertExpiry')}: {formatTimestamp(latestCertificate.node.certificate_expiry)}</span>
                <div className="cluster-cert-result-actions">
                  <Button icon={<Copy size={15} />} onClick={() => void copyText(latestCertificate.certificates.cert, t('cluster.copied'), t('cluster.copyFailed'))}>
                    {t('cluster.copyCertificate')}
                  </Button>
                  <Button icon={<Copy size={15} />} onClick={() => void copyText(latestCertificate.certificates.ca, t('cluster.copied'), t('cluster.copyFailed'))}>
                    {t('cluster.copyCA')}
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
              <Typography.Title heading={5}>{t('cluster.deployWizardTitle')}</Typography.Title>
              <Typography.Paragraph>{t('cluster.deployWizardHint')}</Typography.Paragraph>
            </div>
          </div>
          <Steps current={deployWizardStep + 1} size="small" className="cluster-deploy-steps">
            <Steps.Step title={t('cluster.deployWizardStepMethod')} />
            <Steps.Step title={t('cluster.deployWizardStepTarget')} />
            <Steps.Step title={deployMethod === 'ssh' ? t('cluster.deployWizardStepPrecheck') : t('cluster.deployWizardStepPackage')} />
            <Steps.Step title={t('cluster.deployWizardStepResult')} />
          </Steps>

          <div className="cluster-deploy-methods" role="radiogroup" aria-label={t('cluster.deployWizardMethodLabel')}>
            <button
              type="button"
              className={`cluster-deploy-method ${deployMethod === 'ansible' ? 'cluster-deploy-method-active' : ''}`}
              onClick={() => {
                setDeployMethod('ansible');
                setDeployWizardStep(0);
              }}
            >
              <strong>{t('cluster.deployWizardMethodAnsible')}</strong>
              <span>{t('cluster.deployWizardMethodAnsibleHint')}</span>
            </button>
            <button
              type="button"
              className={`cluster-deploy-method ${deployMethod === 'ssh' ? 'cluster-deploy-method-active' : ''}`}
              onClick={() => {
                setDeployMethod('ssh');
                setDeployWizardStep(0);
              }}
            >
              <strong>{t('cluster.deployWizardMethodSSH')}</strong>
              <span>{t('cluster.deployWizardMethodSSHHint')}</span>
            </button>
          </div>

          {deployMethod === 'ansible' ? (
            <div className="cluster-wizard-panel">
              <Form
                form={ansibleForm}
                layout="vertical"
                initialValues={{ clusterId: 'cheesewaf-mesh', channel: 'canary' }}
                className="cluster-deploy-form"
              >
                <div className="cluster-ansible-summary">
                  <Form.Item label={t('cluster.deployWizardClusterID')} field="clusterId" extra={t('cluster.deployWizardClusterIDHint')}>
                    <Input placeholder="cheesewaf-mesh" allowClear />
                  </Form.Item>
                  <Form.Item label={t('cluster.deployWizardChannel')} field="channel" extra={t('cluster.deployWizardChannelHint')}>
                    <Select>
                      <Select.Option value="dev">{t('cluster.channelDev')}</Select.Option>
                      <Select.Option value="canary">{t('cluster.channelCanary')}</Select.Option>
                      <Select.Option value="stable">{t('cluster.channelStable')}</Select.Option>
                    </Select>
                  </Form.Item>
                </div>
              </Form>

              <div className="cluster-ansible-node-list">
                <div className="cluster-section-title">
                  <strong>{t('cluster.deployWizardAnsibleNodes')}</strong>
                  <Button size="small" icon={<Plus size={15} />} onClick={addAnsibleNode}>{t('cluster.deployWizardAddNode')}</Button>
                </div>
                {ansibleNodes.map((node, index) => (
                  <div className="cluster-ansible-node" key={`ansible-node-${index}`}>
                    <Input
                      value={node.name}
                      placeholder={t('cluster.deployWizardNodeName')}
                      onChange={(value) => updateAnsibleNode(index, { name: value })}
                    />
                    <Input
                      value={node.address}
                      placeholder={t('cluster.deployWizardNodeAddress')}
                      onChange={(value) => updateAnsibleNode(index, { address: value })}
                    />
                    <Select value={node.role} onChange={(value) => updateAnsibleNode(index, { role: String(value) })}>
                      <Select.Option value="waf">{t('cluster.roleWaf')}</Select.Option>
                      <Select.Option value="monitor">{t('cluster.roleMonitor')}</Select.Option>
                    </Select>
                    <InputNumber
                      value={node.ssh_port}
                      min={1}
                      max={65535}
                      precision={0}
                      onChange={(value) => updateAnsibleNode(index, { ssh_port: Number(value || 22) })}
                    />
                    <Input
                      value={node.region || ''}
                      placeholder={t('cluster.deployWizardNodeRegion')}
                      onChange={(value) => updateAnsibleNode(index, { region: value })}
                    />
                    <Button
                      icon={<Trash2 size={15} />}
                      disabled={ansibleNodes.length <= 1}
                      onClick={() => removeAnsibleNode(index)}
                    >
                      {t('common.delete')}
                    </Button>
                  </div>
                ))}
              </div>

              <div className="cluster-deploy-actions">
                <Button
                  type="primary"
                  icon={<PackageCheck size={16} />}
                  loading={ansiblePackageMutation.isPending}
                  disabled={ansiblePackageMutation.isPending}
                  onClick={() => ansiblePackageMutation.mutate()}
                >
                  {t('cluster.deployWizardGeneratePackage')}
                </Button>
                <Button icon={<RotateCcw size={16} />} onClick={resetDeploymentWizard}>{t('common.reset')}</Button>
              </div>

              {ansiblePackage && (
                <AnsiblePackageViewer
                  pkg={ansiblePackage}
                  selectedFile={selectedAnsibleFile}
                  setSelectedFile={setSelectedAnsibleFile}
                  t={t}
                />
              )}
            </div>
          ) : (
            <div className="cluster-wizard-panel">
              <Form
                form={form}
                layout="vertical"
                initialValues={{ user: 'root', port: 22, action: 'install' }}
                className="cluster-deploy-form"
              >
                <div className="cluster-deploy-fields">
                  <Form.Item
                    label={t('cluster.deployHost')}
                    field="host"
                    rules={[{ required: true, message: t('cluster.deployHostRequired') }]}
                    extra={t('cluster.deployWizardHostHint')}
                  >
                    <Input placeholder="192.168.6.249" allowClear onFocus={() => setDeployWizardStep(1)} />
                  </Form.Item>
                  <Form.Item
                    label={t('cluster.deployUser')}
                    field="user"
                    rules={[{ required: true, message: t('cluster.deployUserRequired') }]}
                  >
                    <Input placeholder="root" allowClear onFocus={() => setDeployWizardStep(1)} />
                  </Form.Item>
                  <Form.Item
                    label={t('cluster.deployPort')}
                    field="port"
                    rules={[{ required: true, message: t('cluster.deployPortRequired') }]}
                  >
                    <InputNumber min={1} max={65535} precision={0} onFocus={() => setDeployWizardStep(1)} />
                  </Form.Item>
                  <Form.Item label={t('cluster.deployAction')} field="action" extra={t('cluster.deployWizardActionHint')}>
                    <Select onChange={() => setDeployWizardStep(1)}>
                      <Select.Option value="install">{t('cluster.deployActionInstall')}</Select.Option>
                      <Select.Option value="rollback-install">{t('cluster.deployActionRollbackInstall')}</Select.Option>
                      <Select.Option value="restart-service">{t('cluster.deployActionRestart')}</Select.Option>
                    </Select>
                  </Form.Item>
                </div>

                <div className="cluster-credential-panel">
                  <div className="cluster-section-title">
                    <strong>{t('cluster.deployWizardAuthTitle')}</strong>
                    <span>{t('cluster.deployWizardAuthHint')}</span>
                  </div>
                  <Radio.Group type="button" value={deployAuthMethod} onChange={(value) => setDeployAuthMethod(value as DeployAuthMethod)}>
                    <Radio value="agent">{t('cluster.deployWizardAuthAgent')}</Radio>
                    <Radio value="password">{t('cluster.deployWizardAuthPassword')}</Radio>
                    <Radio value="private_key">{t('cluster.deployWizardAuthPrivateKey')}</Radio>
                  </Radio.Group>
                  {deployAuthMethod === 'password' && (
                    <Form.Item label={t('cluster.deployPassword')} field="password" extra={t('cluster.deployPasswordHint')}>
                      <Input.Password placeholder={t('cluster.deployPasswordPlaceholder')} autoComplete="new-password" allowClear />
                    </Form.Item>
                  )}
                  {deployAuthMethod === 'private_key' && (
                    <Form.Item label={t('cluster.deployPrivateKey')} field="privateKey" extra={t('cluster.deployPrivateKeyHint')}>
                      <Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
                    </Form.Item>
                  )}
                </div>

                <div className="cluster-hostkey-panel">
                  <div className="cluster-section-title">
                    <strong>{t('cluster.deployWizardHostKeyTitle')}</strong>
                    <span>{t('cluster.deployWizardHostKeyHint')}</span>
                  </div>
                  <Radio.Group type="button" value={deployHostKeyMode} onChange={(value) => setDeployHostKeyMode(value as DeployHostKeyMode)}>
                    <Radio value="known_hosts">{t('cluster.deployWizardHostKeyKnownHosts')}</Radio>
                    <Radio value="fingerprint">{t('cluster.deployWizardHostKeyFingerprint')}</Radio>
                  </Radio.Group>
                  {deployHostKeyMode === 'fingerprint' && (
                    <Form.Item label={t('cluster.deployHostKey')} field="hostKeySHA256" extra={t('cluster.deployHostKeyHint')}>
                      <Input placeholder="SHA256:..." allowClear />
                    </Form.Item>
                  )}
                </div>

                <div className="cluster-deploy-actions">
                  <Button
                    icon={<ShieldCheck size={16} />}
                    loading={deployTaskMutation.isPending}
                    disabled={deployTaskMutation.isPending}
                    onClick={() => void submitDeployment('check')}
                  >
                    {t('cluster.deployWizardRunPrecheck')}
                  </Button>
                  <Button
                    type="primary"
                    icon={<Play size={16} />}
                    loading={deployTaskMutation.isPending}
                    disabled={deployTaskMutation.isPending || !activeDeployTask || activeDeployTask.action !== 'check' || activeDeployTask.status !== 'succeeded'}
                    onClick={() => void submitDeployment('run')}
                  >
                    {t('cluster.deployWizardStartAction')}
                  </Button>
                  <Button icon={<RotateCcw size={16} />} disabled={deployTaskMutation.isPending} onClick={resetDeploymentWizard}>
                    {t('common.reset')}
                  </Button>
                </div>
              </Form>

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
              <Typography.Title heading={5}>{t('cluster.auditTitle')}</Typography.Title>
              <Typography.Paragraph>{t('cluster.auditHint')}</Typography.Paragraph>
            </div>
          </div>
          <div className="cluster-audit-toolbar">
            <Tag color="arcoblue">{t('cluster.auditScopeTag')}</Tag>
            <Button size="small" loading={isFetchingAudit} onClick={() => void refetchAudit()}>{t('cluster.auditRefresh')}</Button>
          </div>
          {isAuditError && (
            <div className="cluster-result-note cluster-result-note-error cluster-inline-error">
              <strong>{t('cluster.auditLoadFailed')}</strong>
              <span>{errorMessage(auditError)}</span>
              <Button size="mini" onClick={() => void refetchAudit()}>{t('common.retry')}</Button>
            </div>
          )}
          {!isAuditError && !auditEntries.length && !isFetchingAudit && (
            <div className="cluster-result-note cluster-result-note-muted">
              <strong>{t('cluster.auditEmptyTitle')}</strong>
              <span>{t('cluster.auditEmptyHint')}</span>
            </div>
          )}
          <div className="table-scroll cluster-audit-table">
            <Table
              rowKey={clusterAuditRowKey}
              loading={isFetchingAudit && !auditEntries.length}
              pagination={auditEntries.length > 10 ? { pageSize: 10, sizeCanChange: true } : false}
              data={auditEntries}
              columns={[
                { title: t('cluster.auditTime'), dataIndex: 'timestamp', width: 190, render: (value: string) => <span className="nowrap-cell" title={value}>{formatTimestamp(value) || '-'}</span> },
                { title: t('cluster.auditSourceType'), width: 170, render: (_: unknown, item: ClusterAuditEntry) => <ClusterAuditSourceCell entry={item} t={t} /> },
                { title: t('cluster.auditAction'), width: 150, render: (_: unknown, item: ClusterAuditEntry) => <span className="cluster-audit-text">{clusterAuditAction(item, t)}</span> },
                { title: t('cluster.auditActor'), width: 140, render: (_: unknown, item: ClusterAuditEntry) => <span className="cluster-audit-text">{clusterAuditActor(item, t)}</span> },
                { title: t('cluster.auditTarget'), render: (_: unknown, item: ClusterAuditEntry) => <code className="table-code" title={clusterAuditTarget(item)}>{clusterAuditTarget(item) || '-'}</code> },
                { title: t('cluster.auditStatus'), width: 120, render: (_: unknown, item: ClusterAuditEntry) => clusterAuditStatusTag(item, t) },
                { title: t('cluster.auditRemoteIP'), width: 150, render: (_: unknown, item: ClusterAuditEntry) => <span className="nowrap-cell">{item.remote_ip || '-'}</span> },
                { title: t('cluster.auditMessage'), render: (_: unknown, item: ClusterAuditEntry) => <span className="cluster-audit-message">{clusterAuditMessage(item, t)}</span> },
              ]}
              scroll={{ x: 1180 }}
            />
          </div>
          <div className="mobile-card-list cluster-audit-cards">
            {auditEntries.map((entry) => (
              <ClusterAuditEntryCard key={clusterAuditRowKey(entry)} entry={entry} t={t} />
            ))}
          </div>
        </Card>
      </Spin>
    </main>
  );
}

function clearDeploySecrets(form: ReturnType<typeof Form.useForm<ClusterDeployForm>>[0]) {
  form.setFieldValue('password', '');
  form.setFieldValue('privateKey', '');
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
    return <Tag color="arcoblue">{t('cluster.roleMonitor')}</Tag>;
  }
  if (role === 'waf') {
    return <Tag color="green">{t('cluster.roleWaf')}</Tag>;
  }
  return <Tag color="gray">{role ? t('cluster.roleUnknown', { role }) : t('common.unknown')}</Tag>;
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
      <div className="table-scroll cluster-deploy-task-table">
        <Table
          rowKey="id"
          loading={isFetchingDeployTasks && !deployTasks.length}
          pagination={false}
          data={deployTasks}
          columns={[
            { title: t('cluster.deployTaskID'), dataIndex: 'id', render: (value: string) => <code>{value}</code> },
            { title: t('cluster.deployHost'), render: (_: unknown, item: ClusterDeploymentTask) => `${item.user}@${item.host}:${item.port}` },
            { title: t('cluster.deployAction'), dataIndex: 'action', render: (value: string) => deployActionLabel(value, t) },
            { title: t('cluster.deployTaskStatus'), dataIndex: 'status', render: (value: string) => deployTaskStatusTag(value, t) },
            { title: t('cluster.deployTaskUpdated'), dataIndex: 'updated_at', render: formatTimestamp },
            {
              title: t('common.actions'),
              render: (_: unknown, item: ClusterDeploymentTask) => (
                <Button size="mini" onClick={() => setActiveDeployTaskId(item.id)}>{t('cluster.deployTaskView')}</Button>
              ),
            },
          ]}
          scroll={{ x: 840 }}
        />
      </div>
      <div className="mobile-card-list cluster-deploy-task-cards">
        {deployTasks.map((task) => (
          <DeploymentTaskCard key={task.id} task={task} setActiveDeployTaskId={setActiveDeployTaskId} t={t} />
        ))}
      </div>
      <Button size="small" loading={isFetchingDeployTasks} onClick={() => void refetchDeployTasks()}>{t('cluster.deployTaskRefresh')}</Button>
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
      <Button size="small" onClick={() => setActiveDeployTaskId(task.id)}>{t('cluster.deployTaskView')}</Button>
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
          <Button icon={<Download size={15} />} disabled={!activeFile} onClick={() => downloadTextFile(activeFile, content)}>
            {t('cluster.deployWizardDownloadFile')}
          </Button>
          <Button icon={<Download size={15} />} onClick={() => downloadAnsiblePackage(pkg)}>
            {t('cluster.deployWizardDownloadPackage')}
          </Button>
        </div>
      </div>
      <div className="cluster-ansible-file-picker">
        <Select value={activeFile} onChange={(value) => setSelectedFile(String(value))}>
          {files.map((file) => (
            <Select.Option key={file} value={file}>{file}</Select.Option>
          ))}
        </Select>
        <Button icon={<Copy size={15} />} disabled={!content} onClick={() => void copyText(content, t('cluster.copied'), t('cluster.copyFailed'))}>
          {t('common.copy')}
        </Button>
      </div>
      <pre className="cluster-ansible-preview">{content || t('cluster.deployWizardPackageEmpty')}</pre>
    </div>
  );
}

function ClusterAuditSourceCell({ entry, t }: { entry: ClusterAuditEntry; t: Translate }) {
  return (
    <span className="cluster-audit-source">
      <Tag color={clusterAuditSourceColor(entry.source)}>{clusterAuditSourceLabel(entry.source, t)}</Tag>
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
      return <Tag color="green">{t('cluster.auditStatusOK')}</Tag>;
    case 'error':
    case 'rejected':
      return <Tag color="red">{t('cluster.auditStatusFailed')}</Tag>;
    default:
      break;
  }
  if (typeof entry.status_code === 'number' && entry.status_code > 0) {
    return httpStatusTag(entry.status_code);
  }
  return status ? <Tag color="gray">{status}</Tag> : <Tag color="gray">-</Tag>;
}

function httpStatusTag(status: number) {
  return <Tag color={status >= 400 ? 'red' : 'green'}>{status}</Tag>;
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

function clusterAuditSourceColor(source: string) {
  if (isDeployAuditSource(source)) {
    return 'green';
  }
  if (source === 'cluster_join' || source === 'node_join') {
    return 'purple';
  }
  return 'arcoblue';
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
      return <Tag color="gray">{t('cluster.deployTaskPending')}</Tag>;
    case 'running':
      return <Tag color="arcoblue">{t('cluster.deployTaskRunning')}</Tag>;
    case 'succeeded':
      return <Tag color="green">{t('cluster.deployTaskSucceeded')}</Tag>;
    case 'failed':
      return <Tag color="red">{t('cluster.deployTaskFailed')}</Tag>;
    case 'cancelled':
      return <Tag color="orangered">{t('cluster.deployTaskCancelled')}</Tag>;
    default:
      return <Tag color="gray">{status || t('common.unknown')}</Tag>;
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
          <Button icon={<Copy size={15} />} onClick={() => void copyText(joinCommand, t('cluster.copied'), t('cluster.copyFailed'))}>
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
    ArcoMessage.success(successMessage);
  } catch {
    ArcoMessage.error(failureMessage);
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
