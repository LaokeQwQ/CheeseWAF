import { useState } from 'react';
import { Button, Card, Form, Input, InputNumber, Message as ArcoMessage, Popconfirm, Select, Spin, Table, Tag, Typography } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Network, Play, RotateCcw, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { checkClusterDeployment, createClusterJoinToken, fetchClusterJoinTokens, fetchClusterNodes, fetchClusterStatus, revokeClusterJoinToken, runClusterDeployment } from '../../api/client';
import type { ClusterDeploymentCheckResult, ClusterDeploymentRequest, ClusterDeploymentRunResult, ClusterJoinToken, ClusterJoinTokenCreateRequest, ClusterNodeRegistration } from '../../types/api';

type ClusterDeployForm = {
  host?: string;
  user?: string;
  port?: number;
  password?: string;
  privateKey?: string;
  hostKeySHA256?: string;
  action?: string;
};

type ClusterTokenForm = {
  role?: string;
  ttl?: string;
  maxUses?: number;
};

type Translate = (key: string, options?: Record<string, unknown>) => string;

export default function ClusterPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [form] = Form.useForm<ClusterDeployForm>();
  const [tokenForm] = Form.useForm<ClusterTokenForm>();
  const [checkResult, setCheckResult] = useState<ClusterDeploymentCheckResult | null>(null);
  const [runResult, setRunResult] = useState<ClusterDeploymentRunResult | null>(null);
  const [latestToken, setLatestToken] = useState<ClusterJoinToken | null>(null);
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
  const checkMutation = useMutation({
    mutationFn: (payload: ClusterDeploymentRequest) => checkClusterDeployment(payload),
    onSuccess: (result) => {
      setCheckResult(result);
      setRunResult(null);
      clearDeploySecrets(form);
      ArcoMessage.success(t('cluster.deployCheckOk'));
    },
    onError: (error) => {
      clearDeploySecrets(form);
      ArcoMessage.error(error.message);
    },
  });
  const runMutation = useMutation({
    mutationFn: (payload: ClusterDeploymentRequest) => runClusterDeployment(payload),
    onSuccess: (result) => {
      setRunResult(result);
      clearDeploySecrets(form);
      void queryClient.invalidateQueries({ queryKey: ['cluster-status'] });
      ArcoMessage.success(result.ok ? t('cluster.deployRunOk') : t('cluster.deployRunFailed'));
    },
    onError: (error) => {
      clearDeploySecrets(form);
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
    const values = await tokenForm.validate();
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
    if (password && privateKey) {
      ArcoMessage.warning(t('cluster.deployCredentialConflict'));
      return;
    }
    if (password) {
      payload.password = password;
    }
    if (privateKey) {
      payload.private_key = privateKey;
    }
    const hostKeySHA256 = String(values.hostKeySHA256 || '').trim();
    if (hostKeySHA256) {
      payload.host_key_sha256 = hostKeySHA256;
    }
    if (mode === 'check') {
      checkMutation.mutate(payload);
    } else {
      runMutation.mutate(payload);
    }
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
                  <Button disabled>{t('cluster.fullWizardPending')}</Button>
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
              <span>{t('cluster.joinCommandTemplate')}</span>
              <code>{buildJoinCommand(latestToken, data?.cluster_id)}</code>
              <Button icon={<Copy size={15} />} onClick={() => void copyText(buildJoinCommand(latestToken, data?.cluster_id), t('cluster.copied'), t('cluster.copyFailed'))}>
                {t('cluster.copyJoinCommand')}
              </Button>
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
              ]}
              scroll={{ x: 840 }}
            />
          </div>
        </Card>

        <Card className="cluster-deploy-card">
          <div className="cluster-card-head cluster-card-head-compact">
            <span className="cluster-icon"><KeyRound size={18} /></span>
            <div>
              <Typography.Title heading={5}>{t('cluster.deployTitle')}</Typography.Title>
              <Typography.Paragraph>{t('cluster.deployHint')}</Typography.Paragraph>
            </div>
          </div>
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
              >
                <Input placeholder="192.168.6.249" allowClear />
              </Form.Item>
              <Form.Item
                label={t('cluster.deployUser')}
                field="user"
                rules={[{ required: true, message: t('cluster.deployUserRequired') }]}
              >
                <Input placeholder="root" allowClear />
              </Form.Item>
              <Form.Item
                label={t('cluster.deployPort')}
                field="port"
                rules={[{ required: true, message: t('cluster.deployPortRequired') }]}
              >
                <InputNumber min={1} max={65535} precision={0} />
              </Form.Item>
              <Form.Item label={t('cluster.deployAction')} field="action">
                <Select>
                  <Select.Option value="install">{t('cluster.deployActionInstall')}</Select.Option>
                  <Select.Option value="restart-service">{t('cluster.deployActionRestart')}</Select.Option>
                </Select>
              </Form.Item>
            </div>
            <div className="cluster-deploy-secrets">
              <Form.Item label={t('cluster.deployPassword')} field="password" extra={t('cluster.deployPasswordHint')}>
                <Input.Password placeholder={t('cluster.deployPasswordPlaceholder')} autoComplete="new-password" allowClear />
              </Form.Item>
              <Form.Item label={t('cluster.deployPrivateKey')} field="privateKey" extra={t('cluster.deployPrivateKeyHint')}>
                <Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
              </Form.Item>
            </div>
            <Form.Item label={t('cluster.deployHostKey')} field="hostKeySHA256" extra={t('cluster.deployHostKeyHint')}>
              <Input placeholder="SHA256:..." allowClear />
            </Form.Item>
            <div className="cluster-deploy-actions">
              <Button
                icon={<ShieldCheck size={16} />}
                loading={checkMutation.isPending}
                disabled={runMutation.isPending}
                onClick={() => void submitDeployment('check')}
              >
                {t('cluster.deployCheck')}
              </Button>
              <Button
                type="primary"
                icon={<Play size={16} />}
                loading={runMutation.isPending}
                disabled={checkMutation.isPending}
                onClick={() => void submitDeployment('run')}
              >
                {t('cluster.deployRun')}
              </Button>
              <Button
                icon={<RotateCcw size={16} />}
                disabled={checkMutation.isPending || runMutation.isPending}
                onClick={() => {
                  form.resetFields();
                  setCheckResult(null);
                  setRunResult(null);
                }}
              >
                {t('common.reset')}
              </Button>
            </div>
          </Form>

          <div className="cluster-deploy-results">
            {checkResult && (
              <div className="cluster-result-note cluster-result-note-ok">
                <strong>{t('cluster.deployCheckResult')}</strong>
                <span>{checkResult.user}@{checkResult.host}:{checkResult.port}</span>
                <code>{checkResult.command.join(' ')}</code>
              </div>
            )}
            {runResult && (
              <div className={runResult.ok ? 'cluster-result-note cluster-result-note-ok' : 'cluster-result-note cluster-result-note-error'}>
                <strong>{runResult.ok ? t('cluster.deployRunResultOk') : t('cluster.deployRunResultFailed')}</strong>
                <span>{runResult.host} · {formatTimestamp(runResult.finished_at)}</span>
                {runResult.output && <pre>{runResult.output}</pre>}
                {runResult.output_truncated && <small>{t('cluster.deployOutputTruncated')}</small>}
              </div>
            )}
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

function buildJoinCommand(token: ClusterJoinToken, clusterID?: string) {
  const role = token.role === 'waf' || token.role === 'monitor' ? token.role : '<role>';
  const nodeID = role === 'monitor' ? 'monitor-1' : role === 'waf' ? 'waf-1' : '<node-id>';
  const parts = [
    'cheesewaf',
    'cluster',
    'join',
    '--controller',
    '<controller-admin-url>',
    '--token-file',
    './join-token.txt',
    '--node-id',
    nodeID,
    '--role',
    role,
    '--advertise-addr',
    '<node-ip>:9444',
  ];
  if (clusterID) {
    parts.push('#', clusterID);
  }
  return parts.join(' ');
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
