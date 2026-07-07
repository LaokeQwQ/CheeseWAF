import { Button, Card, Spin, Tag, Typography } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { Network, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { fetchClusterStatus } from '../../api/client';

export default function ClusterPage() {
  const { t } = useTranslation();
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['cluster-status'],
    queryFn: fetchClusterStatus,
    refetchInterval: 15_000,
    staleTime: 10_000,
    retry: false,
  });

  return (
    <main className="page-surface cluster-page">
      <section className="page-header">
        <div>
          <h1>{t('cluster.title')}</h1>
          <p>{t('cluster.subtitle')}</p>
        </div>
        <Button loading={isFetching} onClick={() => void refetch()}>{t('cluster.refresh')}</Button>
      </section>

      <Spin loading={isLoading && !data}>
        <section className="cluster-grid">
          <Card className="cluster-status-card">
            <div className="cluster-card-head">
              <span className="cluster-icon"><Network size={18} /></span>
              <div>
                <Typography.Title heading={5}>{t('cluster.currentMode')}</Typography.Title>
                <Typography.Paragraph>{t('cluster.currentModeHint')}</Typography.Paragraph>
              </div>
              <Tag color={data?.enabled ? 'green' : 'gray'}>{data?.enabled ? t('common.enabled') : t('cluster.standalone')}</Tag>
            </div>

            <div className="cluster-status-main">
              <div>
                <span>{t('cluster.mode')}</span>
                <strong>{clusterModeLabel(data?.mode, data?.product_mode_label, t)}</strong>
              </div>
              <div>
                <span>{t('cluster.configWrites')}</span>
                <strong>{data?.can_write_config ? t('cluster.allowed') : t('cluster.protected')}</strong>
              </div>
              <div>
                <span>{t('cluster.traffic')}</span>
                <strong>{data?.can_receive_traffic ? t('cluster.receiving') : t('cluster.notReceiving')}</strong>
              </div>
              <div>
                <span>{t('cluster.majority')}</span>
                <strong>{data?.majority_confirmed ? t('cluster.confirmed') : t('cluster.unconfirmed')}</strong>
              </div>
            </div>

            {data?.protection_mode_reason && (
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
              <div><span>{t('cluster.totalNodes')}</span><strong>{data?.node_count ?? 0}</strong></div>
              <div><span>{t('cluster.wafNodes')}</span><strong>{data?.waf_node_count ?? 0}</strong></div>
              <div><span>{t('cluster.monitorNodes')}</span><strong>{data?.monitor_node_count ?? 0}</strong></div>
              <div><span>{t('cluster.consistency')}</span><strong>{consensusLabel(data?.consensus_provider, t)}</strong></div>
            </div>
            {!data?.enabled && (
              <div className="cluster-empty-action">
                <p>{t('cluster.singleNodeHint')}</p>
                <Button disabled>{t('cluster.expandInM2')}</Button>
              </div>
            )}
          </Card>
        </section>
      </Spin>
    </main>
  );
}

function clusterModeLabel(mode: string | undefined, fallback: string | undefined, t: (key: string) => string) {
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

function consensusLabel(provider: string | undefined, t: (key: string) => string) {
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
