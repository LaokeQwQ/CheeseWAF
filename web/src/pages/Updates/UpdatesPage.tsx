import { Badge } from '@/components/ui';
import { useQuery } from '@tanstack/react-query';
import { CloudDownload, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { normalizeSystem } from '../System/systemModel';

export default function UpdatesPage() {
  const { t } = useTranslation();
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data, isError, isFetching, isLoading, error, refetch } = systemQuery;
  const system = normalizeSystem(data);

  if (isLoading && !data) {
    return (
      <section className="page-surface">
        <PageHeader t={t} />
        <div className="empty-state" role="status">{t('common.loading')}</div>
      </section>
    );
  }

  if (isError && !data) {
    return (
      <section className="page-surface">
        <PageHeader t={t} />
        <QueryErrorState
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => { void refetch(); }}
          retrying={isFetching}
        />
      </section>
    );
  }

  return (
    <section className="page-surface">
      <PageHeader t={t} />
      {isError && (
        <QueryErrorState
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => { void refetch(); }}
          retrying={isFetching}
        />
      )}
      <section className="updates-summary">
        <div>
          <CloudDownload size={20} />
          <span>{t('updates.runtimeUpdate')}</span>
          <strong>{t('updates.unavailable')}</strong>
        </div>
        <div>
          <ShieldAlert size={20} />
          <span>{t('updates.vulnerabilityFeeds')}</span>
          <strong>{t('updates.unavailable')}</strong>
        </div>
      </section>
      <div className="updates-grid">
        <UnavailablePanel
          icon={<CloudDownload size={16} />}
          title={t('updates.runtimeUpdate')}
          message={t('updates.otaUnavailable')}
          capabilityReason={system.capabilities.ota_updates.reason}
          t={t}
        />
        <UnavailablePanel
          icon={<ShieldAlert size={16} />}
          title={t('updates.vulnerabilityFeeds')}
          message={t('updates.feedsUnavailable')}
          capabilityReason={system.capabilities.vulnerability_feeds.reason}
          t={t}
        />
      </div>
    </section>
  );
}

function PageHeader({ t }: { t: (key: string) => string }) {
  return (
    <header className="page-header">
      <div>
        <h1>{t('updates.title')}</h1>
        <p>{t('updates.subtitle')}</p>
      </div>
    </header>
  );
}

function UnavailablePanel({
  icon,
  title,
  message,
  capabilityReason,
  t,
}: {
  icon: React.ReactNode;
  title: string;
  message: string;
  capabilityReason: string;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <section className="panel updates-runtime-panel">
      <div className="panel-heading">
        <h2>{icon} {title}</h2>
        <Badge variant="secondary">{t('updates.unavailable')}</Badge>
      </div>
      <div className="empty-state" role="status">
        <strong>{message}</strong>
        <p>{t('updates.unavailableReason', { reason: capabilityReason })}</p>
        <p>{t('updates.legacyConfigPreserved')}</p>
      </div>
    </section>
  );
}
