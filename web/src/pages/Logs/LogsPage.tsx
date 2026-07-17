import { Button, Empty, Input, Select, Tag } from '@arco-design/web-react';
import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Eye, Search } from 'lucide-react';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';
import { displayAction, displayCategory, formatLogLocation } from '../../utils/display';

const PAGE_SIZE = 8;
type LogViewMode = 'security' | 'access' | 'all';

export default function LogsPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>();
  const [action, setAction] = useState<string>();
  const [viewMode, setViewMode] = useState<LogViewMode>('security');
  const [page, setPage] = useState(1);
  const { data, isLoading } = useQuery({
    queryKey: ['logs', category, action, viewMode],
    queryFn: () => fetchLogs({ limit: 500, category, action }),
    refetchInterval: 8_000,
    retry: false,
  });
  const logs = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const entries = (data?.items ?? []).filter((entry) => matchViewMode(entry, viewMode));
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) => [
      entry.trace_id,
      entry.client_ip,
      entry.uri,
      entry.category,
      entry.action,
      entry.message,
      entry.country,
      formatLogLocation(entry, t),
    ].some((value) => value?.toLowerCase().includes(needle)));
  }, [data?.items, search, t, viewMode]);
  const totalPages = Math.max(1, Math.ceil(logs.length / PAGE_SIZE));
  const pageItems = logs.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const pageStart = logs.length === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const pageEnd = Math.min(page * PAGE_SIZE, logs.length);
  const title = viewMode === 'access' ? t('logs.accessTitle') : t('logs.title');
  const subtitle = viewMode === 'access'
    ? t('logs.accessSubtitle')
    : viewMode === 'all'
      ? t('logs.allSubtitle')
      : t('logs.subtitle');
  const actionOptions = viewMode === 'security'
    ? ['block', 'challenge', 'log', 'monitor']
    : viewMode === 'access'
      ? ['pass', 'cache_hit', 'redirect']
      : ['pass', 'block', 'challenge', 'log', 'monitor', 'cache_hit', 'redirect'];

  useEffect(() => {
    setPage(1);
  }, [search, category, action, viewMode]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
      </header>

      <div className="toolbar-row">
        <Select
          value={viewMode}
          placeholder={t('logs.viewMode')}
          onChange={(value) => {
            setViewMode(value as LogViewMode);
            setAction(undefined);
            setCategory(undefined);
          }}
          style={{ minWidth: 140 }}
        >
          <Select.Option value="security">{t('logs.viewSecurity')}</Select.Option>
          <Select.Option value="access">{t('logs.viewAccess')}</Select.Option>
          <Select.Option value="all">{t('logs.viewAll')}</Select.Option>
        </Select>
        <Input value={search} onChange={setSearch} prefix={<Search size={16} />} placeholder={t('common.search')} allowClear />
        {viewMode !== 'access' && (
          <Select value={category} placeholder={t('logs.category')} allowClear onChange={(value) => setCategory(value as string | undefined)}>
            {['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'nosqli', 'ssti', 'xxe', 'bot', 'threat_intel'].map((item) => (
              <Select.Option key={item} value={item}>{displayCategory(item, t)}</Select.Option>
            ))}
          </Select>
        )}
        <Select value={action} placeholder={t('logs.action')} allowClear onChange={(value) => setAction(value as string | undefined)}>
          {actionOptions.map((item) => (
            <Select.Option key={item} value={item}>{displayAction(item, t)}</Select.Option>
          ))}
        </Select>
      </div>

      <section className="table-panel security-events-panel">
        <div className="security-events-header" aria-hidden="true">
          <span>{t('logs.trace')}</span>
          <span>{t('logs.source')}</span>
          <span>{t('logs.category')}</span>
          <span>{t('logs.action')}</span>
          <span>{t('logs.path')}</span>
          <span>{t('dashboard.ipLocation')}</span>
          <span>{t('logs.time')}</span>
          <span>{t('logs.detail')}</span>
        </div>
        <div className="security-events-list" aria-busy={isLoading}>
          {isLoading && Array.from({ length: 4 }).map((_, index) => (
            <div className="security-event-row security-event-skeleton" key={index} />
          ))}
          {!isLoading && pageItems.length === 0 && <Empty description={t('common.noData')} />}
          {!isLoading && pageItems.map((entry) => (
            <article className="security-event-row" key={entry.id || entry.trace_id}>
              <div className="security-event-cell security-event-trace" data-label={t('logs.trace')}>
                <code title={entry.trace_id || entry.id}>{entry.trace_id || entry.id || '-'}</code>
              </div>
              <div className="security-event-cell" data-label={t('logs.source')}>
                <span title={entry.client_ip || '-'}>{entry.client_ip || '-'}</span>
              </div>
              <div className="security-event-cell" data-label={t('logs.category')}>
                <Tag color={entry.category ? 'orange' : 'green'}>{displayCategory(entry.category || entry.action || 'pass', t)}</Tag>
              </div>
              <div className="security-event-cell" data-label={t('logs.action')}>
                <Tag color={actionTagColor(entry.action)}>{displayAction(entry.action, t)}</Tag>
              </div>
              <div className="security-event-cell security-event-uri" data-label={t('logs.path')}>
                <code title={entry.uri || '-'}>{entry.uri || '-'}</code>
              </div>
              <div className="security-event-cell" data-label={t('dashboard.ipLocation')}>
                <span title={formatLogLocation(entry, t)}>{formatLogLocation(entry, t)}</span>
              </div>
              <div className="security-event-cell" data-label={t('logs.time')}>
                <time dateTime={entry.timestamp}>{formatTime(entry.timestamp)}</time>
              </div>
              <div className="security-event-cell security-event-actions" data-label={t('logs.detail')}>
                <Link to={`/logs/${encodeURIComponent(entry.trace_id || entry.id)}`} className="table-action-link">
                  <Button size="small" icon={<Eye size={14} />}>{t('logs.viewDetail')}</Button>
                </Link>
              </div>
            </article>
          ))}
        </div>
        {!isLoading && logs.length > PAGE_SIZE && (
          <footer className="security-events-pagination">
            <span>{pageStart}-{pageEnd} / {logs.length}</span>
            <div>
              <Button
                aria-label={t('common.back')}
                icon={<ChevronLeft size={15} />}
                disabled={page <= 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
              />
              <strong>{page}</strong>
              <Button
                aria-label={t('common.next')}
                icon={<ChevronRight size={15} />}
                disabled={page >= totalPages}
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
              />
            </div>
          </footer>
        )}
      </section>
    </section>
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString();
}

function isSecurityEvent(entry: LogEntry) {
  const action = String(entry.action ?? '').toLowerCase();
  const status = Number(entry.status_code ?? 0);
  return Boolean(
    entry.category
      || entry.detector_id
      || entry.severity
      || action === 'block'
      || action === 'challenge'
      || action === 'log'
      || action === 'monitor'
      || status === 403
      || status === 429,
  );
}

function isAccessLog(entry: LogEntry) {
  if (isSecurityEvent(entry)) {
    return false;
  }
  const action = String(entry.action ?? '').toLowerCase();
  return action === 'pass' || action === 'cache_hit' || action === 'redirect' || action === '';
}

function matchViewMode(entry: LogEntry, mode: LogViewMode) {
  if (mode === 'all') {
    return true;
  }
  if (mode === 'access') {
    return isAccessLog(entry);
  }
  return isSecurityEvent(entry);
}

function actionTagColor(action: string) {
  switch (String(action ?? '').toLowerCase()) {
    case 'block':
      return 'red';
    case 'challenge':
      return 'orangered';
    case 'pass':
    case 'cache_hit':
    case 'redirect':
      return 'green';
    default:
      return 'blue';
  }
}
