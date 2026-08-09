import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Eye, Search } from 'lucide-react';
import { Badge, Button, Empty, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui';
import { fetchLogs } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { displayAction, displayCategory, formatLogLocation } from '../../utils/display';
import { filterLogs, paginate, type LogViewMode } from './logsLogic';

const PAGE_SIZE = 8;
const ALL = '__all__';

export default function LogsPage() {
  const { t, i18n } = useTranslation();
  const locale = i18n?.resolvedLanguage;
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>();
  const [action, setAction] = useState<string>();
  const [viewMode, setViewMode] = useState<LogViewMode>('security');
  const [page, setPage] = useState(1);
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['logs', category, action],
    queryFn: () => fetchLogs({ limit: 500, category, action }),
    refetchInterval: 8_000,
    retry: false,
  });
  const logs = useMemo(
    () => filterLogs(data?.items, { search, viewMode, formatLocation: (entry) => formatLogLocation(entry, t) }),
    [data?.items, search, t, viewMode],
  );
  const { totalPages, pageItems, pageStart, pageEnd } = paginate(logs, page, PAGE_SIZE);
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
          onValueChange={(value) => {
            setViewMode(value as LogViewMode);
            setAction(undefined);
            setCategory(undefined);
          }}
        >
          <SelectTrigger className="min-w-[140px]" aria-label={t('logs.viewMode')}>
            <SelectValue placeholder={t('logs.viewMode')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="security">{t('logs.viewSecurity')}</SelectItem>
            <SelectItem value="access">{t('logs.viewAccess')}</SelectItem>
            <SelectItem value="all">{t('logs.viewAll')}</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative min-w-[160px] flex-1">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-9"
            placeholder={t('common.search')}
          />
        </div>
        {viewMode !== 'access' && (
          <Select
            value={category ?? ALL}
            onValueChange={(value) => setCategory(value === ALL ? undefined : value)}
          >
            <SelectTrigger className="min-w-[140px]" aria-label={t('logs.category')}>
              <SelectValue placeholder={t('logs.category')} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>{t('logs.category')}</SelectItem>
              {['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'nosqli', 'ssti', 'xxe', 'bot', 'threat_intel'].map((item) => (
                <SelectItem key={item} value={item}>{displayCategory(item, t)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Select
          value={action ?? ALL}
          onValueChange={(value) => setAction(value === ALL ? undefined : value)}
        >
          <SelectTrigger className="min-w-[140px]" aria-label={t('logs.action')}>
            <SelectValue placeholder={t('logs.action')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('logs.action')}</SelectItem>
            {actionOptions.map((item) => (
              <SelectItem key={item} value={item}>{displayAction(item, t)}</SelectItem>
            ))}
          </SelectContent>
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
          {!isLoading && isError && (
            <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />
          )}
          {!isLoading && !isError && pageItems.length === 0 && <Empty description={t('common.noData')} />}
          {!isLoading && !isError && pageItems.map((entry) => (
            <article className="security-event-row" key={entry.id || entry.trace_id}>
              <div className="security-event-cell security-event-trace" data-label={t('logs.trace')}>
                <code title={entry.trace_id || entry.id}>{entry.trace_id || entry.id || '-'}</code>
              </div>
              <div className="security-event-cell" data-label={t('logs.source')}>
                <span title={entry.client_ip || '-'}>{entry.client_ip || '-'}</span>
              </div>
              <div className="security-event-cell" data-label={t('logs.category')}>
                <Badge variant={entry.category ? 'warning' : 'success'}>{displayCategory(entry.category || entry.action || 'pass', t)}</Badge>
              </div>
              <div className="security-event-cell" data-label={t('logs.action')}>
                <Badge variant={actionBadgeVariant(entry.action)}>{displayAction(entry.action, t)}</Badge>
              </div>
              <div className="security-event-cell security-event-uri" data-label={t('logs.path')}>
                <code title={entry.uri || '-'}>{entry.uri || '-'}</code>
              </div>
              <div className="security-event-cell" data-label={t('dashboard.ipLocation')}>
                <span title={formatLogLocation(entry, t)}>{formatLogLocation(entry, t)}</span>
              </div>
              <div className="security-event-cell" data-label={t('logs.time')}>
                <time dateTime={entry.timestamp}>{formatTime(entry.timestamp, locale)}</time>
              </div>
              <div className="security-event-cell security-event-actions" data-label={t('logs.detail')}>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => navigate(`/logs/${encodeURIComponent(entry.trace_id || entry.id)}`)}
                >
                  <Eye size={14} />
                  {t('logs.viewDetail')}
                </Button>
              </div>
            </article>
          ))}
        </div>
        {!isLoading && !isError && logs.length > PAGE_SIZE && (
          <footer className="security-events-pagination">
            <span>{pageStart}-{pageEnd} / {logs.length}</span>
            <div>
              <Button
                size="icon"
                variant="outline"
                aria-label={t('common.back')}
                disabled={page <= 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
              >
                <ChevronLeft size={15} />
              </Button>
              <strong>{page}</strong>
              <Button
                size="icon"
                variant="outline"
                aria-label={t('common.next')}
                disabled={page >= totalPages}
                onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
              >
                <ChevronRight size={15} />
              </Button>
            </div>
          </footer>
        )}
      </section>
    </section>
  );
}

function formatTime(value: string, locale?: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString(locale);
}

function actionBadgeVariant(action: string): 'destructive' | 'warning' | 'success' | 'default' {
  switch (String(action ?? '').toLowerCase()) {
    case 'block':
      return 'destructive';
    case 'challenge':
      return 'warning';
    case 'pass':
    case 'cache_hit':
    case 'redirect':
      return 'success';
    default:
      return 'default';
  }
}
