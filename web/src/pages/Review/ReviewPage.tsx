import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Search } from 'lucide-react';
import { Badge, Button, Empty, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, toast } from '@/components/ui';
import { decideReviewItem, fetchReviewItems, fetchSites } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { displayCategory } from '../../utils/display';
import type { ReviewDecision, ReviewItem } from '../../types/api';
import { formatReviewTime, parseReviewVerdict, reviewSearchMatch, shapeLabelKey, statusLabelKey } from './reviewLogic';

const ALL = '__all__';
const PAGE_SIZE = 8;

export default function ReviewPage() {
  const { t, i18n } = useTranslation();
  const locale = i18n?.resolvedLanguage;
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [siteId, setSiteId] = useState<string>();
  const [category, setCategory] = useState<string>();
  const [status, setStatus] = useState<string>('pending');
  const [page, setPage] = useState(1);
  const { data: sites } = useQuery({ queryKey: ['sites'], queryFn: fetchSites, retry: false });
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['review', siteId, category, status],
    queryFn: () => fetchReviewItems({
      limit: 100,
      offset: 0,
      site_id: siteId,
      category,
      status: status || undefined,
    }),
    refetchInterval: 10_000,
    retry: false,
  });
  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: ReviewDecision }) => decideReviewItem(id, decision),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review'] });
      toast.success(t('common.saved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const items = useMemo(
    () => (data?.items ?? []).filter((item) => reviewSearchMatch(item, search)),
    [data?.items, search],
  );
  const totalPages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  const pageItems = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [search, siteId, category, status]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('review.title')}</h1>
          <p>{t('review.subtitle')}</p>
        </div>
      </header>

      <div className="toolbar-row">
        <div className="relative min-w-[160px] flex-1">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-9"
            placeholder={t('common.search')}
          />
        </div>
        <Select value={siteId ?? ALL} onValueChange={(value) => setSiteId(value === ALL ? undefined : value)}>
          <SelectTrigger className="min-w-[140px]" aria-label={t('review.site')}>
            <SelectValue placeholder={t('review.site')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('review.allSites')}</SelectItem>
            {(sites ?? []).map((site) => (
              <SelectItem key={site.id} value={site.id}>{site.name || site.id}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={category ?? ALL} onValueChange={(value) => setCategory(value === ALL ? undefined : value)}>
          <SelectTrigger className="min-w-[140px]" aria-label={t('review.category')}>
            <SelectValue placeholder={t('review.category')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('review.allCategories')}</SelectItem>
            {['sqli', 'xss', 'rce', 'lfi', 'ssrf', 'nosqli', 'ssti', 'xxe', 'webshell', 'log4shell'].map((item) => (
              <SelectItem key={item} value={item}>{displayCategory(item, t)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status || ALL} onValueChange={(value) => setStatus(value === ALL ? '' : value)}>
          <SelectTrigger className="min-w-[140px]" aria-label={t('review.status')}>
            <SelectValue placeholder={t('review.status')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>{t('review.allStatus')}</SelectItem>
            <SelectItem value="pending">{t('review.pending')}</SelectItem>
            <SelectItem value="blocked">{t('review.blocked')}</SelectItem>
            <SelectItem value="allowed">{t('review.allowed')}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <section className="table-panel">
        {isLoading && <div className="page-spinner" aria-busy="true" />}
        {!isLoading && isError && <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />}
        {!isLoading && !isError && pageItems.length === 0 && <Empty description={t('review.empty')} />}
        {!isLoading && !isError && pageItems.map((item) => (
          <ReviewCard
            key={item.id}
            item={item}
            locale={locale}
            busy={decide.isPending}
            onDecide={(decision) => decide.mutate({ id: item.id, decision })}
          />
        ))}
      </section>
      {!isLoading && !isError && items.length > PAGE_SIZE && (
        <div className="toolbar-row">
          <Button variant="outline" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>{t('common.back')}</Button>
          <span>{page} / {totalPages}</span>
          <Button variant="outline" disabled={page >= totalPages} onClick={() => setPage((value) => value + 1)}>{t('common.next')}</Button>
        </div>
      )}
    </section>
  );
}

function ReviewCard({
  item,
  locale,
  busy,
  onDecide,
}: {
  item: ReviewItem;
  locale?: string;
  busy: boolean;
  onDecide: (decision: ReviewDecision) => void;
}) {
  const { t } = useTranslation();
  const verdict = parseReviewVerdict(item.ai_verdict);
  const pending = item.status === 'pending';
  const canLastingBlock = pending || item.status === 'blocked';
  return (
    <article className="rounded-lg border border-border p-4 mb-3 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={pending ? 'warning' : item.status === 'blocked' ? 'destructive' : 'success'}>
          {t(statusLabelKey(item.status))}
        </Badge>
        <Badge variant="outline">{t(shapeLabelKey(item.shape))}</Badge>
        <Badge variant="outline">{displayCategory(item.category, t)}</Badge>
        <Badge variant="outline">{t('review.level')} {item.protection_level}</Badge>
        <time className="text-sm text-muted-foreground" dateTime={item.created_at}>{formatReviewTime(item.created_at, locale)}</time>
      </div>
      <div className="grid gap-2 text-sm">
        <div><span className="text-muted-foreground">{t('review.path')}: </span><code>{item.uri || '-'}</code></div>
        <div><span className="text-muted-foreground">{t('review.payload')}: </span><code className="break-all">{item.payload || '-'}</code></div>
        <div><span className="text-muted-foreground">{t('review.source')}: </span>{item.client_ip || '-'} {item.param_name ? `· ${item.param_name}` : ''}</div>
        {item.fingerprint && (
          <div><span className="text-muted-foreground">{t('review.fingerprint')}: </span><code>{item.fingerprint}</code></div>
        )}
        {verdict.summary && (
          <div><span className="text-muted-foreground">{t('review.modelVerdict')}: </span>{verdict.summary}</div>
        )}
        {item.decided_by_name && (
          <div><span className="text-muted-foreground">{t('review.decidedBy')}: </span>{item.decided_by_name}</div>
        )}
        {item.applied_rule_id && (
          <div><span className="text-muted-foreground">{t('review.appliedRule')}: </span><code>{item.applied_rule_id}</code></div>
        )}
      </div>
      {canLastingBlock && (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={busy} onClick={() => onDecide('block_payload')}>{t('review.blockPayload')}</Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => onDecide('block_uri')}>{t('review.blockUri')}</Button>
          <Button size="sm" variant="outline" disabled={busy} onClick={() => onDecide('block_ip')}>{t('review.blockIp')}</Button>
          <Button size="sm" variant="outline" disabled={busy || !item.fingerprint} onClick={() => onDecide('block_fingerprint')}>
            {t('review.blockFingerprint')}
          </Button>
          {pending && (
            <>
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => onDecide('allow')}>{t('review.allow')}</Button>
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => onDecide('allow_whitelist')}>
                {t('review.allowWhitelist')}
              </Button>
            </>
          )}
        </div>
      )}
    </article>
  );
}
