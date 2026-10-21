import { useDeferredValue, useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ShieldAlert } from 'lucide-react';
import {
  Badge,
  Button,
  Checkbox,
  Empty,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import {
  approveIntelCandidate,
  fetchIntelCandidates,
  importIntelURL,
  rejectIntelCandidate,
} from '../../api/intel';
import { currentAccount, hasScope } from '../../authProfile';
import QueryErrorState from '../../components/QueryErrorState';
import type { IntelCandidate, IntelCandidateState, IntelImportRequest } from '../../types/api';
import { displayAction } from '../../utils/display';

const ALL_STATES = '__all__';
const STATE_LABEL_KEYS: Record<IntelCandidateState, string> = {
  draft: 'ai.intelStateDraft',
  shadow: 'ai.intelStateShadow',
  canary: 'ai.intelStateCanary',
  active: 'ai.intelStateActive',
  expired: 'ai.intelStateExpired',
  rejected: 'ai.intelStateRejected',
};
const STATE_BADGE_VARIANTS: Record<IntelCandidateState, 'secondary' | 'warning' | 'default' | 'success' | 'destructive'> = {
  draft: 'secondary',
  shadow: 'warning',
  canary: 'default',
  active: 'success',
  expired: 'destructive',
  rejected: 'destructive',
};
const APPROVAL_ACTIONS = ['log', 'challenge', 'block'] as const;
type ApprovalAction = typeof APPROVAL_ACTIONS[number];

export type IntelImportValidation = 'url' | 'site' | 'path' | null;

/** Client-side mirror of the server scope validation, so obvious mistakes never hit the API. */
export function validateIntelImport(url: string, siteId: string, pathPrefix: string): IntelImportValidation {
  const target = url.trim();
  let parsed: URL | null = null;
  try {
    parsed = new URL(target);
  } catch {
    parsed = null;
  }
  if (
    !parsed
    || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.hash !== ''
  ) {
    return 'url';
  }
  const site = siteId.trim();
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(site) || ['*', 'all', 'global'].includes(site.toLowerCase())) {
    return 'site';
  }
  const prefix = pathPrefix.trim();
  if (prefix !== '') {
    if (!prefix.startsWith('/') || prefix === '/' || /\s/.test(prefix)) {
      return 'path';
    }
  }
  return null;
}

export function canSubmitIntelApproval(confirm: boolean, approvedBy: string) {
  const name = approvedBy.trim();
  return confirm && name.length > 0 && name.length <= 128;
}

export type IntelRuleSummary = {
  cve: string;
  step: string;
  location: string;
  pattern: string;
  method: string;
  path: string;
};

type IntelRulePayload = {
  rule?: { id?: unknown; name?: unknown; description?: unknown; location?: unknown; pattern?: unknown };
  scope?: { path_prefix?: unknown; methods?: unknown };
};

/** Reads the display-only parts of the compiled rule; candidate fields stay authoritative. */
export function summarizeIntelRule(ruleJSON: string): IntelRuleSummary {
  try {
    const decoded = JSON.parse(ruleJSON) as IntelRulePayload;
    const rule = decoded.rule ?? {};
    const scope = decoded.scope ?? {};
    const name = typeof rule.name === 'string' ? rule.name : '';
    const description = typeof rule.description === 'string' ? rule.description : '';
    const matches = `${name} ${description}`.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
    const cves = matches
      .map((value) => value.toUpperCase())
      .filter((value, index, all) => all.indexOf(value) === index);
    const classMatch = description.match(/\bclass=([a-z0-9-]+)/i);
    const step = classMatch?.[1] ?? (typeof rule.id === 'string' ? rule.id : '');
    const methods = Array.isArray(scope.methods) ? scope.methods.filter((value) => typeof value === 'string') : [];
    return {
      cve: cves.join(', '),
      step,
      location: typeof rule.location === 'string' ? rule.location : '',
      pattern: typeof rule.pattern === 'string' ? rule.pattern : '',
      method: methods.join(', '),
      path: typeof scope.path_prefix === 'string' ? scope.path_prefix : '',
    };
  } catch {
    return { cve: '', step: '', location: '', pattern: '', method: '', path: '' };
  }
}

function confidenceLabel(value: number) {
  if (!Number.isFinite(value)) {
    return '-';
  }
  return `${(value * 100).toFixed(1)}%`;
}

export default function IntelPanel() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const account = useMemo(() => currentAccount(), []);
  const canMutate = hasScope(account, 'write:protection') || hasScope(account, 'write:rules');
  // The API mounts the entire intel surface behind a write scope so a
  // read-only account cannot trigger imports or review mutations.
  const canView = canMutate;

  const [url, setUrl] = useState('');
  const [siteId, setSiteId] = useState('');
  const [pathPrefix, setPathPrefix] = useState('');
  const [stateFilter, setStateFilter] = useState<string>(ALL_STATES);
  const [importError, setImportError] = useState('');
  const [approvingId, setApprovingId] = useState('');
  const [approvedBy, setApprovedBy] = useState('');
  const [approvalConfirmed, setApprovalConfirmed] = useState(false);
  const [approvalAction, setApprovalAction] = useState<ApprovalAction>('log');
  const [approvalError, setApprovalError] = useState('');
  const deferredSiteId = useDeferredValue(siteId.trim());

  const candidatesQuery = useQuery({
    queryKey: ['intel-candidates', deferredSiteId, stateFilter],
    queryFn: () => fetchIntelCandidates({
      ...(deferredSiteId ? { site_id: deferredSiteId } : {}),
      ...(stateFilter === ALL_STATES ? {} : { state: stateFilter as IntelCandidateState }),
    }),
    enabled: canView,
    retry: false,
  });

  const importMutation = useMutation({
    mutationFn: (payload: IntelImportRequest) => importIntelURL(payload),
    onSuccess: (result) => {
      setImportError('');
      setApprovingId('');
      queryClient.invalidateQueries({ queryKey: ['intel-candidates'] });
      toast.success(t('ai.intelImportOk', { candidates: result.candidates.length }));
    },
    onError: (error) => setImportError(error.message),
  });

  const approveMutation = useMutation({
    mutationFn: (candidateId: string) => approveIntelCandidate(candidateId, {
      approved_by: approvedBy.trim(),
      confirm: true,
      action: approvalAction,
    }),
    onSuccess: () => {
      setApprovalError('');
      setApprovingId('');
      queryClient.invalidateQueries({ queryKey: ['intel-candidates'] });
      toast.success(t('ai.intelApproveOk'));
    },
    onError: (error) => setApprovalError(error.message),
  });

  const rejectMutation = useMutation({
    mutationFn: (candidateId: string) => rejectIntelCandidate(candidateId),
    onSuccess: () => {
      setApprovingId('');
      queryClient.invalidateQueries({ queryKey: ['intel-candidates'] });
      toast.success(t('ai.intelRejectOk'));
    },
    onError: (error) => toast.error(error.message),
  });

  if (!canView) {
    return null;
  }

  const candidates = candidatesQuery.data?.candidates ?? [];

  function handleImport(event: FormEvent) {
    event.preventDefault();
    const invalid = validateIntelImport(url, siteId, pathPrefix);
    if (invalid) {
      setImportError(t(
        invalid === 'url' ? 'ai.intelInvalidUrl' : invalid === 'site' ? 'ai.intelInvalidSite' : 'ai.intelInvalidPath',
      ));
      return;
    }
    setImportError('');
    importMutation.mutate({
      url: url.trim(),
      site_id: siteId.trim(),
      ...(pathPrefix.trim() ? { path_prefix: pathPrefix.trim() } : {}),
    });
  }

  function openApproval(candidate: IntelCandidate) {
    setApprovingId(candidate.id);
    setApprovedBy(account.username);
    setApprovalConfirmed(false);
    setApprovalAction('log');
    setApprovalError('');
  }

  function closeApproval() {
    setApprovingId('');
    setApprovalConfirmed(false);
    setApprovalError('');
  }

  const approvalReady = canMutate && canSubmitIntelApproval(approvalConfirmed, approvedBy);

  return (
    <section className="panel mt-6" aria-labelledby="intel-panel-title">
      <div className="panel-heading">
        <div>
          <h2 id="intel-panel-title"><ShieldAlert size={16} /> {t('ai.intelTitle')}</h2>
          <p>{t('ai.intelSubtitle')}</p>
        </div>
        <Badge variant="secondary">{t('ai.intelCandidateCount', { count: candidatesQuery.data?.count ?? candidates.length })}</Badge>
      </div>

      <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm" role="note">
        {t('ai.intelReviewNotice')}
      </div>

      {!canMutate && (
        <p className="mt-2 text-xs text-muted-foreground">{t('ai.intelReadOnly')}</p>
      )}

      <form className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto] xl:items-end" onSubmit={handleImport}>
        <div className="space-y-1.5">
          <Label htmlFor="intel-import-url">{t('ai.intelUrl')}</Label>
          <Input
            id="intel-import-url"
            type="url"
            value={url}
            placeholder={t('ai.intelUrlPlaceholder')}
            onChange={(event) => setUrl(event.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="intel-import-site">{t('ai.intelSiteID')}</Label>
          <Input
            id="intel-import-site"
            value={siteId}
            placeholder={t('ai.intelSiteIDPlaceholder')}
            onChange={(event) => setSiteId(event.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="intel-import-path">{t('ai.intelPathPrefix')}</Label>
          <Input
            id="intel-import-path"
            value={pathPrefix}
            placeholder={t('ai.intelPathPrefixPlaceholder')}
            onChange={(event) => setPathPrefix(event.target.value)}
          />
        </div>
        <Button type="submit" loading={importMutation.isPending} disabled={!canMutate}>
          {t('ai.intelImport')}
        </Button>
      </form>
      <p className="mt-2 text-xs text-muted-foreground">{t('ai.intelListHint')}</p>
      {importError ? <p className="mt-2 text-sm text-destructive" role="alert">{importError}</p> : null}

      <div className="mt-4 flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="intel-state-filter">{t('ai.intelFilterState')}</Label>
          <Select value={stateFilter} onValueChange={setStateFilter}>
            <SelectTrigger id="intel-state-filter" className="w-[190px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_STATES}>{t('ai.intelAllStates')}</SelectItem>
              {(Object.keys(STATE_LABEL_KEYS) as IntelCandidateState[]).map((state) => (
                <SelectItem key={state} value={state}>{t(STATE_LABEL_KEYS[state])}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <p className="text-xs text-muted-foreground">{t('ai.intelNoBlockDefault')}</p>
      </div>

      {candidatesQuery.isLoading && (
        <p className="py-6 text-sm text-muted-foreground" role="status">{t('common.loading')}</p>
      )}
      {candidatesQuery.isError && (
        <QueryErrorState
          className="mt-4"
          message={candidatesQuery.error?.message}
          onRetry={() => candidatesQuery.refetch()}
          retrying={candidatesQuery.isFetching}
        />
      )}
      {!candidatesQuery.isLoading && !candidatesQuery.isError && candidates.length === 0 && (
        <Empty className="py-8" description={t('ai.intelEmpty')} />
      )}

      {!candidatesQuery.isError && candidates.length > 0 && (
        <Table className="mt-4">
          <TableCaption className="sr-only">{t('ai.intelCandidates')}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t('ai.intelState')}</TableHead>
              <TableHead>{t('ai.intelAction')}</TableHead>
              <TableHead>{t('ai.intelConfidence')}</TableHead>
              <TableHead>{t('ai.intelCVE')}</TableHead>
              <TableHead>{t('ai.intelStep')}</TableHead>
              <TableHead className="text-right">{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {candidates.map((candidate) => {
              const summary = summarizeIntelRule(candidate.rule_json);
              const closed = candidate.state === 'expired' || candidate.state === 'rejected';
              const approving = approvingId === candidate.id;
              return (
                <IntelCandidateRows
                  key={candidate.id}
                  candidate={candidate}
                  summary={summary}
                  closed={closed}
                  canMutate={canMutate}
                  approving={approving}
                  approvalReady={approvalReady}
                  approvedBy={approvedBy}
                  approvalConfirmed={approvalConfirmed}
                  approvalAction={approvalAction}
                  approvalError={approvalError}
                  approvePending={approveMutation.isPending && approveMutation.variables === candidate.id}
                  rejectPending={rejectMutation.isPending && rejectMutation.variables === candidate.id}
                  onOpenApproval={() => openApproval(candidate)}
                  onCloseApproval={closeApproval}
                  onApprovedByChange={setApprovedBy}
                  onConfirmChange={setApprovalConfirmed}
                  onActionChange={setApprovalAction}
                  onApprove={() => approveMutation.mutate(candidate.id)}
                  onReject={() => rejectMutation.mutate(candidate.id)}
                />
              );
            })}
          </TableBody>
        </Table>
      )}
    </section>
  );
}

type IntelCandidateRowsProps = {
  candidate: IntelCandidate;
  summary: IntelRuleSummary;
  closed: boolean;
  canMutate: boolean;
  approving: boolean;
  approvalReady: boolean;
  approvedBy: string;
  approvalConfirmed: boolean;
  approvalAction: ApprovalAction;
  approvalError: string;
  approvePending: boolean;
  rejectPending: boolean;
  onOpenApproval: () => void;
  onCloseApproval: () => void;
  onApprovedByChange: (value: string) => void;
  onConfirmChange: (value: boolean) => void;
  onActionChange: (value: ApprovalAction) => void;
  onApprove: () => void;
  onReject: () => void;
};

function IntelCandidateRows({
  candidate,
  summary,
  closed,
  canMutate,
  approving,
  approvalReady,
  approvedBy,
  approvalConfirmed,
  approvalAction,
  approvalError,
  approvePending,
  rejectPending,
  onOpenApproval,
  onCloseApproval,
  onApprovedByChange,
  onConfirmChange,
  onActionChange,
  onApprove,
  onReject,
}: IntelCandidateRowsProps) {
  const { t } = useTranslation();
  const rowLabel = candidate.id;
  return (
    <>
      <TableRow>
        <TableCell>
          <Badge variant={STATE_BADGE_VARIANTS[candidate.state] ?? 'secondary'}>
            {t(STATE_LABEL_KEYS[candidate.state] ?? 'ai.intelStateDraft')}
          </Badge>
          <p className="mt-1 text-xs text-muted-foreground">{candidate.site_id}</p>
        </TableCell>
        <TableCell>{displayAction(candidate.action, t)}</TableCell>
        <TableCell>{confidenceLabel(candidate.confidence)}</TableCell>
        <TableCell className="whitespace-nowrap">{summary.cve || '-'}</TableCell>
        <TableCell className="max-w-[220px] truncate" title={summary.step || undefined}>{summary.step || '-'}</TableCell>
        <TableCell>
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              aria-label={t('ai.intelApproveFor', { id: rowLabel })}
              disabled={!canMutate || closed}
              onClick={onOpenApproval}
            >
              {t('ai.intelApprove')}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              aria-label={t('ai.intelRejectFor', { id: rowLabel })}
              disabled={!canMutate || closed}
              loading={rejectPending}
              onClick={onReject}
            >
              {t('ai.intelReject')}
            </Button>
          </div>
        </TableCell>
      </TableRow>
      {approving && (
        <TableRow>
          <TableCell colSpan={6}>
            <div className="space-y-3 rounded-md border bg-muted/30 p-3">
              <div>
                <strong className="text-sm">{t('ai.intelApprovalTitle', { id: rowLabel })}</strong>
                <p className="text-xs text-muted-foreground">{t('ai.intelApproveHint')}</p>
              </div>
              <dl className="grid gap-2 rounded-md border bg-background p-2 text-xs md:grid-cols-2">
                <div><dt className="font-medium">{t('ai.intelDetailLocation')}</dt><dd className="font-mono break-all">{summary.location || '-'}</dd></div>
                <div><dt className="font-medium">{t('ai.intelDetailScope')}</dt><dd className="font-mono break-all">{summary.method || '-'} {summary.path || '-'}</dd></div>
                <div className="md:col-span-2"><dt className="font-medium">{t('ai.intelDetailPattern')}</dt><dd className="font-mono break-all">{summary.pattern || '-'}</dd></div>
                <div className="md:col-span-2"><dt className="font-medium">{t('ai.intelDetailEvidence')}</dt><dd className="break-all">{candidate.provenance.source_id || '-'} / {candidate.provenance.item_id || '-'}</dd></div>
              </dl>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <div className="space-y-1.5">
                  <Label htmlFor={`intel-approver-${candidate.id}`}>{t('ai.intelApprovedBy')}</Label>
                  <Input
                    id={`intel-approver-${candidate.id}`}
                    value={approvedBy}
                    maxLength={128}
                    autoComplete="off"
                    placeholder={t('ai.intelApprovedByPlaceholder')}
                    onChange={(event) => onApprovedByChange(event.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor={`intel-approval-action-${candidate.id}`}>{t('ai.intelApprovalAction')}</Label>
                  <Select value={approvalAction} onValueChange={(value) => onActionChange(value as ApprovalAction)}>
                    <SelectTrigger id={`intel-approval-action-${candidate.id}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {APPROVAL_ACTIONS.map((action) => (
                        <SelectItem key={action} value={action}>{displayAction(action, t)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <Checkbox
                  id={`intel-confirm-${candidate.id}`}
                  aria-labelledby={`intel-confirm-label-${candidate.id}`}
                  checked={approvalConfirmed}
                  onCheckedChange={(checked) => onConfirmChange(checked === true)}
                />
                <Label id={`intel-confirm-label-${candidate.id}`} className="text-sm font-normal leading-5">
                  {t('ai.intelConfirmCheckbox')}
                </Label>
              </div>
              {approvalError ? <p className="text-sm text-destructive" role="alert">{approvalError}</p> : null}
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  disabled={!approvalReady}
                  loading={approvePending}
                  onClick={onApprove}
                >
                  {t('ai.intelConfirmApproval')}
                </Button>
                <Button type="button" size="sm" variant="ghost" onClick={onCloseApproval}>
                  {t('common.cancel')}
                </Button>
              </div>
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
