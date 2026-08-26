import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
  toast,
} from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Ban, CheckCircle2, CloudDownload, FileDown, ListPlus, Pencil, Plus, RotateCcw, Search, Shield, Tags, Trash2, X } from 'lucide-react';
import {
  exportThreatIntel,
  fetchIPRules,
  fetchSites,
  importThreatIntel,
  lookupThreatIntel,
  adoptThreatIntel,
  syncThreatIntel,
  testThreatIntelProvider,
  updateIPAccessRules,
  updateIPReputationOverrides,
  updateIPTags,
  updateThreatIntelProviders,
} from '../../api/client';
import type { IPAccessRule, IPReputationEntry, ThreatIntelProvider } from '../../types/api';
import { displayAction, displaySeverity } from '../../utils/display';
import '../../styles/ip-manage.css';

const second = 1_000_000_000;
const formatOptions = ['cidr', 'csv', 'json', 'stix', 'misp', 'abuseipdb', 'otx', 'threatbook'] as const;
const providerTemplates = [
  { type: 'generic', format: 'stix', auth_type: 'bearer', endpoint: '', nameKey: 'ip.providerTypeGeneric', hintKey: 'ip.providerGenericHint' },
  { type: 'threatbook-cn', format: 'threatbook', auth_type: 'query', endpoint: 'https://api.threatbook.cn/v3/ip/query', nameKey: 'ip.providerTypeThreatBookCN', hintKey: 'ip.providerThreatBookCNHint' },
  { type: 'threatbook-intl', format: 'threatbook', auth_type: 'query', endpoint: 'https://api.threatbook.io/v2/ip/query', nameKey: 'ip.providerTypeThreatBookIntl', hintKey: 'ip.providerThreatBookIntlHint' },
  { type: 'abuseipdb', format: 'abuseipdb', auth_type: 'header', endpoint: 'https://api.abuseipdb.com/api/v2/check', nameKey: 'ip.providerTypeAbuseIPDB', hintKey: 'ip.providerAbuseIPDBHint' },
  { type: 'otx', format: 'otx', auth_type: 'header', endpoint: 'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', nameKey: 'ip.providerTypeOTX', hintKey: 'ip.providerOTXHint' },
  { type: 'misp', format: 'misp', auth_type: 'header', endpoint: '', nameKey: 'ip.providerTypeMISP', hintKey: 'ip.providerMISPHint' },
  { type: 'stix', format: 'stix', auth_type: 'bearer', endpoint: '', nameKey: 'ip.providerTypeSTIX', hintKey: 'ip.providerSTIXHint' },
] as const;
type IntelStatusTone = 'success' | 'warning' | 'error';
type IntelOperationStatus = {
  tone: IntelStatusTone;
  title: string;
  detail: string;
  at: string;
  items?: Array<Record<string, unknown>>;
};

const defaultAccessDraft: IPAccessRule = {
  id: '',
  name: '',
  description: '',
  action: 'allow',
  scope: 'global',
  site_id: '',
  path_prefix: '',
  entries: [],
  enabled: true,
};

export default function IPManagePage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [routeParams, setRouteParams] = useSearchParams();
  const tabParam = routeParams.get('tab');
  const normalizedTab = tabParam === 'intel' ? 'providers' : tabParam;
  const activeTab = normalizedTab === 'access' || normalizedTab === 'providers' || normalizedTab === 'import' ? normalizedTab : 'entries';
  const [search, setSearch] = useState('');
  const [draftTags, setDraftTags] = useState<Record<string, string[]>>({});
  const [accessRules, setAccessRules] = useState<IPAccessRule[]>([]);
  const [reputationOverrides, setReputationOverrides] = useState<Record<string, number>>({});
  const [accessDraft, setAccessDraft] = useState<IPAccessRule>(defaultAccessDraft);
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [importDraft, setImportDraft] = useState({
    format: 'cidr',
    source: 'manual',
    severity: 'high',
    action: 'challenge',
    confidence: 0.9,
    labels: [] as string[],
    contents: '',
  });
  const [lookupDraft, setLookupDraft] = useState({ providerId: '', ip: '' });
  const [lookupItems, setLookupItems] = useState<Array<Record<string, unknown>>>([]);
  const [providerStatuses, setProviderStatuses] = useState<Record<string, IntelOperationStatus>>({});
  const [importStatus, setImportStatus] = useState<IntelOperationStatus | null>(null);
  const [syncStatus, setSyncStatus] = useState<IntelOperationStatus | null>(null);
  const [lookupStatus, setLookupStatus] = useState<IntelOperationStatus | null>(null);
  const [exportingFormat, setExportingFormat] = useState<'csv' | 'stix' | null>(null);
  const [deleteRuleId, setDeleteRuleId] = useState<string | null>(null);
  const [entriesPage, setEntriesPage] = useState(1);
  const tagsDirtyRef = useRef(false);
  const accessRulesDirtyRef = useRef(false);
  const reputationDirtyRef = useRef(false);
  const providersDirtyRef = useRef(false);
  const { data, isLoading } = useQuery({ queryKey: ['ip-rules'], queryFn: fetchIPRules, retry: false });
  const { data: sites = [] } = useQuery({ queryKey: ['sites-lite'], queryFn: fetchSites, retry: false });
  const entries = data?.entries ?? [];
  const hasThreatIntel = (data?.threat_intel?.length ?? 0) > 0;
  const tagsChanged = useMemo(() => {
    if (!data?.tags) {
      return Object.values(draftTags).some((tags) => tags.length > 0);
    }
    return stableTagSnapshot(draftTags) !== stableTagSnapshot(data.tags);
  }, [data?.tags, draftTags]);

  useEffect(() => {
    if (!data?.tags || tagsDirtyRef.current) {
      return;
    }
    setDraftTags(data.tags);
  }, [data?.tags]);

  useEffect(() => {
    if (!data?.access_rules || accessRulesDirtyRef.current) {
      return;
    }
    setAccessRules(data.access_rules);
  }, [data?.access_rules]);

  useEffect(() => {
    if (!data?.reputation_overrides || reputationDirtyRef.current) {
      return;
    }
    setReputationOverrides(data.reputation_overrides);
  }, [data?.reputation_overrides]);

  useEffect(() => {
    if (!data?.providers || providersDirtyRef.current) {
      return;
    }
    setProviders(data.providers);
  }, [data?.providers]);

  useEffect(() => {
    if (lookupDraft.providerId || !data?.providers?.length) {
      return;
    }
    setLookupDraft((current) => (current.providerId ? current : { ...current, providerId: data.providers[0].id }));
  }, [data?.providers, lookupDraft.providerId]);

  const tagMutation = useMutation({
    mutationFn: updateIPTags,
    onSuccess: () => {
      tagsDirtyRef.current = false;
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
  });
  const accessRulesMutation = useMutation({
    mutationFn: updateIPAccessRules,
    onSuccess: (saved) => {
      accessRulesDirtyRef.current = false;
      setAccessRules(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      toast.success(t('ip.accessRulesSaved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const reputationMutation = useMutation({
    mutationFn: updateIPReputationOverrides,
    onSuccess: (saved) => {
      reputationDirtyRef.current = false;
      setReputationOverrides(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      toast.success(t('ip.reputationSaved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const providersMutation = useMutation({
    mutationFn: updateThreatIntelProviders,
    onSuccess: (saved) => {
      providersDirtyRef.current = false;
      setProviders(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      toast.success(t('ip.providersSaved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const importMutation = useMutation({
    mutationFn: importThreatIntel,
    onSuccess: (result) => {
      const status = buildCountStatus({
        tone: result.imported > 0 ? 'success' : 'warning',
        title: result.imported > 0 ? t('ip.importApplied') : t('ip.importNoItems'),
        countLabel: t('ip.imported'),
        imported: result.imported,
        total: result.total,
        t,
      });
      setImportStatus(status);
      showStatusMessage(status);
      setImportDraft((current) => ({ ...current, contents: '' }));
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error) => {
      setImportStatus(buildErrorStatus(t('ip.importFailed'), error.message));
      toast.error(error.message);
    },
  });
  const syncMutation = useMutation({
    mutationFn: syncThreatIntel,
    onSuccess: (result, providerId) => {
      const status = buildCountStatus({
        tone: result.imported > 0 ? 'success' : 'warning',
        title: result.imported > 0 ? t('ip.syncApplied') : t('ip.syncNoItems'),
        countLabel: t('ip.synced'),
        imported: result.imported,
        total: result.total,
        t,
        items: result.results,
      });
      setSyncStatus(status);
      if (providerId) {
        setProviderStatuses((current) => ({ ...current, [providerId]: status }));
      }
      showStatusMessage(status);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error, providerId) => {
      const status = buildErrorStatus(t('ip.syncFailed'), error.message);
      setSyncStatus(status);
      if (providerId) {
        setProviderStatuses((current) => ({ ...current, [providerId]: status }));
      }
      toast.error(error.message);
    },
  });
  const providerTestMutation = useMutation({
    mutationFn: testThreatIntelProvider,
    onSuccess: (result, provider) => {
      const status: IntelOperationStatus = {
        tone: result.ok && result.count > 0 ? 'success' : 'warning',
        title: result.ok && result.count > 0 ? t('ip.providerTestUsable') : t('ip.providerTestClean'),
        detail: `${t('ip.parsedItems')}: ${result.count}`,
        at: formatStatusTime(),
      };
      setProviderStatuses((current) => ({ ...current, [provider.id]: status }));
      showStatusMessage(status);
    },
    onError: (error, provider) => {
      setProviderStatuses((current) => ({ ...current, [provider.id]: buildErrorStatus(t('ip.providerTestFailed'), error.message) }));
      toast.error(error.message);
    },
  });
  const lookupMutation = useMutation({
    mutationFn: () => lookupThreatIntel(lookupDraft.providerId, lookupDraft.ip),
    onSuccess: (result) => {
      const found = result.items.length > 0;
      const status = buildCountStatus({
        tone: found ? 'success' : 'warning',
        title: found ? t('ip.lookupFound') : t('ip.lookupClean'),
        countLabel: t('ip.parsedItems'),
        imported: result.items.length,
        total: result.items.length,
        t,
        items: result.items,
      });
      setLookupStatus(status);
      setLookupItems(result.items);
      setProviderStatuses((current) => ({ ...current, [lookupDraft.providerId]: status }));
      showStatusMessage(status);
    },
    onError: (error) => {
      const status = buildErrorStatus(t('ip.lookupFailed'), error.message);
      setLookupStatus(status);
      setLookupItems([]);
      setProviderStatuses((current) => ({ ...current, [lookupDraft.providerId]: status }));
      toast.error(error.message);
    },
  });
  const adoptMutation = useMutation({
    mutationFn: () => adoptThreatIntel(lookupItems),
    onSuccess: (result) => {
      const status = buildCountStatus({
        tone: result.imported > 0 ? 'success' : 'warning',
        title: t('ip.lookupApplied'),
        countLabel: t('ip.lookupImported'),
        imported: result.imported,
        total: result.total,
        t,
        items: result.items,
      });
      setLookupStatus(status);
      setProviderStatuses((current) => ({ ...current, [lookupDraft.providerId]: status }));
      showStatusMessage(status);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error) => {
      const status = buildErrorStatus(t('ip.lookupFailed'), error.message);
      setLookupStatus(status);
      toast.error(error.message);
    },
  });

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) => (
      entry.ip.toLowerCase().includes(needle)
      || entry.list.includes(needle)
      || tagsFor(entry, draftTags).some((tag) => tag.toLowerCase().includes(needle))
      || intelFor(entry).some((intel) => `${intel.source} ${intel.severity} ${intel.labels.join(' ')}`.toLowerCase().includes(needle))
    ));
  }, [draftTags, entries, search]);
  const entriesPageSize = 10;
  const entriesPageCount = Math.max(1, Math.ceil(filtered.length / entriesPageSize));
  const pagedEntries = useMemo(() => {
    const start = (entriesPage - 1) * entriesPageSize;
    return filtered.slice(start, start + entriesPageSize);
  }, [entriesPage, entriesPageSize, filtered]);

  useEffect(() => {
    setEntriesPage(1);
  }, [search]);

  useEffect(() => {
    setEntriesPage((current) => Math.min(current, entriesPageCount));
  }, [entriesPageCount]);

  const updateProvider = (index: number, patch: Partial<ThreatIntelProvider>) => {
    providersDirtyRef.current = true;
    setProviders((current) => current.map((provider, providerIndex) => (providerIndex === index ? { ...provider, ...patch } : provider)));
  };
  const removeProvider = (id: string) => {
    providersDirtyRef.current = true;
    setProviders((current) => current.filter((provider) => provider.id !== id));
  };
  const addProvider = () => {
    providersDirtyRef.current = true;
    const template = providerTemplates[0];
    setProviders((current) => [
      ...current,
      {
        id: `provider-${Date.now()}`,
        name: '',
        type: template.type,
        endpoint: template.endpoint,
        api_key: '',
        auth_type: template.auth_type,
        format: template.format,
        action: 'challenge',
        min_severity: 'high',
        interval: 24 * 60 * 60 * second,
        headers: {},
        notes: '',
        enabled: true,
      },
    ]);
  };
  const applyProviderTemplate = (index: number, type: string) => {
    const template = providerTemplates.find((item) => item.type === type);
    if (!template) {
      updateProvider(index, { type });
      return;
    }
    providersDirtyRef.current = true;
    setProviders((current) => current.map((provider, providerIndex) => {
      if (providerIndex !== index) {
        return provider;
      }
      return {
        ...provider,
        type: template.type,
        format: template.format,
        auth_type: template.auth_type,
        endpoint: template.endpoint || provider.endpoint,
        name: provider.name || t(template.nameKey),
      };
    }));
  };
  const defaultAccessRuleName = t('ip.defaultAccessRuleName');
  const saveAccessRules = (nextRules = accessRules) => {
    accessRulesMutation.mutate(nextRules.map((rule) => normalizeAccessRuleForSave(rule, defaultAccessRuleName)).filter((rule) => rule.entries.length > 0));
  };
  const addAccessRule = () => {
    const entries = accessDraft.entries.length > 0 ? accessDraft.entries : splitList(accessDraft.entries.join(','));
    if (entries.length === 0) {
      toast.warning(t('ip.entriesRequired'));
      return;
    }
    const invalidEntries = entries.filter((entry) => !isValidIPOrCIDR(entry));
    if (invalidEntries.length > 0) {
      toast.warning(t('ip.entriesInvalid', { value: invalidEntries.slice(0, 3).join(', ') }));
      return;
    }
    if ((accessDraft.scope === 'site' || accessDraft.scope === 'path') && !accessDraft.site_id) {
      toast.warning(t('ip.scopedSiteRequired'));
      return;
    }
    if (accessDraft.scope === 'path' && !accessDraft.path_prefix.trim()) {
      toast.warning(t('ip.pathRequired'));
      return;
    }
    const nextRule = normalizeAccessRuleForSave({
      ...accessDraft,
      id: accessDraft.id || `ip-rule-${Date.now()}`,
      name: accessDraft.name || entries[0],
      entries,
    }, defaultAccessRuleName);
    const nextRules = [...accessRules, nextRule];
    accessRulesDirtyRef.current = true;
    setAccessRules(nextRules);
    setAccessDraft(defaultAccessDraft);
    saveAccessRules(nextRules);
  };
  const saveEditedAccessRule = (index: number) => {
    const nextRules = accessRules.map((rule, ruleIndex) => (ruleIndex === index ? normalizeAccessRuleForSave(rule, defaultAccessRuleName) : rule));
    const current = nextRules[index];
    if (!current || current.entries.length === 0) {
      toast.warning(t('ip.entriesRequired'));
      return;
    }
    const invalidEntries = current.entries.filter((entry) => !isValidIPOrCIDR(entry));
    if (invalidEntries.length > 0) {
      toast.warning(t('ip.entriesInvalid', { value: invalidEntries.slice(0, 3).join(', ') }));
      return;
    }
    if ((current.scope === 'site' || current.scope === 'path') && !current.site_id) {
      toast.warning(t('ip.scopedSiteRequired'));
      return;
    }
    if (current.scope === 'path' && !current.path_prefix.trim()) {
      toast.warning(t('ip.pathRequired'));
      return;
    }
    accessRulesDirtyRef.current = true;
    setAccessRules(nextRules);
    saveAccessRules(nextRules);
  };
  const removeAccessRule = (id: string) => {
    setDeleteRuleId(id);
  };
  const confirmRemoveAccessRule = () => {
    if (!deleteRuleId) {
      return;
    }
    const nextRules = accessRules.filter((rule) => rule.id !== deleteRuleId);
    accessRulesDirtyRef.current = true;
    setAccessRules(nextRules);
    saveAccessRules(nextRules);
    setDeleteRuleId(null);
  };
  const updateAccessRule = (index: number, patch: Partial<IPAccessRule>) => {
    accessRulesDirtyRef.current = true;
    setAccessRules((current) => current.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)));
  };
  const applyIPDisposition = (ip: string, action: 'allow' | 'block' | 'monitor') => {
    const cleaned = accessRules
      .map((rule) => ({ ...rule, entries: rule.entries.filter((entry) => entry !== ip) }))
      .filter((rule) => rule.entries.length > 0);
    const nextRules = [
        ...cleaned,
        {
          ...defaultAccessDraft,
          id: `manual-${action}-${safeRuleID(ip)}`,
          name: action === 'allow'
            ? `${t('ip.allow')} ${ip}`
            : action === 'block'
              ? `${t('ip.block')} ${ip}`
              : `${t('common.monitor')} ${ip}`,
          action,
          scope: 'global',
          entries: [ip],
          enabled: true,
        },
      ];
    accessRulesDirtyRef.current = true;
    setAccessRules(nextRules);
    saveAccessRules(nextRules);
  };
  const saveReputationOverride = (ip: string, score: number) => {
    reputationDirtyRef.current = true;
    reputationMutation.mutate({ ...reputationOverrides, [ip]: Math.max(0, Math.min(100, Math.round(score))) });
  };
  const resetReputationOverride = (ip: string) => {
    reputationDirtyRef.current = true;
    const next = { ...reputationOverrides };
    delete next[ip];
    reputationMutation.mutate(next);
  };
  const saveIntelFile = async (format: 'csv' | 'stix') => {
    if (exportingFormat) {
      return;
    }
    setExportingFormat(format);
    try {
      const blob = await exportThreatIntel(format);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `cheesewaf-threat-intel.${format === 'stix' ? 'json' : 'csv'}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('common.requestFailed'));
    } finally {
      setExportingFormat(null);
    }
  };
  const validateImportDraft = () => {
    if (!importDraft.contents.trim()) {
      toast.warning(t('ip.iocRequired'));
      return false;
    }
    if (!importDraft.source.trim()) {
      toast.warning(t('ip.sourceRequired'));
      return false;
    }
    const confidencePercent = importDraft.confidence * 100;
    if (!Number.isFinite(confidencePercent) || confidencePercent < 0 || confidencePercent > 100) {
      toast.warning(t('ip.confidenceInvalid'));
      return false;
    }
    if (importDraft.format === 'cidr') {
      const invalid = splitLines(importDraft.contents).filter((line) => !line.startsWith('#') && !isValidIPOrCIDR(firstToken(line)));
      if (invalid.length > 0) {
        toast.warning(t('ip.entriesInvalid', { value: invalid.slice(0, 3).join(', ') }));
        return false;
      }
    }
    return true;
  };
  const runImport = () => {
    if (!validateImportDraft()) {
      return;
    }
    importMutation.mutate({ ...importDraft, source: importDraft.source.trim(), labels: importDraft.labels });
  };


  return (
    <section className="page-surface ip-manage-page">
      <header className="page-header">
        <div>
          <h1>{t('ip.title')}</h1>
          <p>{t('ip.subtitle')}</p>
        </div>
        {(activeTab === 'entries' && tagsChanged) || ((activeTab === 'providers' || activeTab === 'import') && hasThreatIntel) ? (
          <span className="table-identity ip-header-actions">
            {(activeTab === 'providers' || activeTab === 'import') && hasThreatIntel && (
              <>
                <Button variant="outline" loading={exportingFormat === 'csv'} disabled={Boolean(exportingFormat)} onClick={() => { void saveIntelFile('csv'); }}>
                  <FileDown size={16} />{t('ip.exportCsv')}
                </Button>
                <Button variant="outline" loading={exportingFormat === 'stix'} disabled={Boolean(exportingFormat)} onClick={() => { void saveIntelFile('stix'); }}>
                  <FileDown size={16} />{t('ip.exportStix')}
                </Button>
              </>
            )}
            {activeTab === 'entries' && tagsChanged && (
              <Button loading={tagMutation.isPending} onClick={() => tagMutation.mutate(draftTags)}>
                <Tags size={16} />{t('ip.saveTags')}
              </Button>
            )}
          </span>
        ) : null}
      </header>

      <section className="panel ip-manage-panel">
        <Tabs
          value={activeTab}
          onValueChange={(tab) => {
            const next = new URLSearchParams(routeParams);
            if (tab === 'entries') {
              next.delete('tab');
            } else {
              next.set('tab', tab === 'providers' ? 'intel' : tab);
            }
            setRouteParams(next, { replace: true });
          }}
        >
          <TabsList className="mb-3 flex h-auto flex-wrap">
            <TabsTrigger value="entries">{t('ip.entries')}</TabsTrigger>
            <TabsTrigger value="access">{t('ip.accessRules')}</TabsTrigger>
            <TabsTrigger value="providers">{t('ip.providers')}</TabsTrigger>
            <TabsTrigger value="import">{t('ip.import')}</TabsTrigger>
          </TabsList>

          <TabsContent value="entries">
            <div className="toolbar-row toolbar-row-compact ip-toolbar">
              <div className="relative toolbar-search">
                <Search size={16} className="absolute left-2.5 top-1/2 -translate-y-1/2 opacity-50" />
                <Input className="pl-8" value={search} placeholder={t('common.search')} onChange={(event) => setSearch(event.target.value)} />
              </div>
            </div>
            <div className="table-panel table-panel-embedded ip-entries-table">
              {isLoading ? (
                <div className="empty-state" role="status">{t('common.loading')}</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP</TableHead>
                      <TableHead>{t('ip.list')}</TableHead>
                      <TableHead>{t('ip.reputation')}</TableHead>
                      <TableHead>{t('ip.tags')}</TableHead>
                      <TableHead>{t('ip.intel')}</TableHead>
                      <TableHead>{t('ip.activity')}</TableHead>
                      <TableHead>{t('ip.actions')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.map((record) => {
                      const listLabel = record.list === 'whitelist' ? t('ip.whitelist') : record.list === 'blacklist' ? t('ip.blacklist') : t('common.monitor');
                      const stats = statsFor(record);
                      return (
                        <TableRow key={record.ip}>
                          <TableCell>
                            <span className="table-identity"><Shield size={17} />{record.ip}</span>
                          </TableCell>
                          <TableCell><Badge variant={listBadgeVariant(record.list)}>{listLabel}</Badge></TableCell>
                          <TableCell>
                            <ReputationOverrideEditor
                              value={record.reputation}
                              override={record.reputation_override}
                              saving={reputationMutation.isPending}
                              onSave={(score) => saveReputationOverride(record.ip, score)}
                              onReset={() => resetReputationOverride(record.ip)}
                            />
                          </TableCell>
                          <TableCell>
                            <EditableTagInput
                              tags={tagsFor(record, draftTags)}
                              onChange={(tags) => {
                                tagsDirtyRef.current = true;
                                setDraftTags((current) => ({ ...current, [record.ip]: tags }));
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            <span className="intel-chip-list">
                              {intelFor(record).length === 0 ? (
                                <span className="intel-chip intel-chip-muted">{t('common.monitor')}</span>
                              ) : intelFor(record).map((item) => {
                                const confidence = formatConfidenceSuffix(item.confidence);
                                return (
                                  <span key={`${record.ip}-${item.id || item.value}`} className={`intel-chip intel-chip-${intelColor(item.severity)}`}>
                                    <span>{item.source || displaySeverity(item.severity, t)}</span>
                                    <strong>{displayAction(item.action || 'challenge', t)}{confidence}</strong>
                                  </span>
                                );
                              })}
                            </span>
                          </TableCell>
                          <TableCell>{stats.blocked}/{stats.total}</TableCell>
                          <TableCell>
                            <div className="ip-row-actions flex flex-wrap items-center gap-1.5">
                              <Button size="sm" variant="outline" loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'allow')}>
                                <CheckCircle2 size={13} />{t('ip.allow')}
                              </Button>
                              <Button size="sm" variant="destructive" loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'block')}>
                                <Ban size={13} />{t('ip.block')}
                              </Button>
                              <Button size="sm" variant="outline" loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'monitor')}>
                                <RotateCcw size={13} />{t('common.monitor')}
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </div>
            <div className="ip-entry-card-list">
              {isLoading && <div className="empty-state">{t('common.loading')}</div>}
              {!isLoading && filtered.length === 0 && <div className="empty-state">{t('common.noData')}</div>}
              {!isLoading && pagedEntries.map((entry) => (
                <IPEntryMobileCard
                  key={entry.ip}
                  entry={entry}
                  tags={tagsFor(entry, draftTags)}
                  savingAccess={accessRulesMutation.isPending}
                  savingReputation={reputationMutation.isPending}
                  onTagsChange={(tags) => {
                    tagsDirtyRef.current = true;
                    setDraftTags((current) => ({ ...current, [entry.ip]: tags }));
                  }}
                  onAllow={() => applyIPDisposition(entry.ip, 'allow')}
                  onBlock={() => applyIPDisposition(entry.ip, 'block')}
                  onMonitor={() => applyIPDisposition(entry.ip, 'monitor')}
                  onSaveReputation={(score) => saveReputationOverride(entry.ip, score)}
                  onResetReputation={() => resetReputationOverride(entry.ip)}
                  t={t}
                />
              ))}
              {!isLoading && filtered.length > entriesPageSize && (
                <div className="feed-pagination">
                  <span>{t('updates.feedPage', { page: entriesPage, total: entriesPageCount, defaultValue: `Page ${entriesPage} / ${entriesPageCount}` })}</span>
                  <div className="flex gap-2">
                    <Button variant="outline" disabled={entriesPage <= 1} onClick={() => setEntriesPage((current) => Math.max(1, current - 1))}>{t('common.back')}</Button>
                    <Button variant="outline" disabled={entriesPage >= entriesPageCount} onClick={() => setEntriesPage((current) => Math.min(entriesPageCount, current + 1))}>{t('common.next')}</Button>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="access">
            <div className="ip-access-workspace">
              <section className="ip-access-editor">
                <div className="system-section-title">
                  <h2><ListPlus size={16} /> {t('ip.accessRules')}</h2>
                  <Button loading={accessRulesMutation.isPending} onClick={() => saveAccessRules()}>{t('common.save')}</Button>
                </div>
                <div className="ip-access-draft-grid">
                  <label className="ip-access-rule-name-field">
                    <span>{t('rules.name')}</span>
                    <Input value={accessDraft.name} placeholder={t('ip.ruleNamePlaceholder')} onChange={(event) => setAccessDraft((current) => ({ ...current, name: event.target.value }))} />
                  </label>
                  <label className="ip-access-description-field">
                    <span>{t('ip.ruleDescription')}</span>
                    <Input value={accessDraft.description} placeholder={t('ip.ruleDescriptionPlaceholder')} onChange={(event) => setAccessDraft((current) => ({ ...current, description: event.target.value }))} />
                    <small>{t('ip.ruleDescriptionHint')}</small>
                  </label>
                  <label>
                    <span>{t('logs.action')}</span>
                    <Select value={accessDraft.action} onValueChange={(action) => setAccessDraft((current) => ({ ...current, action }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="allow">{t('ip.allow')}</SelectItem>
                        <SelectItem value="block">{t('ip.block')}</SelectItem>
                        <SelectItem value="monitor">{t('common.monitor')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <small>{t('ip.accessActionHint')}</small>
                  </label>
                  <label>
                    <span>{t('ip.scope')}</span>
                    <Select value={accessDraft.scope} onValueChange={(scope) => setAccessDraft((current) => ({ ...current, ...normalizeAccessScopePatch(current, String(scope || 'global')) }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="global">{t('ip.scopeGlobal')}</SelectItem>
                        <SelectItem value="site">{t('ip.scopeSite')}</SelectItem>
                        <SelectItem value="path">{t('ip.scopePath')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <small>{t('ip.accessScopeHint')}</small>
                  </label>
                  <label className="ip-access-site-field">
                    <span>{t('sites.title')}</span>
                    <Select
                      disabled={accessDraft.scope === 'global'}
                      value={accessDraft.site_id || undefined}
                      onValueChange={(site_id) => setAccessDraft((current) => ({ ...current, site_id: String(site_id || '') }))}
                    >
                      <SelectTrigger><SelectValue placeholder={t('ip.optionalSite')} /></SelectTrigger>
                      <SelectContent>
                        {sites.map((site) => <SelectItem key={site.id} value={site.id}>{site.name || site.id}</SelectItem>)}
                      </SelectContent>
                    </Select>
                    <small>{accessDraft.scope === 'global' ? t('ip.globalScopeHint') : accessDraft.scope === 'site' ? t('ip.siteScopeHint') : t('ip.pathScopeSiteHint')}</small>
                  </label>
                  <label className="ip-access-path-field">
                    <span>{t('ip.pathPrefix')}</span>
                    <Input
                      disabled={accessDraft.scope !== 'path'}
                      value={accessDraft.path_prefix}
                      placeholder="/admin"
                      onChange={(event) => setAccessDraft((current) => ({ ...current, path_prefix: event.target.value }))}
                    />
                    <small>{accessDraft.scope === 'path' ? t('ip.pathScopeHint') : t('ip.pathDisabledHint')}</small>
                  </label>
                  <label className="ip-access-entries-field">
                    <span>{t('ip.entriesInput')}</span>
                    <Input value={accessDraft.entries.join(', ')} placeholder="203.0.113.10, 198.51.100.0/24" onChange={(event) => setAccessDraft((current) => ({ ...current, entries: splitList(event.target.value) }))} />
                    <small>{t('ip.entriesHint')}</small>
                  </label>
                  <div className="ip-access-draft-actions">
                    <label className="switch-line ip-access-enabled">
                      <span>{t('rules.enabled')}</span>
                      <Switch checked={accessDraft.enabled} onCheckedChange={(enabled) => setAccessDraft((current) => ({ ...current, enabled }))} />
                    </label>
                    <Button className="ip-access-add-button" onClick={addAccessRule}><Plus size={15} />{t('ip.addRule')}</Button>
                  </div>
                </div>
              </section>
              <div className="table-panel table-panel-embedded ip-access-table">
                <div className="ip-access-table-desktop">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('rules.name')}</TableHead>
                        <TableHead>{t('logs.action')}</TableHead>
                        <TableHead>{t('ip.scope')}</TableHead>
                        <TableHead>{t('ip.entriesInput')}</TableHead>
                        <TableHead>{t('rules.enabled')}</TableHead>
                        <TableHead>{t('ip.actions')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {accessRules.map((rule, index) => (
                        <TableRow key={rule.id}>
                          <TableCell>
                            <div className="ip-access-name-edit space-y-1">
                              <Input value={rule.name || rule.id} onChange={(event) => updateAccessRule(index, { name: event.target.value })} />
                              <Textarea
                                value={rule.description || ''}
                                placeholder={t('ip.ruleDescriptionPlaceholder')}
                                rows={2}
                                onChange={(event) => updateAccessRule(index, { description: event.target.value })}
                              />
                            </div>
                          </TableCell>
                          <TableCell>
                            <Select value={rule.action || 'allow'} onValueChange={(value) => updateAccessRule(index, { action: value })}>
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="allow">{t('ip.allow')}</SelectItem>
                                <SelectItem value="block">{t('ip.block')}</SelectItem>
                                <SelectItem value="monitor">{t('common.monitor')}</SelectItem>
                              </SelectContent>
                            </Select>
                          </TableCell>
                          <TableCell>
                            <AccessRuleScopeEditor rule={rule} sites={sites} t={t} onChange={(patch) => updateAccessRule(index, patch)} />
                          </TableCell>
                          <TableCell>
                            <Input value={(rule.entries || []).join(', ')} onChange={(event) => updateAccessRule(index, { entries: splitList(event.target.value) })} />
                          </TableCell>
                          <TableCell>
                            <Switch checked={rule.enabled} onCheckedChange={(value) => updateAccessRule(index, { enabled: value })} />
                          </TableCell>
                          <TableCell>
                            <span className="action-group ip-access-row-actions">
                              <Button size="sm" variant="outline" loading={accessRulesMutation.isPending} onClick={() => saveEditedAccessRule(index)}>{t('common.save')}</Button>
                              <Button size="sm" variant="destructive" onClick={() => removeAccessRule(rule.id)}><Trash2 size={14} />{t('common.delete')}</Button>
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                <div className="ip-access-card-list">
                  {accessRules.map((rule, index) => (
                    <article className="ip-access-rule-card" key={rule.id || index}>
                      <label className="ip-access-rule-card-name">
                        <span>{t('rules.name')}</span>
                        <Input value={rule.name || rule.id} onChange={(event) => updateAccessRule(index, { name: event.target.value })} />
                      </label>
                      <label className="ip-access-rule-card-description">
                        <span>{t('ip.ruleDescription')}</span>
                        <Textarea
                          value={rule.description || ''}
                          placeholder={t('ip.ruleDescriptionPlaceholder')}
                          rows={2}
                          onChange={(event) => updateAccessRule(index, { description: event.target.value })}
                        />
                      </label>
                      <div className="ip-access-rule-card-grid">
                        <label>
                          <span>{t('logs.action')}</span>
                          <Select value={rule.action || 'allow'} onValueChange={(value) => updateAccessRule(index, { action: value })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="allow">{t('ip.allow')}</SelectItem>
                              <SelectItem value="block">{t('ip.block')}</SelectItem>
                              <SelectItem value="monitor">{t('common.monitor')}</SelectItem>
                            </SelectContent>
                          </Select>
                        </label>
                        <AccessRuleScopeEditor compact rule={rule} sites={sites} t={t} onChange={(patch) => updateAccessRule(index, patch)} />
                        <label className="ip-access-rule-card-entries">
                          <span>{t('ip.entriesInput')}</span>
                          <Input value={(rule.entries || []).join(', ')} onChange={(event) => updateAccessRule(index, { entries: splitList(event.target.value) })} />
                        </label>
                        <label className="switch-line ip-access-rule-card-enabled">
                          <span>{t('rules.enabled')}</span>
                          <Switch checked={rule.enabled} onCheckedChange={(value) => updateAccessRule(index, { enabled: value })} />
                        </label>
                      </div>
                      <small className="ip-access-rule-card-scope">{scopeLabel(rule, t)}</small>
                      <div className="ip-access-rule-card-actions">
                        <Button size="sm" variant="outline" loading={accessRulesMutation.isPending} onClick={() => saveEditedAccessRule(index)}>{t('common.save')}</Button>
                        <Button size="sm" variant="destructive" onClick={() => removeAccessRule(rule.id)}><Trash2 size={14} />{t('common.delete')}</Button>
                      </div>
                    </article>
                  ))}
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="providers">
            <div className="system-section">
              <div className="system-section-title">
                <h2><CloudDownload size={16} /> {t('ip.providers')}</h2>
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="outline" onClick={addProvider}><Plus size={15} />{t('common.add')}</Button>
                  <Button variant="outline" onClick={() => syncMutation.mutate(undefined)} loading={syncMutation.isPending}>{t('ip.syncAll')}</Button>
                  <Button loading={providersMutation.isPending} onClick={() => providersMutation.mutate(providers.map(normalizeProviderForSave))}>{t('common.save')}</Button>
                </div>
              </div>
              <div className="provider-list">
                {providers.map((provider, index) => {
                  const status = providerStatuses[provider.id];
                  return (
                    <article className="provider-card" key={provider.id}>
                      <div className="provider-card-head">
                        <Switch checked={provider.enabled} onCheckedChange={(enabled) => updateProvider(index, { enabled })} />
                        <div>
                          <strong>{provider.name || t('ip.providerName')}</strong>
                          <span>{provider.endpoint || t('ip.providerEndpointEmpty')}</span>
                        </div>
                        <div className="provider-actions">
                          <Button size="sm" variant="outline" loading={providerTestMutation.isPending} onClick={() => providerTestMutation.mutate(normalizeProviderForSave(provider))}>{t('system.test')}</Button>
                          <Button size="sm" variant="outline" loading={syncMutation.isPending} onClick={() => syncMutation.mutate(provider.id)}>{t('ip.sync')}</Button>
                          <Button size="sm" variant="destructive" onClick={() => removeProvider(provider.id)}><Trash2 size={14} />{t('common.delete')}</Button>
                        </div>
                      </div>
                      {status && <IntelStatusPanel status={status} t={t} />}
                      <div className="provider-field-grid">
                        <label>
                          <span>{t('ip.providerName')}</span>
                          <Input value={provider.name} placeholder={t('ip.providerName')} onChange={(event) => updateProvider(index, { name: event.target.value })} />
                        </label>
                        <label>
                          <span>{t('ip.providerType')}</span>
                          <Select value={provider.type} onValueChange={(type) => applyProviderTemplate(index, type)}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              {providerTemplates.map((template) => (
                                <SelectItem key={template.type} value={template.type}>{t(template.nameKey)}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <small>{t(providerTemplateFor(provider.type).hintKey)}</small>
                        </label>
                        <label>
                          <span>{t('ip.format')}</span>
                          <Select value={provider.format || 'stix'} onValueChange={(format) => updateProvider(index, { format })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              {formatOptions.map((format) => <SelectItem key={format} value={format}>{formatLabel(format)}</SelectItem>)}
                            </SelectContent>
                          </Select>
                          <small>{t('ip.formatHint')}</small>
                        </label>
                        <label>
                          <span>{t('logs.action')}</span>
                          <Select value={normalizeProviderAction(provider.action)} onValueChange={(action) => updateProvider(index, { action })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="challenge">{displayAction('challenge', t)}</SelectItem>
                              <SelectItem value="block">{displayAction('block', t)}</SelectItem>
                              <SelectItem value="log">{displayAction('log', t)}</SelectItem>
                            </SelectContent>
                          </Select>
                          <small>{t('ip.providerActionHint')}</small>
                        </label>
                        <label className="provider-endpoint-field">
                          <span>{t('ip.endpoint')}</span>
                          <Input value={provider.endpoint} placeholder="https://..." onChange={(event) => updateProvider(index, { endpoint: event.target.value })} />
                          <small>{t('ip.endpointHint')}</small>
                        </label>
                        <label>
                          <span>{t('ip.providerAuth')}</span>
                          <Select value={provider.auth_type || 'bearer'} onValueChange={(auth_type) => updateProvider(index, { auth_type })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="bearer">{t('ip.authBearer')}</SelectItem>
                              <SelectItem value="header">{t('ip.authHeader')}</SelectItem>
                              <SelectItem value="query">{t('ip.authQuery')}</SelectItem>
                              <SelectItem value="basic">{t('ip.authBasic')}</SelectItem>
                              <SelectItem value="none">{t('ip.authNone')}</SelectItem>
                            </SelectContent>
                          </Select>
                          <small>{t('ip.authHint')}</small>
                        </label>
                        <label>
                          <span>{t('ip.apiKey')}</span>
                          <Input
                            type="password"
                            value={provider.api_key}
                            placeholder={provider.auth_type === 'basic' ? 'user:password' : t('ip.apiKey')}
                            disabled={provider.auth_type === 'none'}
                            onChange={(event) => updateProvider(index, { api_key: event.target.value })}
                          />
                          <small>{provider.auth_type === 'none' ? t('ip.authNoneHint') : t('ip.apiKeyPreserveHint')}</small>
                        </label>
                        <label className="provider-headers-field">
                          <span>{t('ip.providerHeaders')}</span>
                          <Textarea
                            value={headersToText(provider.headers)}
                            placeholder={t('ip.providerHeadersPlaceholder')}
                            rows={3}
                            onChange={(event) => updateProvider(index, { headers: textToHeaders(event.target.value) })}
                          />
                          <small>{t('ip.providerHeadersHint')}</small>
                        </label>
                        <label className="provider-interval-field">
                          <span>{t('ip.intervalValue')}</span>
                          <div className="duration-input-group">
                            <Input
                              type="number"
                              value={durationAmount(provider.interval)}
                              min={1}
                              max={intervalMax(provider.interval)}
                              onChange={(event) => updateProvider(index, { interval: secondsToDuration(Number(event.target.value || 1) * intervalUnitSeconds(intervalUnit(provider.interval))) })}
                            />
                            <Select
                              value={intervalUnit(provider.interval)}
                              onValueChange={(unit) => updateProvider(index, { interval: secondsToDuration(durationAmount(provider.interval) * intervalUnitSeconds(unit)) })}
                            >
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                <SelectItem value="minute">{t('common.minutes')}</SelectItem>
                                <SelectItem value="hour">{t('common.hours')}</SelectItem>
                                <SelectItem value="day">{t('common.days')}</SelectItem>
                                <SelectItem value="month">30 {t('common.days')}</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <small>{t('ip.intervalHint')}</small>
                        </label>
                        <label className="provider-notes-field">
                          <span>{t('ip.providerNotes')}</span>
                          <Textarea
                            value={provider.notes || ''}
                            placeholder={t('ip.providerNotesPlaceholder')}
                            rows={2}
                            onChange={(event) => updateProvider(index, { notes: event.target.value })}
                          />
                        </label>
                      </div>
                    </article>
                  );
                })}
                {!providers.length && <div className="empty-state">{t('ip.noProviders')}</div>}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="import">
            <div className="ip-intel-workspace">
              <section className="system-card ip-import-card">
                <div className="system-section-title">
                  <div>
                    <h2>{t('ip.import')}</h2>
                    <p>{t('ip.importHint')}</p>
                  </div>
                </div>
                <div className="ip-import-grid">
                  <label>
                    <span>{t('ip.format')}</span>
                    <Select value={importDraft.format} onValueChange={(format) => setImportDraft((current) => ({ ...current, format }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {formatOptions.map((format) => <SelectItem key={format} value={format}>{formatLabel(format)}</SelectItem>)}
                      </SelectContent>
                    </Select>
                    <small>{formatHelp(importDraft.format, t)}</small>
                  </label>
                  <label>
                    <span>{t('ip.source')}</span>
                    <Input value={importDraft.source} onChange={(event) => setImportDraft((current) => ({ ...current, source: event.target.value }))} />
                    <small>{t('ip.sourceHint')}</small>
                  </label>
                  <label>
                    <span>{t('rules.severity')}</span>
                    <Select value={importDraft.severity} onValueChange={(severity) => setImportDraft((current) => ({ ...current, severity }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">{t('rules.low')}</SelectItem>
                        <SelectItem value="medium">{t('rules.medium')}</SelectItem>
                        <SelectItem value="high">{t('rules.high')}</SelectItem>
                        <SelectItem value="critical">{t('rules.critical')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </label>
                  <label>
                    <span>{t('logs.action')}</span>
                    <Select value={importDraft.action} onValueChange={(action) => setImportDraft((current) => ({ ...current, action }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="challenge">{displayAction('challenge', t)}</SelectItem>
                        <SelectItem value="block">{displayAction('block', t)}</SelectItem>
                        <SelectItem value="monitor">{displayAction('monitor', t)}</SelectItem>
                        <SelectItem value="log">{displayAction('log', t)}</SelectItem>
                      </SelectContent>
                    </Select>
                  </label>
                  <label>
                    <span>{t('ip.confidence')}</span>
                    <Input
                      type="number"
                      value={importDraft.confidence * 100}
                      min={0}
                      max={100}
                      onChange={(event) => setImportDraft((current) => ({ ...current, confidence: Number(event.target.value || 0) / 100 }))}
                    />
                    <small>{t('ip.confidenceHint')}</small>
                  </label>
                  <label className="wide-field tag-token-field">
                    <span>{t('ip.labels')}</span>
                    <TagTokenInput
                      value={importDraft.labels}
                      onChange={(labels) => setImportDraft((current) => ({ ...current, labels }))}
                      placeholder={t('ip.labelPlaceholder')}
                    />
                  </label>
                  <label className="ioc-field">
                    <span>{t('ip.ioc')}</span>
                    <Textarea
                      value={importDraft.contents}
                      placeholder={t('ip.iocPlaceholder')}
                      rows={12}
                      onChange={(event) => setImportDraft((current) => ({ ...current, contents: event.target.value }))}
                    />
                    <small>{t('ip.iocHint')}</small>
                  </label>
                </div>
                <div className="form-action-row">
                  <Button
                    disabled={!importDraft.contents.trim()}
                    loading={importMutation.isPending}
                    onClick={runImport}
                  >
                    {t('ip.import')}
                  </Button>
                </div>
                {importStatus && <IntelStatusPanel status={importStatus} t={t} />}
              </section>
              <section className="system-card ip-lookup-card">
                <div className="system-section-title">
                  <div>
                    <h2>{t('ip.lookup')}</h2>
                    <p>{t('ip.lookupHint')}</p>
                  </div>
                </div>
                <div className="ip-lookup-grid">
                  <label>
                    <span>{t('ip.providerName')}</span>
                    <Select value={lookupDraft.providerId} onValueChange={(providerId) => setLookupDraft((current) => ({ ...current, providerId }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {providers.map((provider) => <SelectItem key={provider.id} value={provider.id}>{provider.name || provider.id}</SelectItem>)}
                      </SelectContent>
                    </Select>
                    <small>{providers.length ? t('ip.lookupProviderHint') : t('ip.noProviders')}</small>
                  </label>
                  <label>
                    <span>IP</span>
                    <Input value={lookupDraft.ip} placeholder="8.8.8.8" onChange={(event) => setLookupDraft((current) => ({ ...current, ip: event.target.value }))} />
                    <small>{t('ip.lookupIPHint')}</small>
                  </label>
                </div>
                <div className="form-action-row">
                  <Button disabled={!lookupDraft.providerId || !lookupDraft.ip} loading={lookupMutation.isPending} onClick={() => lookupMutation.mutate()}>
                    {t('ip.lookup')}
                  </Button>
                  <Button
                    variant="outline"
                    disabled={lookupItems.length === 0}
                    loading={adoptMutation.isPending}
                    onClick={() => adoptMutation.mutate()}
                  >
                    {t('ip.lookupAdopt')}
                  </Button>
                </div>
                {lookupStatus && <IntelStatusPanel status={lookupStatus} t={t} />}
                {syncStatus && <IntelStatusPanel status={syncStatus} t={t} compact />}
              </section>
            </div>
          </TabsContent>
        </Tabs>
      </section>

      <Dialog open={deleteRuleId !== null} onOpenChange={(open) => { if (!open) setDeleteRuleId(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('common.confirmDeleteTitle')}</DialogTitle>
            <DialogDescription>{t('common.confirmDeleteEntry')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteRuleId(null)}>{t('common.cancel')}</Button>
            <Button variant="destructive" onClick={confirmRemoveAccessRule}>{t('common.delete')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function IntelStatusPanel({
  status,
  compact = false,
  t,
}: {
  status: IntelOperationStatus;
  compact?: boolean;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  const items = (status.items || []).slice(0, compact ? 2 : 4);
  return (
    <div className={`intel-status intel-status-${status.tone}${compact ? ' intel-status-compact' : ''}`}>
      <div className="intel-status-main">
        <strong>{status.title}</strong>
        <span>{status.detail}</span>
      </div>
      <time>{status.at}</time>
      {items.length > 0 && (
        <div className="intel-status-items">
          {items.map((item, index) => (
            <code key={`${indicatorSummary(item)}-${index}`}>{indicatorSummary(item)}</code>
          ))}
          {(status.items?.length || 0) > items.length && <span>{t('ip.moreItems', { count: (status.items?.length || 0) - items.length })}</span>}
        </div>
      )}
    </div>
  );
}

function buildCountStatus({
  tone,
  title,
  countLabel,
  imported,
  total,
  items,
  t,
}: {
  tone: IntelStatusTone;
  title: string;
  countLabel: string;
  imported: number;
  total: number;
  items?: Array<Record<string, unknown>>;
  t: (key: string, options?: Record<string, unknown>) => string;
}): IntelOperationStatus {
  return {
    tone,
    title,
    detail: `${countLabel}: ${imported} / ${t('ip.totalItems')}: ${total}`,
    at: formatStatusTime(),
    items,
  };
}

function buildErrorStatus(title: string, detail: string): IntelOperationStatus {
  return {
    tone: 'error',
    title,
    detail,
    at: formatStatusTime(),
  };
}

function showStatusMessage(status: IntelOperationStatus) {
  if (status.tone === 'success') {
    toast.success(status.title);
    return;
  }
  if (status.tone === 'warning') {
    toast.warning(status.title);
    return;
  }
  toast.error(status.title);
}

function formatStatusTime() {
  return new Date().toLocaleString();
}

function indicatorSummary(item: Record<string, unknown>) {
  const value = stringField(item, ['value', 'ip', 'ip_address', 'ipAddress', 'address', 'cidr']) || 'item';
  const severity = stringField(item, ['severity', 'risk', 'threat_level', 'judgment', 'verdict']);
  const source = stringField(item, ['source', 'provider', 'origin']);
  const confidence = numberField(item, ['confidence', 'score', 'riskScore', 'threatScore', 'abuseConfidenceScore']);
  const parts = [value];
  if (severity) {
    parts.push(severity);
  }
  if (typeof confidence === 'number' && Number.isFinite(confidence)) {
    parts.push(formatConfidenceLabel(confidence));
  }
  if (source) {
    parts.push(source);
  }
  return parts.join(' · ');
}

function stringField(item: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

function numberField(item: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number') {
      return value;
    }
  }
  return undefined;
}

function formatConfidenceSuffix(value: unknown) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    return '';
  }
  return ` · ${formatConfidenceLabel(value)}`;
}

function formatConfidenceLabel(value: number) {
  const percent = value <= 1 ? value * 100 : value;
  return `${Math.round(Math.max(0, Math.min(100, percent)))}%`;
}


function IPEntryMobileCard({
  entry,
  tags,
  savingAccess,
  savingReputation,
  onTagsChange,
  onAllow,
  onBlock,
  onMonitor,
  onSaveReputation,
  onResetReputation,
  t,
}: {
  entry: IPReputationEntry;
  tags: string[];
  savingAccess: boolean;
  savingReputation: boolean;
  onTagsChange: (tags: string[]) => void;
  onAllow: () => void;
  onBlock: () => void;
  onMonitor: () => void;
  onSaveReputation: (score: number) => void;
  onResetReputation: () => void;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  const list = entry.list === 'whitelist' ? t('ip.whitelist') : entry.list === 'blacklist' ? t('ip.blacklist') : t('common.monitor');
  const stats = statsFor(entry);
  const intel = intelFor(entry);

  return (
    <article className="ip-entry-card">
      <header>
        <span className="table-identity">
          <Shield size={17} />
          <strong>{entry.ip}</strong>
        </span>
        <Badge variant={listBadgeVariant(entry.list)}>{list}</Badge>
      </header>
      <div className="ip-entry-card-grid">
        <div>
          <span>{t('ip.reputation')}</span>
          <ReputationOverrideEditor
            value={entry.reputation}
            override={entry.reputation_override}
            saving={savingReputation}
            onSave={onSaveReputation}
            onReset={onResetReputation}
          />
        </div>
        <div>
          <span>{t('ip.activity')}</span>
          <strong>{stats.blocked}/{stats.total}</strong>
        </div>
      </div>
      <div className="ip-entry-card-section">
        <span>{t('ip.tags')}</span>
        <EditableTagInput tags={tags} onChange={onTagsChange} />
      </div>
      <div className="ip-entry-card-section">
        <span>{t('ip.intel')}</span>
        <span className="intel-chip-list">
          {intel.length === 0 ? <span className="intel-chip intel-chip-muted">{t('common.monitor')}</span> : intel.map((item) => {
            const confidence = formatConfidenceSuffix(item.confidence);
            return (
              <span key={`${entry.ip}-${item.id || item.value}`} className={`intel-chip intel-chip-${intelColor(item.severity)}`}>
                <span>{item.source || displaySeverity(item.severity, t)}</span>
                <strong>{displayAction(item.action || 'challenge', t)}{confidence}</strong>
              </span>
            );
          })}
        </span>
      </div>
      <div className="ip-entry-card-actions">
        <Button size="sm" variant="outline" loading={savingAccess} onClick={onAllow}><CheckCircle2 size={14} />{t('ip.allow')}</Button>
        <Button size="sm" variant="destructive" loading={savingAccess} onClick={onBlock}><Ban size={14} />{t('ip.block')}</Button>
        <Button size="sm" variant="outline" loading={savingAccess} onClick={onMonitor}><RotateCcw size={14} />{t('common.monitor')}</Button>
      </div>
    </article>
  );
}

function EditableTagInput({ tags, onChange }: { tags: string[]; onChange: (tags: string[]) => void }) {
  const { t } = useTranslation();
  const tagText = tags.join('\n');
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(tags);

  useEffect(() => {
    setDraft(tags);
  }, [tagText, tags]);

  const commit = () => {
    onChange(draft);
    setOpen(false);
  };

  return (
    <div className="ip-tag-editor">
      <div className="ip-token-row">
        {tags.length > 0 ? tags.map((tag) => <span className="ip-token" key={tag}>{tag}</span>) : <span className="ip-token-muted">-</span>}
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <Button className="ip-tag-edit-btn" size="sm" variant="ghost" aria-label={t('common.edit')}>
              <Pencil size={12} />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64">
            <div className="ip-tag-popover space-y-2">
              <TagTokenInput value={draft} onChange={setDraft} placeholder={t('ip.labelPlaceholder')} />
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={() => setDraft(tags)}>{t('common.reset')}</Button>
                <Button size="sm" onClick={commit}>{t('common.save')}</Button>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}

function TagTokenInput({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState('');

  const addToken = (raw: string) => {
    const nextItems = splitList(raw.replace(/\n/g, ','));
    if (nextItems.length === 0) {
      return;
    }
    const existing = new Set(value.map((item) => item.toLowerCase()));
    const additions = nextItems.filter((item) => {
      const key = item.toLowerCase();
      if (existing.has(key)) {
        return false;
      }
      existing.add(key);
      return true;
    });
    if (additions.length > 0) {
      onChange([...value, ...additions]);
    }
    setDraft('');
  };

  const removeToken = (target: string) => {
    onChange(value.filter((item) => item !== target));
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' || event.key === ',') {
      event.preventDefault();
      addToken(draft);
      return;
    }
    if (event.key === 'Backspace' && draft.length === 0 && value.length > 0) {
      event.preventDefault();
      onChange(value.slice(0, -1));
    }
  };

  return (
    <div className="tag-token-input">
      {value.map((tag) => (
        <span className="ip-token tag-token-input-item" key={tag}>
          {tag}
          <button type="button" aria-label={t('ip.removeTag', { tag })} onClick={() => removeToken(tag)}>
            <X size={12} />
          </button>
        </span>
      ))}
      <Input
        className="h-8"
        value={draft}
        placeholder={value.length ? '' : placeholder}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={() => addToken(draft)}
        onKeyDown={handleKeyDown}
      />
    </div>
  );
}

function ReputationOverrideEditor({
  value,
  override,
  saving,
  onSave,
  onReset,
}: {
  value: number;
  override?: number;
  saving: boolean;
  onSave: (score: number) => void;
  onReset: () => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(override ?? value);

  useEffect(() => {
    setDraft(override ?? value);
  }, [override, value]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button className="ip-score-button" type="button">
          <Badge variant={reputationBadgeVariant(value)}>{value}</Badge>
          {override !== undefined && <span>{t('ip.manual')}</span>}
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-48">
        <div className="ip-score-popover space-y-2">
          <Input
            type="number"
            min={0}
            max={100}
            value={draft}
            onChange={(event) => setDraft(Number(event.target.value ?? value))}
          />
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={override === undefined} onClick={() => { onReset(); setOpen(false); }}>{t('common.reset')}</Button>
            <Button size="sm" loading={saving} onClick={() => { onSave(draft); setOpen(false); }}>{t('common.save')}</Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function AccessRuleScopeEditor({
  rule,
  sites,
  t,
  onChange,
  compact = false,
}: {
  rule: IPAccessRule;
  sites: Array<{ id: string; name?: string }>;
  t: (key: string) => string;
  onChange: (patch: Partial<IPAccessRule>) => void;
  compact?: boolean;
}) {
  const scope = rule.scope === 'directory' ? 'path' : rule.scope || 'global';
  return (
    <div className={compact ? 'ip-access-scope-fields ip-access-scope-fields-compact' : 'ip-access-scope-fields'}>
      <label>
        <span>{t('ip.scope')}</span>
        <Select value={scope} onValueChange={(value) => onChange(normalizeAccessScopePatch(rule, String(value || 'global')))}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="global">{t('ip.scopeGlobal')}</SelectItem>
            <SelectItem value="site">{t('ip.scopeSite')}</SelectItem>
            <SelectItem value="path">{t('ip.scopePath')}</SelectItem>
          </SelectContent>
        </Select>
        <small>{scopeLabel(rule, t)}</small>
      </label>
      <label>
        <span>{t('sites.title')}</span>
        <Select
          disabled={scope === 'global'}
          value={rule.site_id || undefined}
          onValueChange={(site_id) => onChange({ site_id: String(site_id || '') })}
        >
          <SelectTrigger><SelectValue placeholder={t('ip.optionalSite')} /></SelectTrigger>
          <SelectContent>
            {sites.map((site) => <SelectItem key={site.id} value={site.id}>{site.name || site.id}</SelectItem>)}
          </SelectContent>
        </Select>
        <small>{scope === 'global' ? t('ip.globalScopeHint') : scope === 'site' ? t('ip.siteScopeHint') : t('ip.pathScopeSiteHint')}</small>
      </label>
      <label>
        <span>{t('ip.pathPrefix')}</span>
        <Input
          disabled={scope !== 'path'}
          value={rule.path_prefix || ''}
          placeholder="/admin"
          onChange={(event) => onChange({ path_prefix: event.target.value })}
        />
        <small>{scope === 'path' ? t('ip.pathScopeHint') : t('ip.pathDisabledHint')}</small>
      </label>
    </div>
  );
}

function splitList(value: string) {
  return value.split(/[\n,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean);
}

function headersToText(headers: Record<string, string> | undefined) {
  return Object.entries(headers ?? {})
    .map(([key, value]) => (value ? `${key}: ${value}` : key))
    .join('\n');
}

function textToHeaders(value: string) {
  return value.split(/\r?\n/).reduce<Record<string, string>>((headers, line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return headers;
    }
    const separator = trimmed.indexOf(':');
    const key = separator >= 0 ? trimmed.slice(0, separator) : trimmed;
    const rawValue = separator >= 0 ? trimmed.slice(separator + 1) : '';
    const header = key.trim();
    if (header) {
      headers[header] = rawValue.trim();
    }
    return headers;
  }, {});
}

function normalizeProviderAction(action: string | undefined) {
  switch ((action || '').trim().toLowerCase()) {
    case 'block':
    case 'challenge':
    case 'log':
      return action!.trim().toLowerCase();
    default:
      return 'challenge';
  }
}

function normalizeProviderForSave(provider: ThreatIntelProvider): ThreatIntelProvider {
  return {
    ...provider,
    action: normalizeProviderAction(provider.action),
    headers: Object.fromEntries(
      Object.entries(provider.headers ?? {})
        .map(([key, value]) => [key.trim(), value.trim()] as const)
        .filter(([key]) => key),
    ),
  };
}

function splitLines(value: string) {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

function firstToken(value: string) {
  return value.split('#')[0].trim().split(/\s+/)[0] || '';
}

function providerTemplateFor(type: string) {
  return providerTemplates.find((item) => item.type === type) ?? providerTemplates[0];
}

function formatLabel(format: string) {
  switch (format) {
    case 'cidr':
      return 'CIDR/TXT';
    case 'misp':
      return 'MISP Attribute';
    case 'abuseipdb':
      return 'AbuseIPDB';
    case 'otx':
      return 'AlienVault OTX';
    case 'threatbook':
      return 'ThreatBook';
    default:
      return format.toUpperCase();
  }
}

function formatHelp(format: string, t: (key: string) => string) {
  switch (format) {
    case 'cidr':
      return t('ip.formatCIDRHint');
    case 'csv':
      return t('ip.formatCSVHint');
    case 'json':
      return t('ip.formatJSONHint');
    case 'stix':
      return t('ip.formatSTIXHint');
    case 'misp':
      return t('ip.formatMISPHint');
    case 'abuseipdb':
      return t('ip.formatAbuseIPDBHint');
    case 'otx':
      return t('ip.formatOTXHint');
    case 'threatbook':
      return t('ip.formatThreatBookHint');
    default:
      return t('ip.formatHint');
  }
}

function isValidIPOrCIDR(value: string) {
  const parts = value.split('/');
  if (parts.length > 2) {
    return false;
  }
  const address = parts[0];
  const isIPv4 = isValidIPv4(address);
  const isIPv6 = isLikelyIPv6(address);
  if (!isIPv4 && !isIPv6) {
    return false;
  }
  if (parts.length === 1) {
    return true;
  }
  if (!/^\d+$/.test(parts[1])) {
    return false;
  }
  const prefix = Number(parts[1]);
  return Number.isInteger(prefix) && prefix >= 0 && prefix <= (isIPv4 ? 32 : 128);
}

function isValidIPv4(value: string) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === String(Number(part));
  });
}

function isLikelyIPv6(value: string) {
  if (!value.includes(':') || !/^[0-9a-f:]+$/i.test(value)) {
    return false;
  }
  if ((value.match(/::/g) || []).length > 1) {
    return false;
  }
  const segments = value.split(':').filter(Boolean);
  if (segments.length > 8 || segments.some((segment) => segment.length > 4)) {
    return false;
  }
  return value.includes('::') ? segments.length < 8 : segments.length === 8;
}

function tagsFor(entry: IPReputationEntry, draftTags: Record<string, string[]>) {
  const tags = draftTags[entry.ip] ?? entry.tags;
  return Array.isArray(tags) ? tags : [];
}

function stableTagSnapshot(tags: Record<string, string[]>) {
  return JSON.stringify(
    Object.keys(tags)
      .sort()
      .map((ip) => [ip, [...(tags[ip] ?? [])].map((tag) => tag.trim()).filter(Boolean).sort()]),
  );
}

function intelFor(entry: IPReputationEntry) {
  return Array.isArray(entry.intel)
    ? entry.intel.map((item) => ({ ...item, labels: Array.isArray(item.labels) ? item.labels : [] }))
    : [];
}

function statsFor(entry: IPReputationEntry) {
  return {
    total: Number(entry.stats?.total ?? 0),
    blocked: Number(entry.stats?.blocked ?? 0),
  };
}

function durationSeconds(value: number | string | undefined) {
  if (typeof value === 'number') {
    return Math.max(0, Math.round(value / second));
  }
  const raw = String(value ?? '').trim();
  if (raw.endsWith('h')) {
    return Number(raw.slice(0, -1)) * 3600;
  }
  if (raw.endsWith('m')) {
    return Number(raw.slice(0, -1)) * 60;
  }
  if (raw.endsWith('s')) {
    return Number(raw.slice(0, -1));
  }
  return Number(raw) || 0;
}

function secondsToDuration(value: number) {
  return Math.max(1, value) * second;
}

function intervalUnit(value: number | string | undefined) {
  const seconds = durationSeconds(value);
  if (seconds >= 30 * 24 * 3600) {
    return 'month';
  }
  if (seconds >= 24 * 3600 && seconds % (24 * 3600) === 0) {
    return 'day';
  }
  if (seconds >= 3600 && seconds % 3600 === 0) {
    return 'hour';
  }
  return 'minute';
}

function intervalUnitSeconds(unit: string) {
  switch (unit) {
    case 'month':
      return 30 * 24 * 3600;
    case 'day':
      return 24 * 3600;
    case 'hour':
      return 3600;
    default:
      return 60;
  }
}

function durationAmount(value: number | string | undefined) {
  const seconds = Math.max(60, durationSeconds(value));
  return Math.max(1, Math.round(seconds / intervalUnitSeconds(intervalUnit(value))));
}

function intervalMax(value: number | string | undefined) {
  const unit = intervalUnit(value);
  if (unit === 'month') return 1;
  if (unit === 'day') return 30;
  if (unit === 'hour') return 720;
  return 43_200;
}


function intelColor(severity: string) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'red';
    case 'medium':
      return 'orange';
    default:
      return 'blue';
  }
}

function normalizeAccessRuleForSave(rule: IPAccessRule, fallbackName = 'IP access rule'): IPAccessRule {
  const scope = rule.scope === 'directory' ? 'path' : rule.scope || 'global';
  const pathPrefix = scope === 'path' ? normalizePathPrefix(rule.path_prefix) : '';
  return {
    ...rule,
    id: rule.id || `ip-rule-${Date.now()}`,
    name: rule.name || rule.id || fallbackName,
    description: rule.description || '',
    action: rule.action === 'block' ? 'block' : rule.action === 'monitor' ? 'monitor' : 'allow',
    scope,
    site_id: scope === 'global' ? '' : rule.site_id,
    path_prefix: pathPrefix,
    entries: rule.entries.map((entry) => entry.trim()).filter(Boolean),
    enabled: rule.enabled,
  };
}

function normalizeAccessScopePatch(rule: IPAccessRule, scope: string): Partial<IPAccessRule> {
  if (scope === 'global') {
    return { scope, site_id: '', path_prefix: '' };
  }
  if (scope === 'site') {
    return { scope, path_prefix: '' };
  }
  return { scope, site_id: rule.site_id || '', path_prefix: rule.path_prefix || '/' };
}

function normalizePathPrefix(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function safeRuleID(ip: string) {
  return ip.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase() || String(Date.now());
}

function scopeLabel(rule: IPAccessRule, t: (key: string) => string) {
  const scope = rule.scope === 'directory' ? 'path' : rule.scope;
  if (scope === 'site') {
    return `${t('ip.scopeSite')} · ${rule.site_id || '-'}`;
  }
  if (scope === 'path') {
    const site = rule.site_id ? `${rule.site_id} · ` : '';
    return `${t('ip.scopePath')} · ${site}${rule.path_prefix || '/'}`;
  }
  return t('ip.scopeGlobal');
}

function badgeVariantFromColor(color: string | undefined): 'default' | 'secondary' | 'destructive' | 'success' | 'warning' | 'outline' {
  switch (String(color ?? '')) {
    case 'red':
      return 'destructive';
    case 'green':
      return 'success';
    case 'orange':
      return 'warning';
    case 'blue':
      return 'default';
    default:
      return 'secondary';
  }
}

function listBadgeVariant(list: string): 'success' | 'destructive' | 'default' {
  if (list === 'whitelist') return 'success';
  if (list === 'blacklist') return 'destructive';
  return 'default';
}

function reputationBadgeVariant(value: number): 'success' | 'warning' | 'destructive' {
  if (value >= 80) return 'success';
  if (value >= 50) return 'warning';
  return 'destructive';
}
