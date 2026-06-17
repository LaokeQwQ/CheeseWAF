import { type KeyboardEvent, useEffect, useMemo, useState } from 'react';
import { Button, Input, InputNumber, Message as ArcoMessage, Popover, Select, Space, Switch, Table, Tabs, Tag } from '@arco-design/web-react';
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
  syncThreatIntel,
  testThreatIntelProvider,
  updateIPAccessRules,
  updateIPReputationOverrides,
  updateIPTags,
  updateThreatIntelProviders,
} from '../../api/client';
import type { IPAccessRule, IPReputationEntry, ThreatIntelProvider } from '../../types/api';
import { displayAction, displaySeverity } from '../../utils/display';

const second = 1_000_000_000;
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
  const [providerStatuses, setProviderStatuses] = useState<Record<string, IntelOperationStatus>>({});
  const [importStatus, setImportStatus] = useState<IntelOperationStatus | null>(null);
  const [syncStatus, setSyncStatus] = useState<IntelOperationStatus | null>(null);
  const [lookupStatus, setLookupStatus] = useState<IntelOperationStatus | null>(null);
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
    if (data?.tags) {
      setDraftTags(data.tags);
    }
    if (data?.access_rules) {
      setAccessRules(data.access_rules);
    }
    if (data?.reputation_overrides) {
      setReputationOverrides(data.reputation_overrides);
    }
    if (data?.providers) {
      setProviders(data.providers);
      if (!lookupDraft.providerId && data.providers.length > 0) {
        setLookupDraft((current) => ({ ...current, providerId: data.providers[0].id }));
      }
    }
  }, [data?.access_rules, data?.providers, data?.reputation_overrides, data?.tags, lookupDraft.providerId]);

  const tagMutation = useMutation({
    mutationFn: updateIPTags,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ip-rules'] }),
  });
  const accessRulesMutation = useMutation({
    mutationFn: updateIPAccessRules,
    onSuccess: (saved) => {
      setAccessRules(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      ArcoMessage.success(t('ip.accessRulesSaved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const reputationMutation = useMutation({
    mutationFn: updateIPReputationOverrides,
    onSuccess: (saved) => {
      setReputationOverrides(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      ArcoMessage.success(t('ip.reputationSaved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const providersMutation = useMutation({
    mutationFn: updateThreatIntelProviders,
    onSuccess: (saved) => {
      setProviders(saved);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
      ArcoMessage.success(t('ip.providersSaved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
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
      ArcoMessage.error(error.message);
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
      ArcoMessage.error(error.message);
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
      ArcoMessage.error(error.message);
    },
  });
  const lookupMutation = useMutation({
    mutationFn: () => lookupThreatIntel(lookupDraft.providerId, lookupDraft.ip),
    onSuccess: (result) => {
      const status = buildCountStatus({
        tone: result.imported > 0 ? 'success' : 'warning',
        title: result.imported > 0 ? t('ip.lookupApplied') : t('ip.lookupClean'),
        countLabel: t('ip.lookupImported'),
        imported: result.imported,
        total: result.items.length,
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
      setProviderStatuses((current) => ({ ...current, [lookupDraft.providerId]: status }));
      ArcoMessage.error(error.message);
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

  const updateProvider = (index: number, patch: Partial<ThreatIntelProvider>) => {
    setProviders((current) => current.map((provider, providerIndex) => (providerIndex === index ? { ...provider, ...patch } : provider)));
  };
  const removeProvider = (id: string) => {
    setProviders((current) => current.filter((provider) => provider.id !== id));
  };
  const addProvider = () => {
    setProviders((current) => [
      ...current,
      {
        id: `provider-${Date.now()}`,
        name: '',
        type: 'generic',
        endpoint: '',
        api_key: '',
        auth_type: 'bearer',
        format: 'stix',
        action: 'challenge',
        min_severity: 'high',
        interval: 24 * 60 * 60 * second,
        headers: {},
        notes: '',
        enabled: true,
      },
    ]);
  };
  const saveAccessRules = (nextRules = accessRules) => {
    accessRulesMutation.mutate(nextRules.map(normalizeAccessRuleForSave).filter((rule) => rule.entries.length > 0));
  };
  const addAccessRule = () => {
    const entries = accessDraft.entries.length > 0 ? accessDraft.entries : splitList(accessDraft.entries.join(','));
    if (entries.length === 0) {
      ArcoMessage.warning(t('ip.entriesRequired'));
      return;
    }
    const invalidEntries = entries.filter((entry) => !isValidIPOrCIDR(entry));
    if (invalidEntries.length > 0) {
      ArcoMessage.warning(t('ip.entriesInvalid', { value: invalidEntries.slice(0, 3).join(', ') }));
      return;
    }
    if (accessDraft.scope === 'site' && !accessDraft.site_id) {
      ArcoMessage.warning(t('ip.siteRequired'));
      return;
    }
    if (accessDraft.scope === 'path' && !accessDraft.path_prefix.trim()) {
      ArcoMessage.warning(t('ip.pathRequired'));
      return;
    }
    const nextRule = normalizeAccessRuleForSave({
      ...accessDraft,
      id: accessDraft.id || `ip-rule-${Date.now()}`,
      name: accessDraft.name || entries[0],
      entries,
    });
    const nextRules = [...accessRules, nextRule];
    setAccessRules(nextRules);
    setAccessDraft(defaultAccessDraft);
    saveAccessRules(nextRules);
  };
  const removeAccessRule = (id: string) => {
    const nextRules = accessRules.filter((rule) => rule.id !== id);
    setAccessRules(nextRules);
    saveAccessRules(nextRules);
  };
  const updateAccessRule = (index: number, patch: Partial<IPAccessRule>) => {
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
    setAccessRules(nextRules);
    saveAccessRules(nextRules);
  };
  const saveReputationOverride = (ip: string, score: number) => {
    reputationMutation.mutate({ ...reputationOverrides, [ip]: Math.max(0, Math.min(100, Math.round(score))) });
  };
  const resetReputationOverride = (ip: string) => {
    const next = { ...reputationOverrides };
    delete next[ip];
    reputationMutation.mutate(next);
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
                <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('csv')}>{t('ip.exportCsv')}</Button>
                <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('stix')}>{t('ip.exportStix')}</Button>
              </>
            )}
            {activeTab === 'entries' && tagsChanged && (
              <Button type="primary" icon={<Tags size={16} />} loading={tagMutation.isPending} onClick={() => tagMutation.mutate(draftTags)}>
                {t('ip.saveTags')}
              </Button>
            )}
          </span>
        ) : null}
      </header>

      <section className="panel ip-manage-panel">
        <Tabs
          activeTab={activeTab}
          onChange={(tab) => {
            const next = new URLSearchParams(routeParams);
            if (tab === 'entries') {
              next.delete('tab');
            } else {
              next.set('tab', tab === 'providers' ? 'intel' : tab);
            }
            setRouteParams(next, { replace: true });
          }}
        >
          <Tabs.TabPane key="entries" title={t('ip.entries')}>
            <div className="toolbar-row toolbar-row-compact ip-toolbar">
              <Input className="toolbar-search" prefix={<Search size={16} />} value={search} placeholder={t('common.search')} allowClear onChange={setSearch} />
            </div>
            <div className="table-panel table-panel-embedded ip-entries-table">
              <Table
                rowKey="ip"
                pagination={{ pageSize: 10 }}
                loading={isLoading}
                data={filtered}
                columns={[
                  {
                    title: 'IP',
                    dataIndex: 'ip',
                    render: (ip: string) => (
                      <span className="table-identity">
                        <Shield size={17} />
                        {ip}
                      </span>
                    ),
                  },
                  {
                    title: t('ip.list'),
                    dataIndex: 'list',
                    render: (list: string) => {
                      const label = list === 'whitelist' ? t('ip.whitelist') : list === 'blacklist' ? t('ip.blacklist') : t('common.monitor');
                      const color = list === 'whitelist' ? 'green' : list === 'blacklist' ? 'red' : 'blue';
                      return <Tag color={color}>{label}</Tag>;
                    },
                  },
                  {
                    title: t('ip.reputation'),
                    dataIndex: 'reputation',
                    render: (value: number, record: IPReputationEntry) => (
                      <ReputationOverrideEditor
                        value={value}
                        override={record.reputation_override}
                        saving={reputationMutation.isPending}
                        onSave={(score) => saveReputationOverride(record.ip, score)}
                        onReset={() => resetReputationOverride(record.ip)}
                      />
                    ),
                  },
                  {
                    title: t('ip.tags'),
                    dataIndex: 'tags',
                    render: (_: string[], record: IPReputationEntry) => (
                      <EditableTagInput
                        tags={tagsFor(record, draftTags)}
                        onChange={(tags) => setDraftTags((current) => ({ ...current, [record.ip]: tags }))}
                      />
                    ),
                  },
                  {
                    title: t('ip.intel'),
                    dataIndex: 'intel',
                    render: (_: unknown, record: IPReputationEntry) => (
                      <span className="intel-chip-list">
                        {intelFor(record).length === 0 ? <span className="intel-chip intel-chip-muted">{t('common.monitor')}</span> : intelFor(record).map((item) => {
                          const confidence = formatConfidenceSuffix(item.confidence);
                          return (
                            <span key={`${record.ip}-${item.id || item.value}`} className={`intel-chip intel-chip-${intelColor(item.severity)}`}>
                              <span>{item.source || displaySeverity(item.severity, t)}</span>
                              <strong>{displayAction(item.action || 'challenge', t)}{confidence}</strong>
                            </span>
                          );
                        })}
                      </span>
                    ),
                  },
                  {
                    title: t('ip.activity'),
                    dataIndex: 'stats',
                    render: (_: unknown, record: IPReputationEntry) => {
                      const stats = statsFor(record);
                      return `${stats.blocked}/${stats.total}`;
                    },
                  },
                  {
                    title: t('ip.actions'),
                    dataIndex: 'actions',
                    render: (_: unknown, record: IPReputationEntry) => (
                      <Space className="ip-row-actions" wrap size={6}>
                        <Button size="mini" icon={<CheckCircle2 size={13} />} loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'allow')}>
                          {t('ip.allow')}
                        </Button>
                        <Button size="mini" status="danger" icon={<Ban size={13} />} loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'block')}>
                          {t('ip.block')}
                        </Button>
                        <Button size="mini" icon={<RotateCcw size={13} />} loading={accessRulesMutation.isPending} onClick={() => applyIPDisposition(record.ip, 'monitor')}>
                          {t('common.monitor')}
                        </Button>
                      </Space>
                    ),
                  },
                ]}
              />
            </div>
            <div className="ip-entry-card-list">
              {isLoading && <div className="empty-state">{t('common.loading')}</div>}
              {!isLoading && filtered.length === 0 && <div className="empty-state">{t('common.noData')}</div>}
              {!isLoading && filtered.map((entry) => (
                <IPEntryMobileCard
                  key={entry.ip}
                  entry={entry}
                  tags={tagsFor(entry, draftTags)}
                  savingAccess={accessRulesMutation.isPending}
                  savingReputation={reputationMutation.isPending}
                  onTagsChange={(tags) => setDraftTags((current) => ({ ...current, [entry.ip]: tags }))}
                  onAllow={() => applyIPDisposition(entry.ip, 'allow')}
                  onBlock={() => applyIPDisposition(entry.ip, 'block')}
                  onMonitor={() => applyIPDisposition(entry.ip, 'monitor')}
                  onSaveReputation={(score) => saveReputationOverride(entry.ip, score)}
                  onResetReputation={() => resetReputationOverride(entry.ip)}
                  t={t}
                />
              ))}
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="access" title={t('ip.accessRules')}>
            <div className="ip-access-workspace">
              <section className="ip-access-editor">
                <div className="system-section-title">
                  <h2><ListPlus size={16} /> {t('ip.accessRules')}</h2>
                  <Button type="primary" loading={accessRulesMutation.isPending} onClick={() => saveAccessRules()}>{t('common.save')}</Button>
                </div>
                <div className="ip-access-draft-grid">
                  <label className="ip-access-rule-name-field">
                    <span>{t('rules.name')}</span>
                    <Input value={accessDraft.name} placeholder={t('ip.ruleNamePlaceholder')} onChange={(name) => setAccessDraft((current) => ({ ...current, name }))} />
                  </label>
                  <label>
                    <span>{t('logs.action')}</span>
                    <Select value={accessDraft.action} onChange={(action) => setAccessDraft((current) => ({ ...current, action: action as string }))}>
                      <Select.Option value="allow">{t('ip.allow')}</Select.Option>
                      <Select.Option value="block">{t('ip.block')}</Select.Option>
                      <Select.Option value="monitor">{t('common.monitor')}</Select.Option>
                    </Select>
                  </label>
                  <label>
                    <span>{t('ip.scope')}</span>
                    <Select value={accessDraft.scope} onChange={(scope) => setAccessDraft((current) => ({ ...current, scope: scope as string }))}>
                      <Select.Option value="global">{t('ip.scopeGlobal')}</Select.Option>
                      <Select.Option value="site">{t('ip.scopeSite')}</Select.Option>
                      <Select.Option value="path">{t('ip.scopePath')}</Select.Option>
                    </Select>
                  </label>
                  <label className="ip-access-site-field">
                    <span>{t('sites.title')}</span>
                    <Select
                      allowClear
                      disabled={accessDraft.scope === 'global'}
                      value={accessDraft.site_id || undefined}
                      placeholder={t('ip.optionalSite')}
                      onChange={(site_id) => setAccessDraft((current) => ({ ...current, site_id: String(site_id || '') }))}
                    >
                      {sites.map((site) => <Select.Option key={site.id} value={site.id}>{site.name || site.id}</Select.Option>)}
                    </Select>
                    <small>{accessDraft.scope === 'global' ? t('ip.globalScopeHint') : accessDraft.scope === 'site' ? t('ip.siteScopeHint') : t('ip.pathScopeSiteHint')}</small>
                  </label>
                  <label className="ip-access-path-field">
                    <span>{t('ip.pathPrefix')}</span>
                    <Input
                      disabled={accessDraft.scope !== 'path'}
                      value={accessDraft.path_prefix}
                      placeholder="/admin"
                      onChange={(path_prefix) => setAccessDraft((current) => ({ ...current, path_prefix }))}
                    />
                    <small>{accessDraft.scope === 'path' ? t('ip.pathScopeHint') : t('ip.pathDisabledHint')}</small>
                  </label>
                  <label className="ip-access-entries-field">
                    <span>{t('ip.entriesInput')}</span>
                    <Input value={accessDraft.entries.join(', ')} placeholder="203.0.113.10, 198.51.100.0/24" onChange={(value) => setAccessDraft((current) => ({ ...current, entries: splitList(value) }))} />
                  </label>
                  <div className="ip-access-draft-actions">
                    <label className="switch-line ip-access-enabled"><span>{t('rules.enabled')}</span><Switch checked={accessDraft.enabled} onChange={(enabled) => setAccessDraft((current) => ({ ...current, enabled }))} /></label>
                    <Button className="ip-access-add-button" type="primary" icon={<Plus size={15} />} onClick={addAccessRule}>{t('ip.addRule')}</Button>
                  </div>
                </div>
              </section>
              <div className="table-panel table-panel-embedded ip-access-table">
                <Table
                  rowKey="id"
                  pagination={false}
                  data={accessRules}
                  columns={[
                    { title: t('rules.name'), dataIndex: 'name', render: (_: string, rule: IPAccessRule) => <strong>{rule.name || rule.id}</strong> },
                    { title: t('logs.action'), dataIndex: 'action', render: (action: string) => <Tag color={action === 'allow' ? 'green' : action === 'block' ? 'red' : 'blue'}>{action === 'allow' ? t('ip.allow') : action === 'block' ? t('ip.block') : t('common.monitor')}</Tag> },
                    { title: t('ip.scope'), dataIndex: 'scope', render: (_: string, rule: IPAccessRule) => scopeLabel(rule, t) },
                    { title: t('ip.entriesInput'), dataIndex: 'entries', render: (entries: string[]) => <span className="ip-access-entry-list">{entries.map((entry) => <code key={entry}>{entry}</code>)}</span> },
                    { title: t('rules.enabled'), dataIndex: 'enabled', render: (enabled: boolean, rule: IPAccessRule, index: number) => <Switch checked={enabled} onChange={(value) => updateAccessRule(index, { enabled: value })} /> },
                    {
                      title: t('ip.actions'),
                      dataIndex: 'actions',
                      render: (_: unknown, rule: IPAccessRule) => (
                        <Button size="small" status="danger" icon={<Trash2 size={14} />} onClick={() => removeAccessRule(rule.id)}>
                          {t('common.delete')}
                        </Button>
                      ),
                    },
                  ]}
                />
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="providers" title={t('ip.providers')}>
            <div className="system-section">
              <div className="system-section-title">
                <h2><CloudDownload size={16} /> {t('ip.providers')}</h2>
                <Space wrap>
                  <Button icon={<Plus size={15} />} onClick={addProvider}>{t('common.add')}</Button>
                  <Button onClick={() => syncMutation.mutate(undefined)} loading={syncMutation.isPending}>{t('ip.syncAll')}</Button>
                  <Button type="primary" loading={providersMutation.isPending} onClick={() => providersMutation.mutate(providers)}>{t('common.save')}</Button>
                </Space>
              </div>
              <div className="provider-list">
                {providers.map((provider, index) => {
                  const status = providerStatuses[provider.id];
                  return (
                    <article className="provider-card" key={provider.id}>
                      <div className="provider-card-head">
                        <Switch checked={provider.enabled} onChange={(enabled) => updateProvider(index, { enabled })} />
                        <div>
                          <strong>{provider.name || t('ip.providerName')}</strong>
                          <span>{provider.endpoint || t('ip.providerEndpointEmpty')}</span>
                        </div>
                        <div className="provider-actions">
                          <Button size="small" loading={providerTestMutation.isPending} onClick={() => providerTestMutation.mutate(provider)}>{t('system.test')}</Button>
                          <Button size="small" loading={syncMutation.isPending} onClick={() => syncMutation.mutate(provider.id)}>{t('ip.sync')}</Button>
                          <Button size="small" status="danger" icon={<Trash2 size={14} />} onClick={() => removeProvider(provider.id)}>
                            {t('common.delete')}
                          </Button>
                        </div>
                      </div>
                      {status && <IntelStatusPanel status={status} t={t} />}
                      <div className="provider-field-grid">
                        <label>
                          <span>{t('ip.providerName')}</span>
                          <Input value={provider.name} placeholder={t('ip.providerName')} onChange={(name) => updateProvider(index, { name })} />
                        </label>
                        <label>
                          <span>{t('ip.providerType')}</span>
                          <Select value={provider.type} onChange={(type) => updateProvider(index, { type: type as string })}>
                            <Select.Option value="generic">{t('ip.providerTypeGeneric')}</Select.Option>
                            <Select.Option value="threatbook-cn">{t('ip.providerTypeThreatBookCN')}</Select.Option>
                            <Select.Option value="threatbook-intl">{t('ip.providerTypeThreatBookIntl')}</Select.Option>
                            <Select.Option value="abuseipdb">{t('ip.providerTypeAbuseIPDB')}</Select.Option>
                            <Select.Option value="otx">{t('ip.providerTypeOTX')}</Select.Option>
                            <Select.Option value="misp">{t('ip.providerTypeMISP')}</Select.Option>
                            <Select.Option value="stix">{t('ip.providerTypeSTIX')}</Select.Option>
                          </Select>
                        </label>
                        <label>
                          <span>{t('ip.format')}</span>
                          <Select value={provider.format || 'stix'} onChange={(format) => updateProvider(index, { format: format as string })}>
                            <Select.Option value="cidr">CIDR/TXT</Select.Option>
                            <Select.Option value="csv">CSV</Select.Option>
                            <Select.Option value="json">JSON</Select.Option>
                            <Select.Option value="stix">STIX</Select.Option>
                            <Select.Option value="misp">MISP Attribute</Select.Option>
                            <Select.Option value="abuseipdb">AbuseIPDB</Select.Option>
                            <Select.Option value="otx">AlienVault OTX</Select.Option>
                            <Select.Option value="threatbook">ThreatBook</Select.Option>
                          </Select>
                        </label>
                        <label>
                          <span>{t('logs.action')}</span>
                          <Select value={provider.action || 'challenge'} onChange={(action) => updateProvider(index, { action: action as string })}>
                            <Select.Option value="challenge">{displayAction('challenge', t)}</Select.Option>
                            <Select.Option value="block">{displayAction('block', t)}</Select.Option>
                            <Select.Option value="monitor">{displayAction('monitor', t)}</Select.Option>
                            <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                          </Select>
                        </label>
                        <label className="provider-endpoint-field">
                          <span>{t('ip.endpoint')}</span>
                          <Input value={provider.endpoint} placeholder="https://..." onChange={(endpoint) => updateProvider(index, { endpoint })} />
                        </label>
                        <label>
                          <span>{t('ip.providerAuth')}</span>
                          <Select value={provider.auth_type || 'bearer'} onChange={(auth_type) => updateProvider(index, { auth_type: auth_type as string })}>
                            <Select.Option value="bearer">{t('ip.authBearer')}</Select.Option>
                            <Select.Option value="header">{t('ip.authHeader')}</Select.Option>
                            <Select.Option value="query">{t('ip.authQuery')}</Select.Option>
                            <Select.Option value="basic">{t('ip.authBasic')}</Select.Option>
                            <Select.Option value="none">{t('ip.authNone')}</Select.Option>
                          </Select>
                        </label>
                        <label>
                          <span>API Key</span>
                          <Input.Password
                            value={provider.api_key}
                            placeholder={provider.auth_type === 'basic' ? 'user:password' : 'API Key'}
                            disabled={provider.auth_type === 'none'}
                            onChange={(api_key) => updateProvider(index, { api_key })}
                          />
                        </label>
                        <label className="provider-interval-field">
                          <span>{t('ip.intervalValue')}</span>
                          <div className="duration-input-group">
                            <InputNumber
                              value={durationAmount(provider.interval)}
                              min={1}
                              max={intervalMax(provider.interval)}
                              precision={0}
                              onChange={(value) => updateProvider(index, { interval: secondsToDuration(Number(value || 1) * intervalUnitSeconds(intervalUnit(provider.interval))) })}
                            />
                            <Select
                              value={intervalUnit(provider.interval)}
                              onChange={(unit) => updateProvider(index, { interval: secondsToDuration(durationAmount(provider.interval) * intervalUnitSeconds(unit as string)) })}
                            >
                              <Select.Option value="minute">{t('common.minutes')}</Select.Option>
                              <Select.Option value="hour">{t('common.hours')}</Select.Option>
                              <Select.Option value="day">{t('common.days')}</Select.Option>
                              <Select.Option value="month">30 {t('common.days')}</Select.Option>
                            </Select>
                          </div>
                        </label>
                        <label className="provider-notes-field">
                          <span>{t('ip.providerNotes')}</span>
                          <Input.TextArea
                            value={provider.notes || ''}
                            placeholder={t('ip.providerNotesPlaceholder')}
                            autoSize={{ minRows: 2, maxRows: 4 }}
                            onChange={(notes) => updateProvider(index, { notes })}
                          />
                        </label>
                      </div>
                    </article>
                  );
                })}
                {!providers.length && <div className="empty-state">{t('ip.noProviders')}</div>}
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="import" title={t('ip.import')}>
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
                    <Select value={importDraft.format} onChange={(format) => setImportDraft((current) => ({ ...current, format: format as string }))}>
                      <Select.Option value="cidr">CIDR/TXT</Select.Option>
                      <Select.Option value="csv">CSV</Select.Option>
                      <Select.Option value="json">JSON</Select.Option>
                      <Select.Option value="stix">STIX</Select.Option>
                      <Select.Option value="misp">MISP Attribute</Select.Option>
                      <Select.Option value="abuseipdb">AbuseIPDB</Select.Option>
                      <Select.Option value="otx">AlienVault OTX</Select.Option>
                      <Select.Option value="threatbook">ThreatBook</Select.Option>
                    </Select>
                  </label>
                  <label><span>{t('ip.source')}</span><Input value={importDraft.source} onChange={(source) => setImportDraft((current) => ({ ...current, source }))} /></label>
                  <label>
                    <span>{t('rules.severity')}</span>
                    <Select value={importDraft.severity} onChange={(severity) => setImportDraft((current) => ({ ...current, severity: severity as string }))}>
                      <Select.Option value="low">{t('rules.low')}</Select.Option>
                      <Select.Option value="medium">{t('rules.medium')}</Select.Option>
                      <Select.Option value="high">{t('rules.high')}</Select.Option>
                      <Select.Option value="critical">{t('rules.critical')}</Select.Option>
                    </Select>
                  </label>
                  <label>
                    <span>{t('logs.action')}</span>
                    <Select value={importDraft.action} onChange={(action) => setImportDraft((current) => ({ ...current, action: action as string }))}>
                      <Select.Option value="challenge">{displayAction('challenge', t)}</Select.Option>
                      <Select.Option value="block">{displayAction('block', t)}</Select.Option>
                      <Select.Option value="monitor">{displayAction('monitor', t)}</Select.Option>
                      <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                    </Select>
                  </label>
                  <label><span>{t('ip.confidence')}</span><InputNumber value={importDraft.confidence * 100} min={0} max={100} precision={0} onChange={(value) => setImportDraft((current) => ({ ...current, confidence: Number(value || 0) / 100 }))} /></label>
                  <label className="wide-field tag-token-field">
                    <span>{t('ip.labels')}</span>
                    <TagTokenInput
                      value={importDraft.labels}
                      onChange={(labels) => setImportDraft((current) => ({ ...current, labels }))}
                      placeholder={t('ip.labelPlaceholder')}
                    />
                  </label>
                  <label className="ioc-field"><span>IOC</span><Input.TextArea value={importDraft.contents} placeholder={t('ip.iocPlaceholder')} autoSize={{ minRows: 10, maxRows: 16 }} onChange={(contents) => setImportDraft((current) => ({ ...current, contents }))} /></label>
                </div>
                <div className="form-action-row">
                  <Button
                    type="primary"
                    disabled={!importDraft.contents.trim()}
                    loading={importMutation.isPending}
                    onClick={() => importMutation.mutate({ ...importDraft, labels: importDraft.labels })}
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
                    <Select value={lookupDraft.providerId} onChange={(providerId) => setLookupDraft((current) => ({ ...current, providerId: providerId as string }))}>
                      {providers.map((provider) => <Select.Option key={provider.id} value={provider.id}>{provider.name || provider.id}</Select.Option>)}
                    </Select>
                  </label>
                  <label><span>IP</span><Input value={lookupDraft.ip} placeholder="8.8.8.8" onChange={(ip) => setLookupDraft((current) => ({ ...current, ip }))} /></label>
                </div>
                <div className="form-action-row">
                  <Button type="primary" disabled={!lookupDraft.providerId || !lookupDraft.ip} loading={lookupMutation.isPending} onClick={() => lookupMutation.mutate()}>
                    {t('ip.lookup')}
                  </Button>
                </div>
                {lookupStatus && <IntelStatusPanel status={lookupStatus} t={t} />}
                {syncStatus && <IntelStatusPanel status={syncStatus} t={t} compact />}
              </section>
            </div>
          </Tabs.TabPane>
        </Tabs>
      </section>
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
    ArcoMessage.success(status.title);
    return;
  }
  if (status.tone === 'warning') {
    ArcoMessage.warning(status.title);
    return;
  }
  ArcoMessage.error(status.title);
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
  const listColor = entry.list === 'whitelist' ? 'green' : entry.list === 'blacklist' ? 'red' : 'blue';
  const stats = statsFor(entry);
  const intel = intelFor(entry);

  return (
    <article className="ip-entry-card">
      <header>
        <span className="table-identity">
          <Shield size={17} />
          <strong>{entry.ip}</strong>
        </span>
        <Tag color={listColor}>{list}</Tag>
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
        <Button size="small" icon={<CheckCircle2 size={14} />} loading={savingAccess} onClick={onAllow}>{t('ip.allow')}</Button>
        <Button size="small" status="danger" icon={<Ban size={14} />} loading={savingAccess} onClick={onBlock}>{t('ip.block')}</Button>
        <Button size="small" icon={<RotateCcw size={14} />} loading={savingAccess} onClick={onMonitor}>{t('common.monitor')}</Button>
      </div>
    </article>
  );
}

async function saveIntelFile(format: 'csv' | 'stix') {
  const blob = await exportThreatIntel(format);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `cheesewaf-threat-intel.${format === 'stix' ? 'json' : 'csv'}`;
  link.click();
  URL.revokeObjectURL(url);
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
        <Popover
          popupVisible={open}
          onVisibleChange={setOpen}
          trigger="click"
          position="bottom"
          content={(
            <div className="ip-tag-popover">
              <TagTokenInput value={draft} onChange={setDraft} placeholder={t('ip.labelPlaceholder')} autoFocus />
              <div>
                <Button size="mini" onClick={() => setDraft(tags)}>{t('common.reset')}</Button>
                <Button size="mini" type="primary" onClick={commit}>{t('common.save')}</Button>
              </div>
            </div>
          )}
        >
          <Button className="ip-tag-edit-btn" size="mini" icon={<Pencil size={12} />} />
        </Popover>
      </div>
    </div>
  );
}

function TagTokenInput({
  value,
  onChange,
  placeholder,
  autoFocus,
}: {
  value: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  autoFocus?: boolean;
}) {
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
    <div className="tag-token-input" onClick={(event) => event.currentTarget.querySelector('input')?.focus()}>
      {value.map((tag) => (
        <span className="ip-token tag-token-input-item" key={tag}>
          {tag}
          <button type="button" aria-label={`Remove ${tag}`} onClick={() => removeToken(tag)}>
            <X size={12} />
          </button>
        </span>
      ))}
      <Input
        autoFocus={autoFocus}
        size="small"
        value={draft}
        placeholder={value.length ? '' : placeholder}
        onChange={setDraft}
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
    <Popover
      popupVisible={open}
      onVisibleChange={setOpen}
      trigger="click"
      position="bottom"
      content={(
        <div className="ip-score-popover">
          <InputNumber min={0} max={100} precision={0} value={draft} onChange={(score) => setDraft(Number(score ?? value))} />
          <div>
            <Button size="mini" disabled={override === undefined} onClick={() => { onReset(); setOpen(false); }}>{t('common.reset')}</Button>
            <Button size="mini" type="primary" loading={saving} onClick={() => { onSave(draft); setOpen(false); }}>{t('common.save')}</Button>
          </div>
        </div>
      )}
    >
      <button className="ip-score-button" type="button">
        <Tag color={reputationColor(value)}>{value}</Tag>
        {override !== undefined && <span>{t('ip.manual')}</span>}
      </button>
    </Popover>
  );
}

function splitList(value: string) {
  return value.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
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

function reputationColor(value: number) {
  if (value >= 80) {
    return 'green';
  }
  if (value >= 50) {
    return 'orange';
  }
  return 'red';
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

function normalizeAccessRuleForSave(rule: IPAccessRule): IPAccessRule {
  const scope = rule.scope === 'directory' ? 'path' : rule.scope || 'global';
  const pathPrefix = scope === 'path' ? normalizePathPrefix(rule.path_prefix) : '';
  return {
    ...rule,
    id: rule.id || `ip-rule-${Date.now()}`,
    name: rule.name || rule.id || 'IP access rule',
    description: rule.description || '',
    action: rule.action === 'block' ? 'block' : rule.action === 'monitor' ? 'monitor' : 'allow',
    scope,
    site_id: scope === 'global' ? '' : rule.site_id,
    path_prefix: pathPrefix,
    entries: rule.entries.map((entry) => entry.trim()).filter(Boolean),
    enabled: rule.enabled,
  };
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
