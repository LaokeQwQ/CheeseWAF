import { useEffect, useMemo, useState } from 'react';
import { Button, Input, InputNumber, Message as ArcoMessage, Popover, Select, Space, Switch, Table, Tabs, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { CloudDownload, FileDown, Pencil, Plus, Search, Shield, Tags, Trash2 } from 'lucide-react';
import {
  exportThreatIntel,
  fetchIPRules,
  importThreatIntel,
  lookupThreatIntel,
  syncThreatIntel,
  testThreatIntelProvider,
  updateIPTags,
  updateThreatIntelProviders,
} from '../../api/client';
import type { IPReputationEntry, ThreatIntelProvider } from '../../types/api';
import { displayAction, displaySeverity } from '../../utils/display';

const second = 1_000_000_000;

export default function IPManagePage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [routeParams, setRouteParams] = useSearchParams();
  const activeTab = routeParams.get('tab') === 'providers' || routeParams.get('tab') === 'import' ? routeParams.get('tab') as string : 'entries';
  const [search, setSearch] = useState('');
  const [draftTags, setDraftTags] = useState<Record<string, string[]>>({});
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [importDraft, setImportDraft] = useState({
    format: 'cidr',
    source: 'manual',
    severity: 'high',
    action: 'challenge',
    confidence: 0.9,
    labels: '',
    contents: '',
  });
  const [lookupDraft, setLookupDraft] = useState({ providerId: '', ip: '' });
  const { data, isLoading } = useQuery({ queryKey: ['ip-rules'], queryFn: fetchIPRules, retry: false });
  const entries = data?.entries ?? [];

  useEffect(() => {
    if (data?.tags) {
      setDraftTags(data.tags);
    }
    if (data?.providers) {
      setProviders(data.providers);
      if (!lookupDraft.providerId && data.providers.length > 0) {
        setLookupDraft((current) => ({ ...current, providerId: data.providers[0].id }));
      }
    }
  }, [data?.providers, data?.tags, lookupDraft.providerId]);

  const tagMutation = useMutation({
    mutationFn: updateIPTags,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ip-rules'] }),
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
      ArcoMessage.success(`${t('ip.imported')} ${result.imported}`);
      setImportDraft((current) => ({ ...current, contents: '' }));
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const syncMutation = useMutation({
    mutationFn: syncThreatIntel,
    onSuccess: (result) => {
      ArcoMessage.success(`${t('ip.synced')} ${result.imported}`);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const providerTestMutation = useMutation({
    mutationFn: testThreatIntelProvider,
    onSuccess: (result) => ArcoMessage.success(`${t('system.testOk')}: ${result.count}`),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const lookupMutation = useMutation({
    mutationFn: () => lookupThreatIntel(lookupDraft.providerId, lookupDraft.ip),
    onSuccess: (result) => {
      ArcoMessage.success(`${t('ip.lookupImported')} ${result.imported}`);
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
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
        format: 'stix',
        action: 'challenge',
        min_severity: 'high',
        interval: 24 * 60 * 60 * second,
        headers: {},
        enabled: true,
      },
    ]);
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ip.title')}</h1>
          <p>{t('ip.subtitle')}</p>
        </div>
        <span className="table-identity">
          <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('csv')}>CSV</Button>
          <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('stix')}>STIX</Button>
          <Button type="primary" icon={<Tags size={16} />} loading={tagMutation.isPending} onClick={() => tagMutation.mutate(draftTags)}>
            {t('ip.saveTags')}
          </Button>
        </span>
      </header>

      <section className="panel">
        <Tabs
          activeTab={activeTab}
          onChange={(tab) => {
            const next = new URLSearchParams(routeParams);
            if (tab === 'entries') {
              next.delete('tab');
            } else {
              next.set('tab', tab);
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
                  { title: t('ip.reputation'), dataIndex: 'reputation', render: (value: number) => <Tag color={reputationColor(value)}>{value}</Tag> },
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
                          const confidence = typeof item.confidence === 'number' && item.confidence > 0 ? ` · ${Math.round(item.confidence * 100)}%` : '';
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
                ]}
              />
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
                {providers.map((provider, index) => (
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
                        <Button size="small" status="danger" icon={<Trash2 size={14} />} onClick={() => removeProvider(provider.id)} />
                      </div>
                    </div>
                    <div className="provider-field-grid">
                      <label>
                        <span>{t('ip.providerName')}</span>
                        <Input value={provider.name} placeholder={t('ip.providerName')} onChange={(name) => updateProvider(index, { name })} />
                      </label>
                      <label>
                        <span>{t('ip.providerType')}</span>
                        <Select value={provider.type} onChange={(type) => updateProvider(index, { type: type as string })}>
                          <Select.Option value="generic">Generic</Select.Option>
                          <Select.Option value="threatbook-cn">ThreatBook CN</Select.Option>
                          <Select.Option value="threatbook-intl">ThreatBook Intl</Select.Option>
                          <Select.Option value="misp">MISP</Select.Option>
                          <Select.Option value="stix">STIX</Select.Option>
                        </Select>
                      </label>
                      <label>
                        <span>{t('ip.format')}</span>
                        <Select value={provider.format || 'stix'} onChange={(format) => updateProvider(index, { format: format as string })}>
                          <Select.Option value="cidr">CIDR/TXT</Select.Option>
                          <Select.Option value="csv">CSV</Select.Option>
                          <Select.Option value="json">JSON</Select.Option>
                          <Select.Option value="stix">STIX</Select.Option>
                          <Select.Option value="threatbook">ThreatBook</Select.Option>
                        </Select>
                      </label>
                      <label>
                        <span>{t('logs.action')}</span>
                        <Select value={provider.action || 'challenge'} onChange={(action) => updateProvider(index, { action: action as string })}>
                          <Select.Option value="challenge">{t('logs.challenge')}</Select.Option>
                          <Select.Option value="block">{t('common.block')}</Select.Option>
                          <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                        </Select>
                      </label>
                      <label className="provider-endpoint-field">
                        <span>{t('ip.endpoint')}</span>
                        <Input value={provider.endpoint} placeholder="https://..." onChange={(endpoint) => updateProvider(index, { endpoint })} />
                      </label>
                      <label>
                        <span>API Key</span>
                        <Input.Password value={provider.api_key} placeholder="API Key" onChange={(api_key) => updateProvider(index, { api_key })} />
                      </label>
                      <label>
                        <span>{t('ip.intervalHours')}</span>
                        <InputNumber value={durationSeconds(provider.interval) / 3600} min={1} max={720} onChange={(value) => updateProvider(index, { interval: secondsToDuration(Number(value || 24) * 3600) })} />
                      </label>
                    </div>
                  </article>
                ))}
                {!providers.length && <div className="empty-state">{t('ip.noProviders')}</div>}
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="import" title={t('ip.import')}>
            <div className="ip-intel-workspace">
              <section className="system-card ip-import-card">
                <div className="system-section-title"><h2>{t('ip.import')}</h2></div>
                <div className="ip-import-grid">
                  <label>
                    <span>{t('ip.format')}</span>
                    <Select value={importDraft.format} onChange={(format) => setImportDraft((current) => ({ ...current, format: format as string }))}>
                      <Select.Option value="cidr">CIDR/TXT</Select.Option>
                      <Select.Option value="csv">CSV</Select.Option>
                      <Select.Option value="json">JSON</Select.Option>
                      <Select.Option value="stix">STIX</Select.Option>
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
                      <Select.Option value="challenge">{t('logs.challenge')}</Select.Option>
                      <Select.Option value="block">{t('common.block')}</Select.Option>
                      <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                    </Select>
                  </label>
                  <label><span>{t('ip.confidence')}</span><InputNumber value={importDraft.confidence * 100} min={0} max={100} precision={0} onChange={(value) => setImportDraft((current) => ({ ...current, confidence: Number(value || 0) / 100 }))} /></label>
                  <label className="wide-field"><span>{t('ip.labels')}</span><Input value={importDraft.labels} onChange={(labels) => setImportDraft((current) => ({ ...current, labels }))} /></label>
                  <label className="ioc-field"><span>IOC</span><Input.TextArea value={importDraft.contents} autoSize={{ minRows: 12, maxRows: 20 }} onChange={(contents) => setImportDraft((current) => ({ ...current, contents }))} /></label>
                </div>
                <div className="form-action-row">
                  <Button
                    type="primary"
                    disabled={!importDraft.contents.trim()}
                    loading={importMutation.isPending}
                    onClick={() => importMutation.mutate({ ...importDraft, labels: splitList(importDraft.labels) })}
                  >
                    {t('ip.import')}
                  </Button>
                </div>
              </section>
              <section className="system-card ip-lookup-card">
                <div className="system-section-title"><h2>{t('ip.lookup')}</h2></div>
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
              </section>
            </div>
          </Tabs.TabPane>
        </Tabs>
      </section>
    </section>
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
  const tagText = tags.join(', ');
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(tagText);

  useEffect(() => {
    setDraft(tagText);
  }, [tagText]);

  const commit = () => {
    onChange(splitList(draft));
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
              <Input
                size="small"
                value={draft}
                placeholder="tag-a, tag-b"
                onChange={setDraft}
                onPressEnter={commit}
              />
              <div>
                <Button size="mini" onClick={() => setDraft(tagText)}>{t('common.reset')}</Button>
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

function splitList(value: string) {
  return value.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
}

function tagsFor(entry: IPReputationEntry, draftTags: Record<string, string[]>) {
  const tags = draftTags[entry.ip] ?? entry.tags;
  return Array.isArray(tags) ? tags : [];
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
