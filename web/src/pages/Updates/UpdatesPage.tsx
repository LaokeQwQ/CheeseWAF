import { Badge, Button, Empty, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Switch, toast } from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CloudDownload, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig, updateSystemConfig } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { useServerDraft } from '../../hooks/useServerDraft';
import type { SystemConfig } from '../../types/api';
import { fallbackSystem, normalizeSystem, second, secondsToDuration, durationSeconds } from '../System/systemModel';

type Feed = SystemConfig['vulnerability']['feeds'][number];
const OFFICIAL_OTA_SERVER = 'https://ota.waf.laoker.cc/';
const FORGEJO_OTA_SERVER = 'https://git.laoker.cc/Laoke/CheeseWAF/releases';
const GITHUB_OTA_SERVER = 'https://github.com/LaokeQwQ/CheeseWAF/releases';
export const CUSTOM_OTA_SERVER_OPTION = '__custom__';
const OTA_SERVER_OPTIONS = [OFFICIAL_OTA_SERVER, FORGEJO_OTA_SERVER, GITHUB_OTA_SERVER];
const FEED_PAGE_SIZE = 4;

export default function UpdatesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [feedPage, setFeedPage] = useState(1);
  const [keySyncing, setKeySyncing] = useState(false);
  const [otaServerSelection, setOtaServerSelection] = useState(OFFICIAL_OTA_SERVER);
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data, isError, isFetching, isLoading, isSuccess, error, refetch } = systemQuery;
  const serverSystem = useMemo(() => {
    if (!data) {
      return undefined;
    }
    const normalized = normalizeSystem(data);
    if (!normalized.update.ota.server) {
      normalized.update.ota.server = OFFICIAL_OTA_SERVER;
    }
    return normalized;
  }, [data]);
  const { draft, setDraft, markClean, isDirty } = useServerDraft(serverSystem);
  const system = draft ?? fallbackSystem;
  const ready = Boolean(draft) && isSuccess;

  useEffect(() => {
    if (!serverSystem || isDirty()) {
      return;
    }
    setOtaServerSelection(resolveOTAServerSelectValue(serverSystem.update.ota.server));
  }, [serverSystem, isDirty]);

  const enabledFeeds = useMemo(() => system.vulnerability.feeds.filter((feed) => feed.enabled).length, [system.vulnerability.feeds]);
  const feedPageCount = Math.max(1, Math.ceil(system.vulnerability.feeds.length / FEED_PAGE_SIZE));
  const visibleFeeds = system.vulnerability.feeds.slice((feedPage - 1) * FEED_PAGE_SIZE, feedPage * FEED_PAGE_SIZE);
  const configuredUpdateServer = system.update.ota.server;
  const updateServer = system.update.ota.server || OFFICIAL_OTA_SERVER;
  const updateServerSelectValue = otaServerSelection === CUSTOM_OTA_SERVER_OPTION ? CUSTOM_OTA_SERVER_OPTION : resolveOTAServerSelectValue(updateServer);
  const showCustomUpdateServer = updateServerSelectValue === CUSTOM_OTA_SERVER_OPTION;
  const customUpdateServerValue = showCustomUpdateServer && !OTA_SERVER_OPTIONS.includes(configuredUpdateServer) ? configuredUpdateServer : '';

  useEffect(() => {
    setFeedPage((current) => Math.min(current, feedPageCount));
  }, [feedPageCount]);

  const saveMutation = useMutation({
    mutationFn: updateSystemConfig,
    onSuccess: (saved) => {
      const normalized = normalizeSystem(saved);
      markClean(normalized);
      setOtaServerSelection(resolveOTAServerSelectValue(normalized.update.ota.server || OFFICIAL_OTA_SERVER));
      queryClient.invalidateQueries({ queryKey: ['system'] });
      toast.success(t('updates.saved'));
    },
    onError: (mutationError) => toast.error(mutationError.message),
  });

  const patchSystem = (patch: Partial<SystemConfig>) => setDraft((current) => normalizeSystem({ ...(current ?? fallbackSystem), ...patch }));

  function saveUpdatesConfig() {
    if (!ready) {
      return;
    }
    try {
      saveMutation.mutate(buildUpdatesSavePayload(system, otaServerSelection));
    } catch {
      toast.error(t('updates.invalidCustomServer'));
    }
  }

  async function syncOfficialPublicKey() {
    const validatedServer = validateOTAServer(system.update.ota.server, otaServerSelection);
    if (!validatedServer) {
      toast.error(t('updates.invalidCustomServer'));
      return;
    }
    setKeySyncing(true);
    try {
      const base = validatedServer.endsWith('/') ? validatedServer : `${validatedServer}/`;
      const response = await fetch(new URL('public-key.pem', base).toString(), { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      const publicKey = (await response.text()).trim();
      if (!publicKey.includes('BEGIN PUBLIC KEY')) {
        throw new Error(t('updates.publicKeyInvalid'));
      }
      patchSystem({ update: { ota: { ...system.update.ota, server: validatedServer, public_key: publicKey } } });
      toast.success(t('updates.publicKeySynced'));
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('updates.publicKeySyncFailed'));
    } finally {
      setKeySyncing(false);
    }
  }

  if (isLoading && !draft) {
    return (
      <section className="page-surface">
        <header className="page-header">
          <div>
            <h1>{t('updates.title')}</h1>
            <p>{t('updates.subtitle')}</p>
          </div>
        </header>
        <div className="empty-state" role="status">{t('common.loading')}</div>
      </section>
    );
  }

  if (isError && !draft) {
    return (
      <section className="page-surface">
        <header className="page-header">
          <div>
            <h1>{t('updates.title')}</h1>
            <p>{t('updates.subtitle')}</p>
          </div>
        </header>
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
      <header className="page-header">
        <div>
          <h1>{t('updates.title')}</h1>
          <p>{t('updates.subtitle')}</p>
        </div>
        <Button loading={saveMutation.isPending} disabled={!ready} onClick={saveUpdatesConfig}>
          <CloudDownload size={16} />
          {t('common.save')}
        </Button>
      </header>

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
          <span>{t('updates.channel')}</span>
          <strong>{system.update.ota.channel}</strong>
        </div>
        <div>
          <ShieldAlert size={20} />
          <span>{t('updates.emergencyRules')}</span>
          <strong>{system.update.ota.auto_update_rules ? t('system.enabled') : t('system.disabled')}</strong>
        </div>
        <div>
          <Plus size={20} />
          <span>{t('updates.feedCount')}</span>
          <strong>{enabledFeeds}/{system.vulnerability.feeds.length}</strong>
        </div>
      </section>

      <div className="updates-grid">
        <section className="panel updates-runtime-panel">
          <div className="panel-heading">
            <h2><CloudDownload size={16} /> {t('updates.runtimeUpdate')}</h2>
            <Badge variant={system.update.ota.enabled ? 'success' : 'secondary'}>
              {system.update.ota.enabled ? t('system.enabled') : t('system.disabled')}
            </Badge>
          </div>
          <div className="updates-runtime-form">
            <label className="switch-line updates-main-switch">
              <span>{t('updates.enableAutoUpdate')}</span>
              <Switch
                checked={system.update.ota.enabled}
                disabled={!ready}
                onCheckedChange={(enabled) => patchSystem({ update: { ota: { ...system.update.ota, enabled } } })}
              />
            </label>
            <label className="wide-field">
              <span>{t('system.updateServer')}</span>
              <Select
                value={updateServerSelectValue}
                onValueChange={(server) => {
                  const selected = String(server);
                  setOtaServerSelection(selected);
                  if (selected !== CUSTOM_OTA_SERVER_OPTION) {
                    patchSystem({ update: { ota: { ...system.update.ota, server: selected } } });
                  } else if (OTA_SERVER_OPTIONS.includes(system.update.ota.server)) {
                    patchSystem({ update: { ota: { ...system.update.ota, server: '' } } });
                  }
                }}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value={OFFICIAL_OTA_SERVER}>{t('updates.officialServer')} ({OFFICIAL_OTA_SERVER})</SelectItem>
                  <SelectItem value={FORGEJO_OTA_SERVER}>{t('updates.forgejoServer')}</SelectItem>
                  <SelectItem value={GITHUB_OTA_SERVER}>{t('updates.githubServer')}</SelectItem>
                  <SelectItem value={CUSTOM_OTA_SERVER_OPTION}>{t('updates.customServer')}</SelectItem>
                </SelectContent>
              </Select>
            </label>
            {showCustomUpdateServer && (
              <label className="wide-field">
                <span>{t('updates.customURL')}</span>
                <Input
                  value={customUpdateServerValue}
                  placeholder="https://"
                  onChange={(event) => patchSystem({ update: { ota: { ...system.update.ota, server: event.target.value } } })}
                />
              </label>
            )}
            <label>
              <span>{t('system.channel')}</span>
              <Select
                value={system.update.ota.channel}
                onValueChange={(channel) => patchSystem({ update: { ota: { ...system.update.ota, channel } } })}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="stable">{t('updates.channelStable')}</SelectItem>
                  <SelectItem value="canary">{t('updates.channelCanary')}</SelectItem>
                  <SelectItem value="dev">{t('updates.channelDev')}</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label>
              <span>{t('system.checkIntervalHours')}</span>
              <Input
                type="number"
                min={1}
                max={168}
                value={durationSeconds(system.update.ota.check_interval) / 3600}
                onChange={(event) => patchSystem({
                  update: {
                    ota: {
                      ...system.update.ota,
                      check_interval: secondsToDuration(Number(event.target.value || 1) * 3600),
                    },
                  },
                })}
              />
            </label>
            <label className="switch-line">
              <span>{t('system.autoUpdateRules')}</span>
              <Switch
                checked={system.update.ota.auto_update_rules}
                onCheckedChange={(auto_update_rules) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_rules } } })}
              />
            </label>
            <label className="switch-line">
              <span>{t('system.autoUpdateBinary')}</span>
              <Switch
                checked={system.update.ota.auto_update_binary}
                onCheckedChange={(auto_update_binary) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_binary } } })}
              />
            </label>
            <label className="switch-line">
              <span>{t('system.verifySignature')}</span>
              <Switch
                checked={system.update.ota.verify_signature}
                onCheckedChange={(verify_signature) => patchSystem({ update: { ota: { ...system.update.ota, verify_signature } } })}
              />
            </label>
            <div className="updates-public-key wide-field">
              <div>
                <span>{t('system.publicKey')}</span>
                <strong>{system.update.ota.public_key ? publicKeySummary(system.update.ota.public_key, t) : t('updates.publicKeyNotSet')}</strong>
              </div>
              <Button variant="outline" loading={keySyncing} onClick={syncOfficialPublicKey}>{t('updates.syncPublicKey')}</Button>
            </div>
          </div>
        </section>

        <section className="panel updates-feeds-panel">
          <div className="panel-heading">
            <h2><ShieldAlert size={16} /> {t('updates.vulnerabilityFeeds')}</h2>
            <div className="flex flex-wrap items-center gap-2">
              <Switch
                checked={system.vulnerability.enabled}
                onCheckedChange={(enabled) => patchSystem({ vulnerability: { ...system.vulnerability, enabled } })}
              />
              <Button variant="outline" onClick={() => addVulnerabilityFeed(setDraft)} disabled={!ready}>
                <Plus size={15} />
                {t('common.add')}
              </Button>
            </div>
          </div>
          <div className="feed-list feed-list-detailed">
            {visibleFeeds.map((feed, pageIndex) => {
              const index = (feedPage - 1) * FEED_PAGE_SIZE + pageIndex;
              return (
                <div className="feed-card" key={feed.id}>
                  <div className="feed-card-head">
                    <Switch checked={feed.enabled} onCheckedChange={(enabled) => updateVulnerabilityFeed(index, { enabled }, setDraft)} />
                    <Input value={feed.name} placeholder="NVD" onChange={(event) => updateVulnerabilityFeed(index, { name: event.target.value }, setDraft)} />
                    <Button variant="destructive" size="icon" aria-label={t('common.delete')} onClick={() => removeVulnerabilityFeed(feed.id, setDraft)}>
                      <Trash2 size={14} />
                    </Button>
                  </div>
                  <div className="feed-card-body">
                    <label className="wide-field">
                      <span>URL</span>
                      <Input value={feed.url} placeholder="https://..." onChange={(event) => updateVulnerabilityFeed(index, { url: event.target.value }, setDraft)} />
                    </label>
                    <label>
                      <span>{t('ip.format')}</span>
                      <Select value={feed.type || 'json'} onValueChange={(type) => updateVulnerabilityFeed(index, { type }, setDraft)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="json">JSON</SelectItem>
                          <SelectItem value="nvd">NVD</SelectItem>
                          <SelectItem value="osv">OSV</SelectItem>
                          <SelectItem value="cve">CVE</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label>
                      <span>{t('rules.severity')}</span>
                      <Select value={feed.min_severity} onValueChange={(min_severity) => updateVulnerabilityFeed(index, { min_severity }, setDraft)}>
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
                      <span>{t('system.checkIntervalHours')}</span>
                      <Input
                        type="number"
                        min={1}
                        max={720}
                        value={durationSeconds(feed.interval) / 3600}
                        onChange={(event) => updateVulnerabilityFeed(index, { interval: secondsToDuration(Number(event.target.value || 12) * 3600) }, setDraft)}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('updates.notify')}</span>
                      <Switch checked={feed.notify} onCheckedChange={(notify) => updateVulnerabilityFeed(index, { notify }, setDraft)} />
                    </label>
                  </div>
                </div>
              );
            })}
            {!system.vulnerability.feeds.length && <Empty description={t('system.noFeeds')} />}
          </div>
          {system.vulnerability.feeds.length > FEED_PAGE_SIZE && (
            <div className="feed-pagination">
              <span>{t('updates.feedPage', { page: feedPage, total: feedPageCount })}</span>
              <div className="flex gap-2">
                <Button variant="outline" disabled={feedPage <= 1} onClick={() => setFeedPage((current) => Math.max(1, current - 1))}>{t('common.back')}</Button>
                <Button variant="outline" disabled={feedPage >= feedPageCount} onClick={() => setFeedPage((current) => Math.min(feedPageCount, current + 1))}>{t('common.next')}</Button>
              </div>
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

function addVulnerabilityFeed(setSystem: (next: SystemConfig | ((prev: SystemConfig | undefined) => SystemConfig)) => void) {
  setSystem((current) => {
    const base = current ?? fallbackSystem;
    return {
      ...base,
      vulnerability: {
        ...base.vulnerability,
        feeds: [
          ...base.vulnerability.feeds,
          {
            id: `feed-${Date.now()}-${Math.random().toString(16).slice(2)}`,
            name: '',
            type: 'json',
            url: '',
            interval: 12 * 60 * 60 * second,
            min_severity: 'high',
            notify: true,
            enabled: true,
          },
        ],
      },
    };
  });
}

function updateVulnerabilityFeed(index: number, patch: Partial<Feed>, setSystem: (next: SystemConfig | ((prev: SystemConfig | undefined) => SystemConfig)) => void) {
  setSystem((current) => {
    const base = current ?? fallbackSystem;
    return {
      ...base,
      vulnerability: {
        ...base.vulnerability,
        feeds: base.vulnerability.feeds.map((feed, feedIndex) => (feedIndex === index ? { ...feed, ...patch } : feed)),
      },
    };
  });
}

function removeVulnerabilityFeed(id: string, setSystem: (next: SystemConfig | ((prev: SystemConfig | undefined) => SystemConfig)) => void) {
  setSystem((current) => {
    const base = current ?? fallbackSystem;
    return {
      ...base,
      vulnerability: {
        ...base.vulnerability,
        feeds: base.vulnerability.feeds.filter((feed) => feed.id !== id),
      },
    };
  });
}

export function resolveOTAServerSelectValue(server: string) {
  return OTA_SERVER_OPTIONS.includes(server) ? server : CUSTOM_OTA_SERVER_OPTION;
}

export function validateOTAServer(server: string, selection = resolveOTAServerSelectValue(server)) {
  if (selection !== CUSTOM_OTA_SERVER_OPTION && OTA_SERVER_OPTIONS.includes(selection)) {
    return selection;
  }
  if (server === CUSTOM_OTA_SERVER_OPTION) {
    return null;
  }
  try {
    const url = new URL(server);
    if (url.protocol !== 'https:' || !url.hostname) {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}

export function buildUpdatesSavePayload(system: SystemConfig, selection = resolveOTAServerSelectValue(system.update.ota.server)): Pick<SystemConfig, 'update' | 'vulnerability'> {
  const validatedServer = validateOTAServer(system.update.ota.server, selection);
  if (!validatedServer) {
    // Message substring kept for unit tests; UI maps this to updates.invalidCustomServer.
    throw new Error('Custom OTA source must be a valid HTTPS URL.');
  }
  return {
    update: {
      ...system.update,
      ota: {
        ...system.update.ota,
        server: validatedServer,
      },
    },
    vulnerability: system.vulnerability,
  };
}

function publicKeySummary(value: string, t: (key: string, options?: Record<string, unknown>) => string) {
  return t('updates.publicKeyConfigured', { chars: value.trim().length });
}
