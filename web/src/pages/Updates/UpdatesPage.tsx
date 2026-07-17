import { Button, Empty, Input, InputNumber, Message as ArcoMessage, Select, Space, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CloudDownload, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig, updateSystemConfig } from '../../api/client';
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
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const [feedPage, setFeedPage] = useState(1);
  const [keySyncing, setKeySyncing] = useState(false);
  const [otaServerSelection, setOtaServerSelection] = useState(OFFICIAL_OTA_SERVER);
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data } = systemQuery;
  const enabledFeeds = useMemo(() => system.vulnerability.feeds.filter((feed) => feed.enabled).length, [system.vulnerability.feeds]);
  const feedPageCount = Math.max(1, Math.ceil(system.vulnerability.feeds.length / FEED_PAGE_SIZE));
  const visibleFeeds = system.vulnerability.feeds.slice((feedPage - 1) * FEED_PAGE_SIZE, feedPage * FEED_PAGE_SIZE);
  const configuredUpdateServer = system.update.ota.server;
  const updateServer = system.update.ota.server || OFFICIAL_OTA_SERVER;
  const updateServerSelectValue = otaServerSelection === CUSTOM_OTA_SERVER_OPTION ? CUSTOM_OTA_SERVER_OPTION : resolveOTAServerSelectValue(updateServer);
  const showCustomUpdateServer = updateServerSelectValue === CUSTOM_OTA_SERVER_OPTION;
  const customUpdateServerValue = showCustomUpdateServer && !OTA_SERVER_OPTIONS.includes(configuredUpdateServer) ? configuredUpdateServer : '';

  useEffect(() => {
    if (data) {
      const normalized = normalizeSystem(data);
      if (!normalized.update.ota.server) {
        normalized.update.ota.server = OFFICIAL_OTA_SERVER;
      }
      setOtaServerSelection(resolveOTAServerSelectValue(normalized.update.ota.server));
      setSystem(normalized);
    }
  }, [data]);

  useEffect(() => {
    setFeedPage((current) => Math.min(current, feedPageCount));
  }, [feedPageCount]);

  const saveMutation = useMutation({
    mutationFn: updateSystemConfig,
    onSuccess: (saved) => {
      setSystem(normalizeSystem(saved));
      queryClient.invalidateQueries({ queryKey: ['system'] });
      ArcoMessage.success(t('updates.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const patchSystem = (patch: Partial<SystemConfig>) => setSystem((current) => normalizeSystem({ ...current, ...patch }));

  function saveUpdatesConfig() {
    if (!systemQuery.isSuccess) {
      return;
    }
    try {
      saveMutation.mutate(buildUpdatesSavePayload(system, otaServerSelection));
    } catch (error) {
      ArcoMessage.error(error instanceof Error ? error.message : t('updates.publicKeySyncFailed'));
    }
  }

  async function syncOfficialPublicKey() {
    const validatedServer = validateOTAServer(system.update.ota.server, otaServerSelection);
    if (!validatedServer) {
      ArcoMessage.error(t('updates.invalidCustomServer'));
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
      ArcoMessage.success(t('updates.publicKeySynced'));
    } catch (error) {
      ArcoMessage.error(error instanceof Error ? error.message : t('updates.publicKeySyncFailed'));
    } finally {
      setKeySyncing(false);
    }
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('updates.title')}</h1>
          <p>{t('updates.subtitle')}</p>
        </div>
        {systemQuery.isError && <Button onClick={() => systemQuery.refetch()} loading={systemQuery.isFetching}>{t('common.retry')}</Button>}
        <Button type="primary" icon={<CloudDownload size={16} />} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess} onClick={saveUpdatesConfig}>
          {t('common.save')}
        </Button>
      </header>

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
            <Tag color={system.update.ota.enabled ? 'green' : 'gray'}>{system.update.ota.enabled ? t('system.enabled') : t('system.disabled')}</Tag>
          </div>
          <div className="updates-runtime-form">
            <label className="switch-line updates-main-switch"><span>{t('updates.enableAutoUpdate')}</span><Switch checked={system.update.ota.enabled} onChange={(enabled) => patchSystem({ update: { ota: { ...system.update.ota, enabled } } })} /></label>
            <label className="wide-field"><span>{t('system.updateServer')}</span>
              <Select
                value={updateServerSelectValue}
                onChange={(server) => {
                  const selected = String(server);
                  setOtaServerSelection(selected);
                  if (selected !== CUSTOM_OTA_SERVER_OPTION) {
                    patchSystem({ update: { ota: { ...system.update.ota, server: selected } } });
                  } else if (OTA_SERVER_OPTIONS.includes(system.update.ota.server)) {
                    patchSystem({ update: { ota: { ...system.update.ota, server: '' } } });
                  }
                }}
              >
                <Select.Option value={OFFICIAL_OTA_SERVER}>{t('updates.officialServer')} ({OFFICIAL_OTA_SERVER})</Select.Option>
                <Select.Option value={FORGEJO_OTA_SERVER}>{t('updates.forgejoServer')}</Select.Option>
                <Select.Option value={GITHUB_OTA_SERVER}>{t('updates.githubServer')}</Select.Option>
                <Select.Option value={CUSTOM_OTA_SERVER_OPTION}>{t('updates.customServer')}</Select.Option>
              </Select>
            </label>
            {showCustomUpdateServer && (
              <label className="wide-field"><span>{t('updates.customURL')}</span><Input value={customUpdateServerValue} placeholder="https://" onChange={(server) => patchSystem({ update: { ota: { ...system.update.ota, server } } })} /></label>
            )}
            <label>
              <span>{t('system.channel')}</span>
              <Select value={system.update.ota.channel} onChange={(channel) => patchSystem({ update: { ota: { ...system.update.ota, channel: channel as string } } })}>
                <Select.Option value="stable">{t('updates.channelStable')}</Select.Option>
                <Select.Option value="canary">{t('updates.channelCanary')}</Select.Option>
                <Select.Option value="dev">{t('updates.channelDev')}</Select.Option>
              </Select>
            </label>
            <label><span>{t('system.checkIntervalHours')}</span><InputNumber value={durationSeconds(system.update.ota.check_interval) / 3600} min={1} max={168} onChange={(value) => patchSystem({ update: { ota: { ...system.update.ota, check_interval: secondsToDuration(Number(value || 1) * 3600) } } })} /></label>
            <label className="switch-line"><span>{t('system.autoUpdateRules')}</span><Switch checked={system.update.ota.auto_update_rules} onChange={(auto_update_rules) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_rules } } })} /></label>
            <label className="switch-line"><span>{t('system.autoUpdateBinary')}</span><Switch checked={system.update.ota.auto_update_binary} onChange={(auto_update_binary) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_binary } } })} /></label>
            <label className="switch-line"><span>{t('system.verifySignature')}</span><Switch checked={system.update.ota.verify_signature} onChange={(verify_signature) => patchSystem({ update: { ota: { ...system.update.ota, verify_signature } } })} /></label>
            <div className="updates-public-key wide-field">
              <div>
                <span>{t('system.publicKey')}</span>
                <strong>{system.update.ota.public_key ? publicKeySummary(system.update.ota.public_key, t) : t('updates.publicKeyNotSet')}</strong>
              </div>
              <Button loading={keySyncing} onClick={syncOfficialPublicKey}>{t('updates.syncPublicKey')}</Button>
            </div>
          </div>
        </section>

        <section className="panel updates-feeds-panel">
          <div className="panel-heading">
            <h2><ShieldAlert size={16} /> {t('updates.vulnerabilityFeeds')}</h2>
            <Space wrap>
              <Switch checked={system.vulnerability.enabled} onChange={(enabled) => patchSystem({ vulnerability: { ...system.vulnerability, enabled } })} />
              <Button icon={<Plus size={15} />} onClick={() => addVulnerabilityFeed(setSystem)}>{t('common.add')}</Button>
            </Space>
          </div>
          <div className="feed-list feed-list-detailed">
            {visibleFeeds.map((feed, pageIndex) => {
              const index = (feedPage - 1) * FEED_PAGE_SIZE + pageIndex;
              return (
              <div className="feed-card" key={feed.id}>
                <div className="feed-card-head">
                  <Switch checked={feed.enabled} onChange={(enabled) => updateVulnerabilityFeed(index, { enabled }, setSystem)} />
                  <Input value={feed.name} placeholder="NVD" onChange={(name) => updateVulnerabilityFeed(index, { name }, setSystem)} />
                  <Button status="danger" icon={<Trash2 size={14} />} onClick={() => removeVulnerabilityFeed(feed.id, setSystem)} />
                </div>
                <div className="feed-card-body">
                  <label className="wide-field">
                    <span>URL</span>
                    <Input value={feed.url} placeholder="https://..." onChange={(url) => updateVulnerabilityFeed(index, { url }, setSystem)} />
                  </label>
                  <label>
                    <span>{t('ip.format')}</span>
                    <Select value={feed.type || 'json'} onChange={(type) => updateVulnerabilityFeed(index, { type: type as string }, setSystem)}>
                      <Select.Option value="json">JSON</Select.Option>
                      <Select.Option value="nvd">NVD</Select.Option>
                      <Select.Option value="osv">OSV</Select.Option>
                      <Select.Option value="cve">CVE</Select.Option>
                    </Select>
                  </label>
                  <label>
                    <span>{t('rules.severity')}</span>
                    <Select value={feed.min_severity} onChange={(min_severity) => updateVulnerabilityFeed(index, { min_severity: min_severity as string }, setSystem)}>
                      <Select.Option value="low">{t('rules.low')}</Select.Option>
                      <Select.Option value="medium">{t('rules.medium')}</Select.Option>
                      <Select.Option value="high">{t('rules.high')}</Select.Option>
                      <Select.Option value="critical">{t('rules.critical')}</Select.Option>
                    </Select>
                  </label>
                  <label>
                    <span>{t('system.checkIntervalHours')}</span>
                    <InputNumber value={durationSeconds(feed.interval) / 3600} min={1} max={720} onChange={(value) => updateVulnerabilityFeed(index, { interval: secondsToDuration(Number(value || 12) * 3600) }, setSystem)} />
                  </label>
                  <label className="switch-line">
                    <span>{t('updates.notify')}</span>
                    <Switch checked={feed.notify} onChange={(notify) => updateVulnerabilityFeed(index, { notify }, setSystem)} />
                  </label>
                </div>
              </div>
            ); })}
            {!system.vulnerability.feeds.length && <Empty description={t('system.noFeeds')} />}
          </div>
          {system.vulnerability.feeds.length > FEED_PAGE_SIZE && (
            <div className="feed-pagination">
              <span>{t('updates.feedPage', { page: feedPage, total: feedPageCount })}</span>
              <Space>
                <Button disabled={feedPage <= 1} onClick={() => setFeedPage((current) => Math.max(1, current - 1))}>{t('common.back')}</Button>
                <Button disabled={feedPage >= feedPageCount} onClick={() => setFeedPage((current) => Math.min(feedPageCount, current + 1))}>{t('common.next')}</Button>
              </Space>
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

function addVulnerabilityFeed(setSystem: React.Dispatch<React.SetStateAction<SystemConfig>>) {
  setSystem((current) => ({
    ...current,
    vulnerability: {
      ...current.vulnerability,
      feeds: [
        ...current.vulnerability.feeds,
        {
          id: `feed-${Date.now()}`,
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
  }));
}

function updateVulnerabilityFeed(index: number, patch: Partial<Feed>, setSystem: React.Dispatch<React.SetStateAction<SystemConfig>>) {
  setSystem((current) => ({
    ...current,
    vulnerability: {
      ...current.vulnerability,
      feeds: current.vulnerability.feeds.map((feed, feedIndex) => (feedIndex === index ? { ...feed, ...patch } : feed)),
    },
  }));
}

function removeVulnerabilityFeed(id: string, setSystem: React.Dispatch<React.SetStateAction<SystemConfig>>) {
  setSystem((current) => ({
    ...current,
    vulnerability: {
      ...current.vulnerability,
      feeds: current.vulnerability.feeds.filter((feed) => feed.id !== id),
    },
  }));
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
