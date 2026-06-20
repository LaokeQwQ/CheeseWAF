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
const FEED_PAGE_SIZE = 4;

export default function UpdatesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const [feedPage, setFeedPage] = useState(1);
  const [keySyncing, setKeySyncing] = useState(false);
  const { data } = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const enabledFeeds = useMemo(() => system.vulnerability.feeds.filter((feed) => feed.enabled).length, [system.vulnerability.feeds]);
  const feedPageCount = Math.max(1, Math.ceil(system.vulnerability.feeds.length / FEED_PAGE_SIZE));
  const visibleFeeds = system.vulnerability.feeds.slice((feedPage - 1) * FEED_PAGE_SIZE, feedPage * FEED_PAGE_SIZE);
  const updateServer = system.update.ota.server || OFFICIAL_OTA_SERVER;

  useEffect(() => {
    if (data) {
      const normalized = normalizeSystem(data);
      if (!normalized.update.ota.server) {
        normalized.update.ota.server = OFFICIAL_OTA_SERVER;
      }
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

  async function syncOfficialPublicKey() {
    setKeySyncing(true);
    try {
      const base = updateServer.endsWith('/') ? updateServer : `${updateServer}/`;
      const response = await fetch(new URL('public-key.pem', base).toString(), { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`${response.status} ${response.statusText}`);
      }
      const publicKey = (await response.text()).trim();
      if (!publicKey.includes('BEGIN PUBLIC KEY')) {
        throw new Error(t('updates.publicKeyInvalid'));
      }
      patchSystem({ update: { ota: { ...system.update.ota, server: updateServer, public_key: publicKey } } });
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
        <Button type="primary" icon={<CloudDownload size={16} />} loading={saveMutation.isPending} onClick={() => saveMutation.mutate({ update: system.update, vulnerability: system.vulnerability })}>
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
              <Select value={updateServer || OFFICIAL_OTA_SERVER} onChange={(server) => patchSystem({ update: { ota: { ...system.update.ota, server: String(server) } } })}>
                <Select.Option value={OFFICIAL_OTA_SERVER}>{t('updates.officialServer')} ({OFFICIAL_OTA_SERVER})</Select.Option>
                <Select.Option value="https://git.laoker.cc/Laoke/CheeseWAF/releases">{t('updates.forgejoServer')}</Select.Option>
                <Select.Option value="https://github.com/LaokeQwQ/CheeseWAF/releases">{t('updates.githubServer')}</Select.Option>
                <Select.Option value="__custom__">{t('updates.customServer')}</Select.Option>
              </Select>
            </label>
            {updateServer !== OFFICIAL_OTA_SERVER && updateServer !== 'https://git.laoker.cc/Laoke/CheeseWAF/releases' && updateServer !== 'https://github.com/LaokeQwQ/CheeseWAF/releases' && (
              <label className="wide-field"><span>{t('updates.customURL')}</span><Input value={updateServer} placeholder="https://" onChange={(server) => patchSystem({ update: { ota: { ...system.update.ota, server } } })} /></label>
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

function publicKeySummary(value: string, t: (key: string, options?: Record<string, unknown>) => string) {
  return t('updates.publicKeyConfigured', { chars: value.trim().length });
}
