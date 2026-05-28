import { Button, Empty, Input, InputNumber, Message as ArcoMessage, Select, Space, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CloudDownload, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig, updateSystemConfig } from '../../api/client';
import type { SystemConfig } from '../../types/api';
import { fallbackSystem, normalizeSystem, second, secondsToDuration, durationSeconds } from '../System/systemModel';

type Feed = SystemConfig['vulnerability']['feeds'][number];

export default function UpdatesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const { data } = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const enabledFeeds = useMemo(() => system.vulnerability.feeds.filter((feed) => feed.enabled).length, [system.vulnerability.feeds]);

  useEffect(() => {
    if (data) {
      setSystem(normalizeSystem(data));
    }
  }, [data]);

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
        <section className="panel">
          <div className="panel-heading">
            <h2><CloudDownload size={16} /> {t('updates.runtimeUpdate')}</h2>
            <Tag color={system.update.ota.enabled ? 'green' : 'gray'}>{system.update.ota.enabled ? t('system.enabled') : t('system.disabled')}</Tag>
          </div>
          <div className="site-detail-grid">
            <label className="switch-line"><span>OTA</span><Switch checked={system.update.ota.enabled} onChange={(enabled) => patchSystem({ update: { ota: { ...system.update.ota, enabled } } })} /></label>
            <label><span>{t('system.updateServer')}</span><Input value={system.update.ota.server} onChange={(server) => patchSystem({ update: { ota: { ...system.update.ota, server } } })} /></label>
            <label>
              <span>{t('system.channel')}</span>
              <Select value={system.update.ota.channel} onChange={(channel) => patchSystem({ update: { ota: { ...system.update.ota, channel: channel as string } } })}>
                <Select.Option value="stable">stable</Select.Option>
                <Select.Option value="canary">canary</Select.Option>
                <Select.Option value="dev">dev</Select.Option>
              </Select>
            </label>
            <label><span>{t('system.checkIntervalHours')}</span><InputNumber value={durationSeconds(system.update.ota.check_interval) / 3600} min={1} max={168} onChange={(value) => patchSystem({ update: { ota: { ...system.update.ota, check_interval: secondsToDuration(Number(value || 1) * 3600) } } })} /></label>
            <label className="switch-line"><span>{t('system.autoUpdateRules')}</span><Switch checked={system.update.ota.auto_update_rules} onChange={(auto_update_rules) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_rules } } })} /></label>
            <label className="switch-line"><span>{t('system.autoUpdateBinary')}</span><Switch checked={system.update.ota.auto_update_binary} onChange={(auto_update_binary) => patchSystem({ update: { ota: { ...system.update.ota, auto_update_binary } } })} /></label>
            <label className="switch-line"><span>{t('system.verifySignature')}</span><Switch checked={system.update.ota.verify_signature} onChange={(verify_signature) => patchSystem({ update: { ota: { ...system.update.ota, verify_signature } } })} /></label>
            <label className="wide-field"><span>{t('system.publicKey')}</span><Input.TextArea value={system.update.ota.public_key} autoSize={{ minRows: 3, maxRows: 6 }} onChange={(public_key) => patchSystem({ update: { ota: { ...system.update.ota, public_key } } })} /></label>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <h2><ShieldAlert size={16} /> {t('updates.vulnerabilityFeeds')}</h2>
            <Space wrap>
              <Switch checked={system.vulnerability.enabled} onChange={(enabled) => patchSystem({ vulnerability: { ...system.vulnerability, enabled } })} />
              <Button icon={<Plus size={15} />} onClick={() => addVulnerabilityFeed(setSystem)}>{t('common.add')}</Button>
            </Space>
          </div>
          <div className="feed-list feed-list-detailed">
            {system.vulnerability.feeds.map((feed, index) => (
              <div className="feed-row feed-row-detailed" key={feed.id}>
                <Switch checked={feed.enabled} onChange={(enabled) => updateVulnerabilityFeed(index, { enabled }, setSystem)} />
                <Input value={feed.name} placeholder="NVD" onChange={(name) => updateVulnerabilityFeed(index, { name }, setSystem)} />
                <Input value={feed.url} placeholder="https://..." onChange={(url) => updateVulnerabilityFeed(index, { url }, setSystem)} />
                <Select value={feed.type || 'json'} onChange={(type) => updateVulnerabilityFeed(index, { type: type as string }, setSystem)}>
                  <Select.Option value="json">JSON</Select.Option>
                  <Select.Option value="nvd">NVD</Select.Option>
                  <Select.Option value="osv">OSV</Select.Option>
                  <Select.Option value="cve">CVE</Select.Option>
                </Select>
                <Select value={feed.min_severity} onChange={(min_severity) => updateVulnerabilityFeed(index, { min_severity: min_severity as string }, setSystem)}>
                  <Select.Option value="low">{t('rules.low')}</Select.Option>
                  <Select.Option value="medium">{t('rules.medium')}</Select.Option>
                  <Select.Option value="high">{t('rules.high')}</Select.Option>
                  <Select.Option value="critical">{t('rules.critical')}</Select.Option>
                </Select>
                <InputNumber value={durationSeconds(feed.interval) / 3600} min={1} max={720} onChange={(value) => updateVulnerabilityFeed(index, { interval: secondsToDuration(Number(value || 12) * 3600) }, setSystem)} />
                <Switch checked={feed.notify} onChange={(notify) => updateVulnerabilityFeed(index, { notify }, setSystem)} />
                <Button status="danger" icon={<Trash2 size={14} />} onClick={() => removeVulnerabilityFeed(feed.id, setSystem)} />
              </div>
            ))}
            {!system.vulnerability.feeds.length && <Empty description={t('system.noFeeds')} />}
          </div>
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
