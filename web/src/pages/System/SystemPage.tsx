import {
  Button,
  Empty,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CloudDownload, Database, KeyRound, LockKeyhole, ServerCog, ShieldAlert, UserRound } from 'lucide-react';
import QRCode from 'qrcode';
import { useEffect, useMemo, useState, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import {
  disableUser2FA,
  enableUser2FA,
  fetchSystemConfig,
  fetchUsers,
  setupUser2FA,
  testStorageBackend,
  updateSystemConfig,
} from '../../api/client';
import i18n from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';
import type { SystemConfig, TOTPSetup } from '../../types/api';

const second = 1_000_000_000;

const fallbackSystem: SystemConfig = {
  server: {
    listen: ':80',
    listen_tls: ':443',
    listen_http3: ':443',
    admin_listen: '127.0.0.1:9443',
    read_timeout: 15 * second,
    write_timeout: 30 * second,
    idle_timeout: 60 * second,
    http3: { enabled: false, zero_rtt: false },
  },
  tls: { auto_cert: false, cert_file: '', key_file: '', min_version: '1.3', hsts: true },
  storage: {
    sqlite: { path: './data/cheesewaf.db' },
    redis: { enabled: false, address: '127.0.0.1:6379' },
    clickhouse: { enabled: false, endpoint: '', database: 'cheesewaf', table: 'waf_logs', username: '', password: '', timeout: 5 * second },
    victorialogs: { enabled: false, endpoint: '', timeout: 5 * second },
    postgresql: { enabled: false, dsn: '', table: 'waf_logs', timeout: 5 * second },
    elasticsearch: { enabled: false, endpoint: '', index: 'cheesewaf-logs', username: '', password: '', api_key: '', headers: {}, timeout: 5 * second },
  },
  logging: { level: 'info', format: 'json', output: { type: 'file', file: { path: './logs/access.log', max_size: '100MB', max_backups: 10 } } },
  update: {
    ota: {
      enabled: false,
      server: '',
      channel: 'stable',
      check_interval: 6 * 60 * 60 * second,
      auto_update_rules: true,
      auto_update_binary: false,
      verify_signature: true,
      public_key: '',
    },
  },
  vulnerability: { enabled: false, feeds: [] },
  monitor: {},
  apisec: {},
};

export default function SystemPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const setTheme = useAppStore((state) => state.setTheme);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const [twoFA, setTwoFA] = useState<{ userId: string; setup?: TOTPSetup; qr?: string; code: string }>({ userId: '', code: '' });
  const { data } = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: fetchUsers, retry: false });

  useEffect(() => {
    if (data) {
      setSystem(normalizeSystem(data));
    }
  }, [data]);
  useEffect(() => {
    if (users?.length && !twoFA.userId) {
      setTwoFA((current) => ({ ...current, userId: users[0].id }));
    }
  }, [twoFA.userId, users]);

  const selectedUser = useMemo(() => users?.find((user) => user.id === twoFA.userId), [twoFA.userId, users]);
  const saveMutation = useMutation({
    mutationFn: updateSystemConfig,
    onSuccess: (saved) => {
      setSystem(normalizeSystem(saved));
      queryClient.invalidateQueries({ queryKey: ['system'] });
      ArcoMessage.success(t('system.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const storageTestMutation = useMutation({
    mutationFn: (backend: string) => testStorageBackend(backend, system.storage),
    onSuccess: (result) => ArcoMessage.success(`${result.backend} ${t('system.testOk')}`),
    onError: (error) => ArcoMessage.error(error.message),
  });
  const twoFASetupMutation = useMutation({
    mutationFn: setupUser2FA,
    onSuccess: async (setup) => {
      const qr = await QRCode.toDataURL(setup.otpauth_url, { margin: 1, width: 180 });
      setTwoFA((current) => ({ ...current, setup, qr, code: '' }));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const twoFAEnableMutation = useMutation({
    mutationFn: () => enableUser2FA(twoFA.userId, twoFA.setup?.secret ?? '', twoFA.code),
    onSuccess: () => {
      ArcoMessage.success(t('system.twoFAEnabled'));
      setTwoFA((current) => ({ ...current, setup: undefined, qr: undefined, code: '' }));
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const twoFADisableMutation = useMutation({
    mutationFn: () => disableUser2FA(twoFA.userId),
    onSuccess: () => {
      ArcoMessage.success(t('system.twoFADisabled'));
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const patchSystem = (patch: Partial<SystemConfig>) => setSystem((current) => normalizeSystem({ ...current, ...patch }));
  const patchStorage = <K extends keyof SystemConfig['storage']>(key: K, patch: Partial<SystemConfig['storage'][K]>) => {
    setSystem((current) => ({
      ...current,
      storage: {
        ...current.storage,
        [key]: {
          ...(current.storage[key] as Record<string, unknown>),
          ...(patch as Record<string, unknown>),
        } as SystemConfig['storage'][K],
      },
    }));
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('system.title')}</h1>
          <p>{t('system.subtitle')}</p>
        </div>
        <Button type="primary" onClick={() => saveMutation.mutate(system)} loading={saveMutation.isPending}>
          {t('common.save')}
        </Button>
      </header>

      <section className="panel">
        <Tabs defaultActiveTab="runtime">
          <Tabs.TabPane key="runtime" title={<span className="tab-title"><ServerCog size={15} />{t('system.runtime')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.interface')}</h2>
                <Button onClick={() => saveMutation.mutate({ server: system.server, tls: system.tls, logging: system.logging })} loading={saveMutation.isPending}>{t('common.save')}</Button>
              </div>
              <div className="site-detail-grid">
                <label>
                  <span>{t('system.theme')}</span>
                  <Select value={theme} onChange={(value) => setTheme(value as ThemeName)}>
                    {themeOptions.map((option) => <Select.Option key={option.value} value={option.value}>{t(option.labelKey)}</Select.Option>)}
                  </Select>
                </label>
                <label>
                  <span>{t('system.language')}</span>
                  <Select
                    value={language}
                    onChange={(value) => {
                      const next = value as Language;
                      setLanguage(next);
                      i18n.changeLanguage(next);
                    }}
                  >
                    <Select.Option value="zh-CN">中文</Select.Option>
                    <Select.Option value="en-US">English</Select.Option>
                  </Select>
                </label>
                <label><span>HTTP</span><Input value={system.server.listen} onChange={(listen) => patchSystem({ server: { ...system.server, listen } })} /></label>
                <label><span>HTTPS</span><Input value={system.server.listen_tls} onChange={(listen_tls) => patchSystem({ server: { ...system.server, listen_tls } })} /></label>
                <label><span>HTTP/3 UDP</span><Input value={system.server.listen_http3} onChange={(listen_http3) => patchSystem({ server: { ...system.server, listen_http3 } })} /></label>
                <label><span>{t('system.adminListen')}</span><Input value={system.server.admin_listen} onChange={(admin_listen) => patchSystem({ server: { ...system.server, admin_listen } })} /></label>
                <label className="switch-line"><span>HTTP/3</span><Switch checked={system.server.http3.enabled} onChange={(enabled) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, enabled } } })} /></label>
                <label className="switch-line"><span>0-RTT</span><Switch checked={system.server.http3.zero_rtt} onChange={(zero_rtt) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, zero_rtt } } })} /></label>
                <label className="switch-line"><span>{t('system.autoCert')}</span><Switch checked={system.tls.auto_cert} onChange={(auto_cert) => patchSystem({ tls: { ...system.tls, auto_cert } })} /></label>
                <label className="switch-line"><span>HSTS</span><Switch checked={system.tls.hsts} onChange={(hsts) => patchSystem({ tls: { ...system.tls, hsts } })} /></label>
                <label><span>{t('sites.certFile')}</span><Input value={system.tls.cert_file} onChange={(cert_file) => patchSystem({ tls: { ...system.tls, cert_file } })} /></label>
                <label><span>{t('sites.keyFile')}</span><Input value={system.tls.key_file} onChange={(key_file) => patchSystem({ tls: { ...system.tls, key_file } })} /></label>
                <label><span>{t('system.logPath')}</span><Input value={system.logging.output.file.path} onChange={(path) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, path } } } })} /></label>
                <label><span>{t('system.logMaxBackups')}</span><InputNumber value={system.logging.output.file.max_backups} min={1} max={365} onChange={(max_backups) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, max_backups: Number(max_backups || 1) } } } })} /></label>
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="storage" title={<span className="tab-title"><Database size={15} />{t('system.storage')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.storage')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ storage: system.storage })} loading={saveMutation.isPending}>{t('common.save')}</Button>
              </div>
              <div className="storage-grid">
                <StoragePanel title="SQLite" enabled action={() => storageTestMutation.mutate('sqlite')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.path')}</span><Input value={system.storage.sqlite.path} onChange={(path) => patchStorage('sqlite', { path })} /></label>
                </StoragePanel>

                <StoragePanel title="Redis" enabled={system.storage.redis.enabled} onToggle={(enabled) => patchStorage('redis', { enabled })} action={() => storageTestMutation.mutate('redis')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.address')}</span><Input value={system.storage.redis.address} onChange={(address) => patchStorage('redis', { address })} /></label>
                </StoragePanel>

                <StoragePanel title="PostgreSQL" enabled={system.storage.postgresql.enabled} onToggle={(enabled) => patchStorage('postgresql', { enabled })} action={() => storageTestMutation.mutate('postgresql')} loading={storageTestMutation.isPending}>
                  <label><span>DSN</span><Input.Password value={system.storage.postgresql.dsn} onChange={(dsn) => patchStorage('postgresql', { dsn })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.postgresql.table} onChange={(table) => patchStorage('postgresql', { table })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.postgresql.timeout)} min={1} max={120} onChange={(value) => patchStorage('postgresql', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>

                <StoragePanel title="Elasticsearch" enabled={system.storage.elasticsearch.enabled} onToggle={(enabled) => patchStorage('elasticsearch', { enabled })} action={() => storageTestMutation.mutate('elasticsearch')} loading={storageTestMutation.isPending}>
                  <label><span>Endpoint</span><Input value={system.storage.elasticsearch.endpoint} onChange={(endpoint) => patchStorage('elasticsearch', { endpoint })} /></label>
                  <label><span>Index</span><Input value={system.storage.elasticsearch.index} onChange={(index) => patchStorage('elasticsearch', { index })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.elasticsearch.username} onChange={(username) => patchStorage('elasticsearch', { username })} /></label>
                  <label><span>API Key</span><Input.Password value={system.storage.elasticsearch.api_key} onChange={(api_key) => patchStorage('elasticsearch', { api_key })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.elasticsearch.timeout)} min={1} max={120} onChange={(value) => patchStorage('elasticsearch', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>

                <StoragePanel title="ClickHouse" enabled={system.storage.clickhouse.enabled} onToggle={(enabled) => patchStorage('clickhouse', { enabled })} action={() => storageTestMutation.mutate('clickhouse')} loading={storageTestMutation.isPending}>
                  <label><span>Endpoint</span><Input value={system.storage.clickhouse.endpoint} onChange={(endpoint) => patchStorage('clickhouse', { endpoint })} /></label>
                  <label><span>Database</span><Input value={system.storage.clickhouse.database} onChange={(database) => patchStorage('clickhouse', { database })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.clickhouse.table} onChange={(table) => patchStorage('clickhouse', { table })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.clickhouse.username} onChange={(username) => patchStorage('clickhouse', { username })} /></label>
                </StoragePanel>

                <StoragePanel title="VictoriaLogs" enabled={system.storage.victorialogs.enabled} onToggle={(enabled) => patchStorage('victorialogs', { enabled })} action={() => storageTestMutation.mutate('victorialogs')} loading={storageTestMutation.isPending}>
                  <label><span>Endpoint</span><Input value={system.storage.victorialogs.endpoint} onChange={(endpoint) => patchStorage('victorialogs', { endpoint })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.victorialogs.timeout)} min={1} max={120} onChange={(value) => patchStorage('victorialogs', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="updates" title={<span className="tab-title"><CloudDownload size={15} />{t('system.updates')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.updates')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ update: system.update, vulnerability: system.vulnerability })} loading={saveMutation.isPending}>{t('common.save')}</Button>
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
                <label className="wide-field"><span>{t('system.publicKey')}</span><Input.TextArea value={system.update.ota.public_key} autoSize={{ minRows: 2, maxRows: 5 }} onChange={(public_key) => patchSystem({ update: { ota: { ...system.update.ota, public_key } } })} /></label>
                <label className="switch-line"><span>{t('system.vulnerabilityFeeds')}</span><Switch checked={system.vulnerability.enabled} onChange={(enabled) => patchSystem({ vulnerability: { ...system.vulnerability, enabled } })} /></label>
              </div>
              <div className="rewrite-toolbar">
                <Button onClick={() => addVulnerabilityFeed(system, setSystem)}>{t('common.add')}</Button>
              </div>
              <div className="feed-list">
                {system.vulnerability.feeds.map((feed, index) => (
                  <div className="feed-row" key={feed.id}>
                    <Switch checked={feed.enabled} onChange={(enabled) => updateVulnerabilityFeed(index, { enabled }, setSystem)} />
                    <Input value={feed.name} placeholder="NVD" onChange={(name) => updateVulnerabilityFeed(index, { name }, setSystem)} />
                    <Input value={feed.url} placeholder="https://..." onChange={(url) => updateVulnerabilityFeed(index, { url }, setSystem)} />
                    <Select value={feed.min_severity} onChange={(min_severity) => updateVulnerabilityFeed(index, { min_severity: min_severity as string }, setSystem)}>
                      <Select.Option value="low">{t('rules.low')}</Select.Option>
                      <Select.Option value="medium">{t('rules.medium')}</Select.Option>
                      <Select.Option value="high">{t('rules.high')}</Select.Option>
                      <Select.Option value="critical">{t('rules.critical')}</Select.Option>
                    </Select>
                    <Button status="danger" onClick={() => removeVulnerabilityFeed(feed.id, setSystem)}>{t('common.delete')}</Button>
                  </div>
                ))}
                {!system.vulnerability.feeds.length && <Empty description={t('system.noFeeds')} />}
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="users" title={<span className="tab-title"><UserRound size={15} />{t('users.title')}</span>}>
            <div className="settings-grid">
              <section className="system-card">
                <div className="system-section-title">
                  <h2>{t('system.twoFA')}</h2>
                  {selectedUser?.two_fa_enabled ? <Tag color="green">{t('system.enabled')}</Tag> : <Tag color="gray">{t('system.disabled')}</Tag>}
                </div>
                <div className="site-detail-grid">
                  <label>
                    <span>{t('users.user')}</span>
                    <Select value={twoFA.userId} onChange={(userId) => setTwoFA({ userId: userId as string, code: '' })}>
                      {(users ?? []).map((user) => <Select.Option key={user.id} value={user.id}>{user.username} / {user.role}</Select.Option>)}
                    </Select>
                  </label>
                  <label className="switch-line"><span>{t('system.twoFAStatus')}</span><Switch checked={Boolean(selectedUser?.two_fa_enabled)} disabled /></label>
                </div>
                <Space wrap>
                  <Button icon={<KeyRound size={15} />} disabled={!twoFA.userId} loading={twoFASetupMutation.isPending} onClick={() => twoFASetupMutation.mutate(twoFA.userId)}>
                    {t('system.setup2FA')}
                  </Button>
                  <Button status="danger" disabled={!selectedUser?.two_fa_enabled} loading={twoFADisableMutation.isPending} onClick={() => twoFADisableMutation.mutate()}>
                    {t('system.disable2FA')}
                  </Button>
                </Space>
              </section>
              <section className="system-card">
                <div className="system-section-title">
                  <h2><LockKeyhole size={16} /> {t('system.verify2FA')}</h2>
                </div>
                {twoFA.setup ? (
                  <div className="twofa-setup">
                    {twoFA.qr && <img src={twoFA.qr} alt="2FA QR" />}
                    <code>{twoFA.setup.secret}</code>
                    <Input value={twoFA.code} placeholder="000000" maxLength={6} onChange={(code) => setTwoFA((current) => ({ ...current, code }))} />
                    <Button type="primary" disabled={twoFA.code.length !== 6} loading={twoFAEnableMutation.isPending} onClick={() => twoFAEnableMutation.mutate()}>
                      {t('system.enable2FA')}
                    </Button>
                  </div>
                ) : (
                  <div className="empty-state"><ShieldAlert size={16} /> {t('system.twoFAGuide')}</div>
                )}
              </section>
            </div>
          </Tabs.TabPane>
        </Tabs>
      </section>
    </section>
  );
}

function StoragePanel({
  title,
  enabled,
  onToggle,
  action,
  loading,
  children,
}: {
  title: string;
  enabled: boolean;
  onToggle?: (enabled: boolean) => void;
  action: () => void;
  loading: boolean;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <section className="system-card">
      <div className="system-section-title">
        <h2>{title}</h2>
        <Space>
          {onToggle && <Switch checked={enabled} onChange={onToggle} />}
          <Button size="small" onClick={action} loading={loading}>{t('system.test')}</Button>
        </Space>
      </div>
      <div className="storage-card-body">{children}</div>
    </section>
  );
}

function normalizeSystem(input?: Partial<SystemConfig>): SystemConfig {
  const next = input ?? fallbackSystem;
  return {
    ...fallbackSystem,
    ...next,
    server: { ...fallbackSystem.server, ...next.server, http3: { ...fallbackSystem.server.http3, ...next.server?.http3 } },
    tls: { ...fallbackSystem.tls, ...next.tls },
    storage: {
      sqlite: { ...fallbackSystem.storage.sqlite, ...next.storage?.sqlite },
      redis: { ...fallbackSystem.storage.redis, ...next.storage?.redis },
      clickhouse: { ...fallbackSystem.storage.clickhouse, ...next.storage?.clickhouse },
      victorialogs: { ...fallbackSystem.storage.victorialogs, ...next.storage?.victorialogs },
      postgresql: { ...fallbackSystem.storage.postgresql, ...next.storage?.postgresql },
      elasticsearch: { ...fallbackSystem.storage.elasticsearch, ...next.storage?.elasticsearch, headers: next.storage?.elasticsearch?.headers ?? {} },
    },
    logging: {
      ...fallbackSystem.logging,
      ...next.logging,
      output: {
        ...fallbackSystem.logging.output,
        ...next.logging?.output,
        file: { ...fallbackSystem.logging.output.file, ...next.logging?.output?.file },
      },
    },
    update: { ota: { ...fallbackSystem.update.ota, ...next.update?.ota } },
    vulnerability: { ...fallbackSystem.vulnerability, ...next.vulnerability, feeds: Array.isArray(next.vulnerability?.feeds) ? next.vulnerability.feeds : [] },
    monitor: next.monitor ?? {},
    apisec: next.apisec ?? {},
  };
}

function durationSeconds(value: number | string | undefined) {
  if (typeof value === 'number') {
    return Math.max(0, Math.round(value / second));
  }
  const raw = String(value ?? '').trim();
  if (!raw) {
    return 0;
  }
  if (raw.endsWith('ms')) {
    return Math.round(Number(raw.slice(0, -2)) / 1000);
  }
  if (raw.endsWith('m')) {
    return Number(raw.slice(0, -1)) * 60;
  }
  if (raw.endsWith('h')) {
    return Number(raw.slice(0, -1)) * 3600;
  }
  if (raw.endsWith('s')) {
    return Number(raw.slice(0, -1));
  }
  return Number(raw) || 0;
}

function secondsToDuration(value: number | string | null | undefined) {
  return Math.max(1, Number(value || 1)) * second;
}

function addVulnerabilityFeed(system: SystemConfig, setSystem: Dispatch<SetStateAction<SystemConfig>>) {
  setSystem({
    ...system,
    vulnerability: {
      ...system.vulnerability,
      feeds: [
        ...system.vulnerability.feeds,
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
  });
}

function updateVulnerabilityFeed(index: number, patch: Partial<SystemConfig['vulnerability']['feeds'][number]>, setSystem: Dispatch<SetStateAction<SystemConfig>>) {
  setSystem((current) => ({
    ...current,
    vulnerability: {
      ...current.vulnerability,
      feeds: current.vulnerability.feeds.map((feed, feedIndex) => (feedIndex === index ? { ...feed, ...patch } : feed)),
    },
  }));
}

function removeVulnerabilityFeed(id: string, setSystem: Dispatch<SetStateAction<SystemConfig>>) {
  setSystem((current) => ({
    ...current,
    vulnerability: {
      ...current.vulnerability,
      feeds: current.vulnerability.feeds.filter((feed) => feed.id !== id),
    },
  }));
}
