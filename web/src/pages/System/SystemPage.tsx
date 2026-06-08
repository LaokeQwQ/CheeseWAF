import {
  Button,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Modal,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Database, KeyRound, LockKeyhole, Plus, ServerCog, ShieldAlert, Trash2, UserRound } from 'lucide-react';
import QRCode from 'qrcode';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
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
import type { APISecAuthConfig, APISecAuthEndpointPolicyConfig, SystemConfig, TOTPSetup } from '../../types/api';
import { durationSeconds, fallbackSystem, normalizeSystem, secondsToDuration } from './systemModel';

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
  const apiAuth = useMemo(() => readAPIAuth(system), [system]);
  const patchAPISec = (patch: Partial<SystemConfig['apisec']>) => {
    setSystem((current) => normalizeSystem({ ...current, apisec: { ...current.apisec, ...patch } }));
  };
  const patchAPIAuth = (patch: Partial<APISecAuthConfig>) => {
    setSystem((current) => {
      const auth = readAPIAuth(current);
      return normalizeSystem({
        ...current,
        apisec: {
          ...current.apisec,
          auth: { ...auth, ...patch },
        },
      });
    });
  };
  const patchAPIAuthEndpoint = (index: number, patch: Partial<APISecAuthEndpointPolicyConfig>) => {
    const endpointPolicies = apiAuth.endpoint_policies.map((policy, policyIndex) => (
      policyIndex === index ? { ...policy, ...patch } : policy
    ));
    patchAPIAuth({ endpoint_policies: endpointPolicies });
  };
  const addAPIAuthEndpoint = () => {
    patchAPIAuth({
      endpoint_policies: [
        ...apiAuth.endpoint_policies,
        {
          id: `api-auth-${apiAuth.endpoint_policies.length + 1}`,
          method: 'GET',
          path_pattern: '^/api/',
          jwt_issuers: [],
          jwt_audiences: [],
          required_scopes: [],
          enabled: true,
        },
      ],
    });
  };
  const removeAPIAuthEndpoint = (index: number) => {
    patchAPIAuth({ endpoint_policies: apiAuth.endpoint_policies.filter((_, policyIndex) => policyIndex !== index) });
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

      <section className="panel system-settings-panel">
        <Tabs className="system-tabs" defaultActiveTab="runtime">
          <Tabs.TabPane key="runtime" title={<span className="tab-title"><ServerCog size={15} />{t('system.runtime')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.interface')}</h2>
                <Button onClick={() => saveMutation.mutate({ server: system.server, tls: system.tls, logging: system.logging })} loading={saveMutation.isPending}>{t('common.save')}</Button>
              </div>
              <div className="system-form-groups">
                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.runtime')}</strong>
                    <span>{t('system.runtimeHint')}</span>
                  </header>
                  <div className="site-detail-grid system-runtime-grid">
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
                    <label className="switch-line"><span>{t('system.adminPublic')}</span><Switch checked={system.server.admin_public} onChange={(admin_public) => patchSystem({ server: { ...system.server, admin_public } })} /></label>
                    <label className="switch-line"><span>HTTP/3</span><Switch checked={system.server.http3.enabled} onChange={(enabled) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, enabled } } })} /></label>
                    <label className="switch-line"><span>0-RTT</span><Switch checked={system.server.http3.zero_rtt} onChange={(zero_rtt) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, zero_rtt } } })} /></label>
                  </div>
                </section>
                <section className="system-fieldset">
                  <header>
                    <strong>TLS</strong>
                    <span>{t('system.tlsHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="switch-line"><span>{t('system.adminTls')}</span><Switch checked={system.server.admin_tls.enabled} onChange={(enabled) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, enabled } } })} /></label>
                    <label><span>{t('system.adminTlsCert')}</span><Input value={system.server.admin_tls.cert_file} onChange={(cert_file) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, cert_file } } })} /></label>
                    <label><span>{t('system.adminTlsKey')}</span><Input value={system.server.admin_tls.key_file} onChange={(key_file) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, key_file } } })} /></label>
                    <label className="switch-line"><span>{t('system.autoCert')}</span><Switch checked={system.tls.auto_cert} onChange={(auto_cert) => patchSystem({ tls: { ...system.tls, auto_cert } })} /></label>
                    <label className="switch-line"><span>HSTS</span><Switch checked={system.tls.hsts} onChange={(hsts) => patchSystem({ tls: { ...system.tls, hsts } })} /></label>
                    <label><span>{t('sites.certFile')}</span><Input value={system.tls.cert_file} onChange={(cert_file) => patchSystem({ tls: { ...system.tls, cert_file } })} /></label>
                    <label><span>{t('sites.keyFile')}</span><Input value={system.tls.key_file} onChange={(key_file) => patchSystem({ tls: { ...system.tls, key_file } })} /></label>
                  </div>
                </section>
                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.logging')}</strong>
                    <span>{t('system.loggingHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label><span>{t('system.logPath')}</span><Input value={system.logging.output.file.path} onChange={(path) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, path } } } })} /></label>
                    <label><span>{t('system.logMaxBackups')}</span><InputNumber value={system.logging.output.file.max_backups} min={1} max={365} onChange={(max_backups) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, max_backups: Number(max_backups || 1) } } } })} /></label>
                  </div>
                </section>
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

          <Tabs.TabPane key="apisec" title={<span className="tab-title"><ShieldAlert size={15} />{t('system.apiSecurity')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2><KeyRound size={16} /> {t('system.jwtAuth')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ apisec: system.apisec })} loading={saveMutation.isPending}>{t('common.save')}</Button>
              </div>
              <div className="system-form-groups">
                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.apiSecurity')}</strong>
                    <span>{t('system.apiSecurityHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="switch-line">
                      <span>{t('system.apiSecurityEnabled')}</span>
                      <Switch checked={Boolean(system.apisec.enabled)} onChange={(enabled) => patchAPISec({ enabled })} />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.jwtAuthEnabled')}</span>
                      <Switch checked={apiAuth.enabled} onChange={(enabled) => patchAPIAuth({ enabled })} />
                    </label>
                    <label>
                      <span>{t('system.jwtAlgorithms')}</span>
                      <Input value={joinList(apiAuth.jwt_algorithms)} placeholder="HS256, RS256" onChange={(value) => patchAPIAuth({ jwt_algorithms: splitList(value) })} />
                    </label>
                    <label>
                      <span>{t('system.jwtIssuers')}</span>
                      <Input value={joinList(apiAuth.jwt_issuers)} placeholder="https://issuer.example.com" onChange={(value) => patchAPIAuth({ jwt_issuers: splitList(value) })} />
                    </label>
                    <label>
                      <span>{t('system.jwtAudiences')}</span>
                      <Input value={joinList(apiAuth.jwt_audiences)} placeholder="orders-api, admin-api" onChange={(value) => patchAPIAuth({ jwt_audiences: splitList(value) })} />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.requiredScopes')}</span>
                      <Input value={joinList(apiAuth.required_scopes)} placeholder="orders:read, admin:read" onChange={(value) => patchAPIAuth({ required_scopes: splitList(value) })} />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset">
                  <header className="fieldset-header-action">
                    <div>
                      <strong>{t('system.apiAuthEndpointPolicies')}</strong>
                      <span>{t('system.apiAuthEndpointPoliciesHint')}</span>
                    </div>
                    <Button size="small" icon={<Plus size={14} />} onClick={addAPIAuthEndpoint}>{t('common.add')}</Button>
                  </header>
                  <div className="endpoint-policy-list">
                    {apiAuth.endpoint_policies.length === 0 ? (
                      <div className="empty-state"><ShieldAlert size={16} /> {t('system.noEndpointPolicies')}</div>
                    ) : apiAuth.endpoint_policies.map((policy, index) => (
                      <section className="endpoint-policy-row" key={`${policy.id}-${index}`}>
                        <div className="endpoint-policy-head">
                          <Switch checked={policy.enabled} onChange={(enabled) => patchAPIAuthEndpoint(index, { enabled })} />
                          <Input value={policy.id} placeholder="orders-write" onChange={(id) => patchAPIAuthEndpoint(index, { id })} />
                          <Button size="mini" status="danger" icon={<Trash2 size={13} />} onClick={() => removeAPIAuthEndpoint(index)}>{t('common.delete')}</Button>
                        </div>
                        <div className="site-detail-grid">
                          <label>
                            <span>{t('apisec.method')}</span>
                            <Select value={policy.method || 'GET'} onChange={(method) => patchAPIAuthEndpoint(index, { method: method as string })}>
                              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((method) => (
                                <Select.Option key={method} value={method}>{method}</Select.Option>
                              ))}
                            </Select>
                          </label>
                          <label>
                            <span>{t('system.pathPattern')}</span>
                            <Input value={policy.path_pattern} placeholder="^/api/orders$" onChange={(path_pattern) => patchAPIAuthEndpoint(index, { path_pattern })} />
                          </label>
                          <label>
                            <span>{t('system.jwtIssuers')}</span>
                            <Input value={joinList(policy.jwt_issuers)} onChange={(value) => patchAPIAuthEndpoint(index, { jwt_issuers: splitList(value) })} />
                          </label>
                          <label>
                            <span>{t('system.jwtAudiences')}</span>
                            <Input value={joinList(policy.jwt_audiences)} onChange={(value) => patchAPIAuthEndpoint(index, { jwt_audiences: splitList(value) })} />
                          </label>
                          <label className="wide-field">
                            <span>{t('system.requiredScopes')}</span>
                            <Input value={joinList(policy.required_scopes)} onChange={(value) => patchAPIAuthEndpoint(index, { required_scopes: splitList(value) })} />
                          </label>
                        </div>
                      </section>
                    ))}
                  </div>
                </section>

                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.jwtVerificationKeys')}</strong>
                    <span>{t('system.jwtVerificationKeysHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label>
                      <span>{t('system.jwtSharedSecret')}</span>
                      <Input.Password value={apiAuth.jwt_shared_secret} onChange={(jwt_shared_secret) => patchAPIAuth({ jwt_shared_secret })} />
                    </label>
                    <label>
                      <span>{t('system.jwtPublicKeyFile')}</span>
                      <Input value={apiAuth.jwt_public_key_file} onChange={(jwt_public_key_file) => patchAPIAuth({ jwt_public_key_file })} />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.jwtPublicKeyPEM')}</span>
                      <Input.TextArea
                        autoSize={{ minRows: 3, maxRows: 7 }}
                        value={apiAuth.jwt_public_key_pem}
                        onChange={(jwt_public_key_pem) => patchAPIAuth({ jwt_public_key_pem })}
                      />
                    </label>
                    <label>
                      <span>{t('system.jwksFile')}</span>
                      <Input value={apiAuth.jwks_file} onChange={(jwks_file) => patchAPIAuth({ jwks_file })} />
                    </label>
                    <label>
                      <span>{t('system.jwksJSON')}</span>
                      <Input.TextArea
                        autoSize={{ minRows: 3, maxRows: 7 }}
                        value={apiAuth.jwks_json}
                        onChange={(jwks_json) => patchAPIAuth({ jwks_json })}
                      />
                    </label>
                  </div>
                </section>
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
                  <label className="switch-line">
                    <span>{t('system.twoFAStatus')}</span>
                    <Switch
                      checked={Boolean(selectedUser?.two_fa_enabled)}
                      disabled={!selectedUser || twoFASetupMutation.isPending || twoFADisableMutation.isPending}
                      loading={twoFASetupMutation.isPending || twoFADisableMutation.isPending}
                      onChange={(checked) => {
                        if (!twoFA.userId) {
                          return;
                        }
                        if (checked) {
                          twoFASetupMutation.mutate(twoFA.userId);
                          return;
                        }
                        Modal.confirm({
                          title: t('system.disable2FAConfirmTitle'),
                          content: t('system.disable2FAConfirm'),
                          okText: t('system.disable2FA'),
                          cancelText: t('common.back'),
                          okButtonProps: { status: 'danger' },
                          onOk: () => twoFADisableMutation.mutate(),
                        });
                      }}
                    />
                  </label>
                </div>
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

function readAPIAuth(system: SystemConfig): APISecAuthConfig {
  const auth = system.apisec.auth ?? {};
  return {
    enabled: Boolean(auth.enabled),
    jwt_issuers: listValue(auth.jwt_issuers),
    jwt_audiences: listValue(auth.jwt_audiences),
    required_scopes: listValue(auth.required_scopes),
    endpoint_policies: endpointPoliciesValue(auth.endpoint_policies),
    jwt_algorithms: listValue(auth.jwt_algorithms),
    jwt_shared_secret: stringValue(auth.jwt_shared_secret),
    jwt_public_key_file: stringValue(auth.jwt_public_key_file),
    jwt_public_key_pem: stringValue(auth.jwt_public_key_pem),
    jwks_file: stringValue(auth.jwks_file),
    jwks_json: stringValue(auth.jwks_json),
  };
}

function endpointPoliciesValue(value: unknown): APISecAuthEndpointPolicyConfig[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item, index) => {
    const record = item && typeof item === 'object' ? item as Partial<APISecAuthEndpointPolicyConfig> : {};
    return {
      id: stringValue(record.id) || `api-auth-${index + 1}`,
      method: stringValue(record.method) || 'GET',
      path_pattern: stringValue(record.path_pattern) || '^/api/',
      jwt_issuers: listValue(record.jwt_issuers),
      jwt_audiences: listValue(record.jwt_audiences),
      required_scopes: listValue(record.required_scopes),
      enabled: record.enabled !== false,
    };
  });
}

function listValue(value: unknown) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  return splitList(String(value ?? ''));
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : '';
}

function splitList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinList(value: string[]) {
  return value.join(', ');
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
    <section className="system-card storage-card">
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
