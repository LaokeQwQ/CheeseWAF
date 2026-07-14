import {
  Button,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, Database, Image, KeyRound, MapPinned, Plus, ServerCog, ShieldAlert, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  createManagementAPIToken,
  fetchSystemConfig,
  fetchManagementAPITokens,
  revokeManagementAPIToken,
  testStorageBackend,
  updateSystemConfig,
} from '../../api/client';
import i18n from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';
import type { APISecAuthConfig, APISecAuthEndpointPolicyConfig, ManagementAPIConfig, ManagementAPIToken, SystemConfig } from '../../types/api';
import { durationMilliseconds, durationSeconds, fallbackSystem, millisecondsToDuration, normalizeSystem, secondsToDuration } from './systemModel';
import './SystemPage.module.css';

export default function SystemPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const setTheme = useAppStore((state) => state.setTheme);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const [apiTokenDraft, setAPITokenDraft] = useState({ name: '', scopes: ['read:system'], ttl: '720h', notes: '' });
  const [latestAPIToken, setLatestAPIToken] = useState('');
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data } = systemQuery;
  const apiTokensQuery = useQuery({ queryKey: ['management-api-tokens'], queryFn: fetchManagementAPITokens, retry: false });

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
      queryClient.invalidateQueries({ queryKey: ['management-api-tokens'] });
      ArcoMessage.success(t('system.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const storageTestMutation = useMutation({
    mutationFn: (backend: string) => testStorageBackend(backend, system.storage),
    onSuccess: (result) => ArcoMessage.success(`${result.backend} ${t('system.testOk')}`),
    onError: (error) => ArcoMessage.error(error.message),
  });

  const patchSystem = (patch: Partial<SystemConfig>) => setSystem((current) => normalizeSystem({ ...current, ...patch }));
  const patchConsoleLogin = (patch: Partial<SystemConfig['console']['login']>) => {
    setSystem((current) => normalizeSystem({
      ...current,
      console: {
        ...current.console,
        login: {
          ...current.console.login,
          ...patch,
        },
      },
    }));
  };
  const patchConsoleMap = (patch: Partial<SystemConfig['console']['map']>) => {
    setSystem((current) => normalizeSystem({
      ...current,
      console: {
        ...current.console,
        map: {
          ...current.console.map,
          ...patch,
        },
      },
    }));
  };
  const patchChinaBoundary = (patch: Partial<SystemConfig['console']['map']['china_boundary']>) => {
    patchConsoleMap({
      china_boundary: {
        ...system.console.map.china_boundary,
        ...patch,
      },
    });
  };
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
  const managementAPI = useMemo(() => readManagementAPI(system), [system]);
  const apiTokens = apiTokensQuery.data?.items ?? managementAPI.tokens ?? [];
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
  const patchManagementAPI = (patch: Partial<ManagementAPIConfig>) => {
    setSystem((current) => {
      const management = readManagementAPI(current);
      return normalizeSystem({
        ...current,
        apisec: {
          ...current.apisec,
          management_api: { ...management, ...patch },
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
  const createAPITokenMutation = useMutation({
    mutationFn: createManagementAPIToken,
    onSuccess: (result) => {
      setLatestAPIToken(result.token);
      setAPITokenDraft({ name: '', scopes: ['read:system'], ttl: '720h', notes: '' });
      queryClient.invalidateQueries({ queryKey: ['management-api-tokens'] });
      queryClient.invalidateQueries({ queryKey: ['system'] });
      ArcoMessage.success(t('system.apiTokenCreated'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const revokeAPITokenMutation = useMutation({
    mutationFn: revokeManagementAPIToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['management-api-tokens'] });
      queryClient.invalidateQueries({ queryKey: ['system'] });
      ArcoMessage.success(t('system.apiTokenRevoked'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const submitAPIToken = () => {
    if (latestAPIToken) {
      ArcoMessage.warning(t('system.apiTokenClearBeforeCreate'));
      return;
    }
    const name = apiTokenDraft.name.trim();
    if (!name) {
      ArcoMessage.warning(t('system.apiTokenNameRequired'));
      return;
    }
    if (apiTokenDraft.scopes.length === 0) {
      ArcoMessage.warning(t('system.apiTokenScopesRequired'));
      return;
    }
    createAPITokenMutation.mutate({
      name,
      scopes: apiTokenDraft.scopes,
      ttl: apiTokenDraft.ttl || undefined,
      notes: apiTokenDraft.notes.trim() || undefined,
      enabled: true,
    });
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('system.title')}</h1>
          <p>{t('system.subtitle')}</p>
        </div>
      </header>

      <section className="panel system-settings-panel">
        <Tabs className="system-tabs" defaultActiveTab="runtime">
          <Tabs.TabPane key="runtime" title={<span className="tab-title"><ServerCog size={15} />{t('system.runtime')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.interface')}</h2>
                {systemQuery.isError && <Button onClick={() => systemQuery.refetch()} loading={systemQuery.isFetching}>{t('common.retry')}</Button>}
                <Button onClick={() => saveMutation.mutate({ server: system.server, tls: system.tls, logging: system.logging })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
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

          <Tabs.TabPane key="console" title={<span className="tab-title"><Image size={15} />{t('system.consoleLogin')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.consoleLogin')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ console: system.console })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
              </div>
              <div className="system-form-groups console-settings-grid">
                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.loginSecurity')}</strong>
                    <span>{t('system.loginSecurityHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="switch-line">
                      <span>{t('system.loginCaptchaEnabled')}</span>
                      <Switch
                        checked={system.console.login.captcha.enabled}
                        onChange={(enabled) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaMode')}</span>
                      <Select
                        value={system.console.login.captcha.mode || 'slider'}
                        onChange={(mode) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, mode: mode as string } })}
                      >
                        <Select.Option value="slider">{t('system.loginCaptchaSlider')}</Select.Option>
                        <Select.Option value="pow">{t('system.loginCaptchaPow')}</Select.Option>
                      </Select>
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaMaxNumber')}</span>
                      <InputNumber
                        min={1000}
                        max={50000000}
                        step={1000}
                        value={system.console.login.captcha.max_number}
                        onChange={(value) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, max_number: Number(value || 75000) } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaTTL')}</span>
                      <InputNumber
                        min={30}
                        max={600}
                        step={30}
                        value={durationSeconds(system.console.login.captcha.ttl)}
                        onChange={(value) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, ttl: secondsToDuration(value) } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderTolerance')}</span>
                      <InputNumber
                        min={2}
                        max={20}
                        value={system.console.login.captcha.slider.tolerance}
                        onChange={(value) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, tolerance: Number(value || 6) } } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderMinDrag')}</span>
                      <InputNumber
                        min={100}
                        max={10000}
                        step={50}
                        value={durationMilliseconds(system.console.login.captcha.slider.min_drag)}
                        onChange={(value) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, min_drag: millisecondsToDuration(value || 450) } } })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.loginSliderPowEnabled')}</span>
                      <Switch
                        checked={system.console.login.captcha.slider.pow_enabled}
                        onChange={(pow_enabled) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, pow_enabled } } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderPowMax')}</span>
                      <InputNumber
                        min={1000}
                        max={50000000}
                        step={1000}
                        disabled={!system.console.login.captcha.slider.pow_enabled}
                        value={system.console.login.captcha.slider.pow_max_number}
                        onChange={(value) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, pow_max_number: Number(value || 12000) } } })}
                      />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.securityEntry')}</strong>
                    <span>{t('system.securityEntryHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="switch-line">
                      <span>{t('system.securityEntryEnabled')}</span>
                      <Switch
                        checked={system.console.login.security_entry.enabled}
                        onChange={(enabled) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.securityEntryPath')}</span>
                      <Input
                        value={system.console.login.security_entry.path}
                        placeholder="/__cheesewaf-entry"
                        onChange={(path) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, path } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.securityEntryCookie')}</span>
                      <Input
                        value={system.console.login.security_entry.cookie_name}
                        placeholder="cheesewaf_admin_entry"
                        onChange={(cookie_name) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, cookie_name } })}
                      />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.loginBackground')}</strong>
                    <span>{t('system.loginBackgroundHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="switch-line">
                      <span>{t('system.loginBackgroundEnabled')}</span>
                      <Switch
                        checked={system.console.login.background.enabled}
                        onChange={(enabled) => patchConsoleLogin({ background: { ...system.console.login.background, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginBackgroundType')}</span>
                      <Select
                        value={system.console.login.background.type || 'auto'}
                        onChange={(type) => patchConsoleLogin({ background: { ...system.console.login.background, type: type as string } })}
                      >
                        <Select.Option value="auto">{t('system.loginBackgroundAuto')}</Select.Option>
                        <Select.Option value="image">{t('system.loginBackgroundImage')}</Select.Option>
                        <Select.Option value="video">{t('system.loginBackgroundVideo')}</Select.Option>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.loginBackgroundURL')}</span>
                      <Input
                        value={system.console.login.background.url}
                        placeholder="https://example.com/admin-bg.webp"
                        onChange={(url) => patchConsoleLogin({ background: { ...system.console.login.background, url } })}
                      />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset console-map-fieldset">
                  <header>
                    <strong><MapPinned size={15} /> {t('system.mapData')}</strong>
                    <span>{t('system.mapDataHint')}</span>
                  </header>
                  <div className="site-detail-grid console-map-grid">
                    <label className="switch-line">
                      <span>{t('system.chinaBoundaryEnabled')}</span>
                      <Switch
                        checked={system.console.map.china_boundary.enabled}
                        onChange={(enabled) => patchChinaBoundary({ enabled })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundarySourceType')}</span>
                      <Select
                        value={system.console.map.china_boundary.source_type || 'file'}
                        onChange={(source_type) => patchChinaBoundary({ source_type: source_type as string })}
                      >
                        <Select.Option value="file">{t('system.mapBoundaryFile')}</Select.Option>
                        <Select.Option value="url">{t('system.mapBoundaryURL')}</Select.Option>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.mapBoundarySource')}</span>
                      <Input
                        value={system.console.map.china_boundary.source}
                        placeholder={system.console.map.china_boundary.source_type === 'url' ? 'https://example.com/china-boundary.geojson' : './data/maps/china-boundary.geojson'}
                        onChange={(source) => patchChinaBoundary({ source })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundaryLicense')}</span>
                      <Input
                        value={system.console.map.china_boundary.license}
                        placeholder={t('system.mapBoundaryLicensePlaceholder')}
                        onChange={(license) => patchChinaBoundary({ license })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundaryReviewID')}</span>
                      <Input
                        value={system.console.map.china_boundary.review_id}
                        placeholder={t('system.mapBoundaryReviewIDPlaceholder')}
                        onChange={(review_id) => patchChinaBoundary({ review_id })}
                      />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.mapBoundaryAttribution')}</span>
                      <Input
                        value={system.console.map.china_boundary.attribution}
                        placeholder={t('system.mapBoundaryAttributionPlaceholder')}
                        onChange={(attribution) => patchChinaBoundary({ attribution })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.mapBoundaryAllowInsecure')}</span>
                      <Switch
                        checked={system.console.map.china_boundary.allow_insecure}
                        onChange={(allow_insecure) => patchChinaBoundary({ allow_insecure })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.mapBoundaryAllowPrivate')}</span>
                      <Switch
                        checked={system.console.map.china_boundary.allow_private}
                        onChange={(allow_private) => patchChinaBoundary({ allow_private })}
                      />
                    </label>
                  </div>
                </section>
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="storage" title={<span className="tab-title"><Database size={15} />{t('system.storage')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.storage')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ storage: system.storage })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
              </div>
              <div className="storage-grid">
                <StoragePanel title="SQLite" enabled action={() => storageTestMutation.mutate('sqlite')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.path')}</span><Input value={system.storage.sqlite.path} onChange={(path) => patchStorage('sqlite', { path })} /></label>
                </StoragePanel>

                <StoragePanel title="Redis" enabled={system.storage.redis.enabled} onToggle={(enabled) => patchStorage('redis', { enabled })} action={() => storageTestMutation.mutate('redis')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.address')}</span><Input value={system.storage.redis.address} onChange={(address) => patchStorage('redis', { address })} /></label>
                </StoragePanel>

                <StoragePanel title="PostgreSQL" enabled={system.storage.postgresql.enabled} onToggle={(enabled) => patchStorage('postgresql', { enabled })} action={() => storageTestMutation.mutate('postgresql')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.dsn')}</span><Input.Password value={system.storage.postgresql.dsn} onChange={(dsn) => patchStorage('postgresql', { dsn })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.postgresql.table} onChange={(table) => patchStorage('postgresql', { table })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.postgresql.timeout)} min={1} max={120} onChange={(value) => patchStorage('postgresql', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>

                <StoragePanel title="Elasticsearch" enabled={system.storage.elasticsearch.enabled} onToggle={(enabled) => patchStorage('elasticsearch', { enabled })} action={() => storageTestMutation.mutate('elasticsearch')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.elasticsearch.endpoint} onChange={(endpoint) => patchStorage('elasticsearch', { endpoint })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.elasticsearch.allow_private_endpoint} onChange={(allow_private_endpoint) => patchStorage('elasticsearch', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.index')}</span><Input value={system.storage.elasticsearch.index} onChange={(index) => patchStorage('elasticsearch', { index })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.elasticsearch.username} onChange={(username) => patchStorage('elasticsearch', { username })} /></label>
                  <label><span>{t('system.apiKey')}</span><Input.Password value={system.storage.elasticsearch.api_key} onChange={(api_key) => patchStorage('elasticsearch', { api_key })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.elasticsearch.timeout)} min={1} max={120} onChange={(value) => patchStorage('elasticsearch', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>

                <StoragePanel title="ClickHouse" enabled={system.storage.clickhouse.enabled} onToggle={(enabled) => patchStorage('clickhouse', { enabled })} action={() => storageTestMutation.mutate('clickhouse')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.clickhouse.endpoint} onChange={(endpoint) => patchStorage('clickhouse', { endpoint })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.clickhouse.allow_private_endpoint} onChange={(allow_private_endpoint) => patchStorage('clickhouse', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.database')}</span><Input value={system.storage.clickhouse.database} onChange={(database) => patchStorage('clickhouse', { database })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.clickhouse.table} onChange={(table) => patchStorage('clickhouse', { table })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.clickhouse.username} onChange={(username) => patchStorage('clickhouse', { username })} /></label>
                </StoragePanel>

                <StoragePanel title="VictoriaLogs" enabled={system.storage.victorialogs.enabled} onToggle={(enabled) => patchStorage('victorialogs', { enabled })} action={() => storageTestMutation.mutate('victorialogs')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.victorialogs.endpoint} onChange={(endpoint) => patchStorage('victorialogs', { endpoint })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.victorialogs.allow_private_endpoint} onChange={(allow_private_endpoint) => patchStorage('victorialogs', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><InputNumber value={durationSeconds(system.storage.victorialogs.timeout)} min={1} max={120} onChange={(value) => patchStorage('victorialogs', { timeout: secondsToDuration(value) })} /></label>
                </StoragePanel>
              </div>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="apisec" title={<span className="tab-title"><ShieldAlert size={15} />{t('system.apiSecurity')}</span>}>
            <div className="system-section">
              <div className="system-section-title">
                <h2><KeyRound size={16} /> {t('system.jwtAuth')}</h2>
                <Button type="primary" onClick={() => saveMutation.mutate({ apisec: system.apisec })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
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

                <section className="system-fieldset management-api-fieldset">
                  <header className="fieldset-header-action">
                    <div>
                      <strong><KeyRound size={15} /> {t('system.managementAPI')}</strong>
                      <span>{t('system.managementAPIHint')}</span>
                    </div>
                    <Switch checked={managementAPI.enabled} onChange={(enabled) => patchManagementAPI({ enabled })} />
                  </header>
                  <div className="api-token-create-grid">
                    <label>
                      <span>{t('system.apiTokenName')}</span>
                      <Input value={apiTokenDraft.name} placeholder={t('system.apiTokenNamePlaceholder')} onChange={(name) => setAPITokenDraft((draft) => ({ ...draft, name }))} />
                    </label>
                    <label>
                      <span>{t('system.apiTokenScopes')}</span>
                      <Select
                        mode="multiple"
                        allowCreate
                        value={apiTokenDraft.scopes}
                        placeholder="read:system"
                        onChange={(scopes) => setAPITokenDraft((draft) => ({ ...draft, scopes: Array.isArray(scopes) ? scopes.map(String) : [] }))}
                      >
                        {apiTokenScopeOptions.map((scope) => <Select.Option key={scope} value={scope}>{scope}</Select.Option>)}
                      </Select>
                    </label>
                    <label>
                      <span>{t('system.apiTokenTTL')}</span>
                      <Select value={apiTokenDraft.ttl} allowCreate onChange={(ttl) => setAPITokenDraft((draft) => ({ ...draft, ttl: String(ttl ?? '') }))}>
                        <Select.Option value="1h">1h</Select.Option>
                        <Select.Option value="24h">24h</Select.Option>
                        <Select.Option value="168h">7d</Select.Option>
                        <Select.Option value="720h">30d</Select.Option>
                        <Select.Option value="">{t('system.apiTokenNoExpiry')}</Select.Option>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.apiTokenNotes')}</span>
                      <Input value={apiTokenDraft.notes} placeholder={t('system.apiTokenNotesPlaceholder')} onChange={(notes) => setAPITokenDraft((draft) => ({ ...draft, notes }))} />
                    </label>
                    <Button type="primary" loading={createAPITokenMutation.isPending} disabled={!managementAPI.enabled || Boolean(latestAPIToken)} onClick={submitAPIToken}>
                      {t('system.createAPIToken')}
                    </Button>
                  </div>
                  {latestAPIToken && (
                    <div className="cluster-result-note cluster-result-note-ok api-token-secret">
                      <strong>{t('system.apiTokenSecretTitle')}</strong>
                      <span>{t('system.apiTokenSecretHint')}</span>
                      <code>{latestAPIToken}</code>
                      <div className="cluster-token-actions">
                        <Button icon={<Copy size={15} />} onClick={() => void copyText(latestAPIToken, t('system.apiTokenCopied'), t('system.apiTokenCopyFailed'))}>{t('system.copyAPIToken')}</Button>
                        <Button onClick={() => {
                          setLatestAPIToken('');
                          ArcoMessage.success(t('system.apiTokenCleared'));
                        }}>{t('system.clearAPIToken')}</Button>
                      </div>
                    </div>
                  )}
                  <Table
                    rowKey="id"
                    loading={apiTokensQuery.isFetching}
                    pagination={{ pageSize: 6, sizeCanChange: true }}
                    data={apiTokens}
                    columns={[
                      { title: t('system.apiTokenName'), dataIndex: 'name', render: (name: string, item: ManagementAPIToken) => <div className="api-token-name"><strong>{name}</strong><span>{item.prefix}</span></div> },
                      { title: t('system.apiTokenScopes'), dataIndex: 'scopes', render: (scopes: string[]) => <span className="api-token-scope-list">{(scopes || []).map((scope) => <Tag key={scope}>{scope}</Tag>)}</span> },
                      { title: t('system.apiTokenExpires'), dataIndex: 'expires_at', render: (value: string) => formatSystemTimestamp(value, t('system.apiTokenNoExpiry')) },
                      { title: t('common.status'), render: (_: unknown, item: ManagementAPIToken) => <Tag color={item.enabled ? 'green' : 'gray'}>{item.enabled ? t('system.enabled') : t('system.disabled')}</Tag> },
                      {
                        title: t('common.actions'),
                        render: (_: unknown, item: ManagementAPIToken) => (
                          <Popconfirm
                            title={t('system.apiTokenRevokeConfirmTitle')}
                            content={t('system.apiTokenRevokeConfirm')}
                            onOk={() => revokeAPITokenMutation.mutate(item.id)}
                          >
                            <Button size="mini" status="danger" disabled={!item.enabled} loading={revokeAPITokenMutation.isPending}>{t('common.revoke')}</Button>
                          </Popconfirm>
                        ),
                      },
                    ]}
                  />
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
                      <span>{t('system.jwksURL')}</span>
                      <Input value={apiAuth.jwks_url} placeholder="https://issuer.example.com/.well-known/jwks.json" onChange={(jwks_url) => patchAPIAuth({ jwks_url })} />
                    </label>
                    <label>
                      <span>{t('system.jwksCacheFile')}</span>
                      <Input value={apiAuth.jwks_cache_file} onChange={(jwks_cache_file) => patchAPIAuth({ jwks_cache_file })} />
                    </label>
                    <label>
                      <span>{t('system.jwksRefreshInterval')}</span>
                      <InputNumber
                        min={60}
                        step={60}
                        value={durationSeconds(apiAuth.jwks_refresh_interval)}
                        onChange={(value) => patchAPIAuth({ jwks_refresh_interval: secondsToDuration(Number(value || 0)) })}
                      />
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
    jwks_url: stringValue(auth.jwks_url),
    jwks_cache_file: stringValue(auth.jwks_cache_file) || './data/apisec-jwks-cache.json',
    jwks_refresh_interval: auth.jwks_refresh_interval ?? 60 * 60 * 1_000_000_000,
  };
}

function readManagementAPI(system: SystemConfig): ManagementAPIConfig {
  const management = system.apisec.management_api ?? {};
  return {
    enabled: Boolean(management.enabled),
    tokens: Array.isArray(management.tokens) ? management.tokens : [],
  };
}

const apiTokenScopeOptions = [
  'read:system',
  'write:system',
  'read:monitor',
  'read:logs',
  'read:sites',
  'write:sites',
  'read:rules',
  'write:rules',
  'read:protection',
  'write:protection',
  'read:apisec',
  'write:apisec',
  'read:ai',
  'write:ai',
  'read:*',
  'write:*',
];

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

async function copyText(value: string, successMessage: string, failureMessage: string) {
  try {
    await navigator.clipboard.writeText(value);
    ArcoMessage.success(successMessage);
  } catch {
    ArcoMessage.error(failureMessage);
  }
}

function formatSystemTimestamp(value: string | undefined, fallback = '') {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
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
