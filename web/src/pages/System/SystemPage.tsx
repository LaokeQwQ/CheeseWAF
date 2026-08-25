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
import { Copy, Database, Image, KeyRound, MapPinned, Plus, ServerCog, ShieldAlert, Trash2 } from 'lucide-react';
import { useMemo, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  createManagementAPIToken,
  fetchSystemConfig,
  fetchManagementAPITokens,
  revokeManagementAPIToken,
  testStorageBackend,
  updateSystemConfig,
} from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { useServerDraft } from '../../hooks/useServerDraft';
import i18n from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';
import type { APISecAuthConfig, APISecAuthEndpointPolicyConfig, ManagementAPIConfig, ManagementAPIToken, SystemConfig } from '../../types/api';
import { durationMilliseconds, durationSeconds, fallbackSystem, millisecondsToDuration, normalizeSystem, secondsToDuration, timeSyncQueryKey } from './systemModel';
import TimeSyncPanel from './TimeSyncPanel';
import './SystemPage.module.css';

export default function SystemPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const aiAssistantFabVisible = useAppStore((state) => state.aiAssistantFabVisible);
  const setTheme = useAppStore((state) => state.setTheme);
  const setAiAssistantFabVisible = useAppStore((state) => state.setAiAssistantFabVisible);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const [apiTokenDraft, setAPITokenDraft] = useState({ name: '', scopes: ['read:system'], ttl: '720h', notes: '' });
  const [latestAPIToken, setLatestAPIToken] = useState('');
  const [revokeTokenId, setRevokeTokenId] = useState<string | null>(null);
  const [apiTokenPage, setAPITokenPage] = useState(0);
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data } = systemQuery;
  const apiTokensQuery = useQuery({ queryKey: ['management-api-tokens'], queryFn: fetchManagementAPITokens, retry: false });
  const serverSystem = useMemo(() => (data ? normalizeSystem(data) : undefined), [data]);
  const { draft, setDraft, markClean } = useServerDraft(serverSystem);
  const system = draft ?? fallbackSystem;

  const saveMutation = useMutation({
    mutationFn: updateSystemConfig,
    onSuccess: (saved) => {
      markClean(normalizeSystem(saved));
      queryClient.invalidateQueries({ queryKey: ['system'] });
      queryClient.invalidateQueries({ queryKey: timeSyncQueryKey });
      queryClient.invalidateQueries({ queryKey: ['management-api-tokens'] });
      toast.success(t('system.saved'));
    },
    onError: (error) => toast.error(error.message),
  });
  const storageTestMutation = useMutation({
    mutationFn: (backend: string) => testStorageBackend(backend, system.storage),
    onSuccess: (result) => toast.success(`${result.backend} ${t('system.testOk')}`),
    onError: (error) => toast.error(error.message),
  });

  const baseSystem = (current: SystemConfig | undefined) => current ?? fallbackSystem;
  const patchSystem = (patch: Partial<SystemConfig>) => setDraft((current) => normalizeSystem({ ...baseSystem(current), ...patch }));
  const patchConsoleLogin = (patch: Partial<SystemConfig['console']['login']>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      return normalizeSystem({
        ...next,
        console: {
          ...next.console,
          login: {
            ...next.console.login,
            ...patch,
          },
        },
      });
    });
  };
  const patchConsoleMap = (patch: Partial<SystemConfig['console']['map']>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      return normalizeSystem({
        ...next,
        console: {
          ...next.console,
          map: {
            ...next.console.map,
            ...patch,
          },
        },
      });
    });
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
    setDraft((current) => {
      const next = baseSystem(current);
      return {
        ...next,
        storage: {
          ...next.storage,
          [key]: {
            ...(next.storage[key] as Record<string, unknown>),
            ...(patch as Record<string, unknown>),
          } as SystemConfig['storage'][K],
        },
      };
    });
  };
  const patchTimeSync = (patch: Partial<NonNullable<SystemConfig['time_sync']>>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      return normalizeSystem({
        ...next,
        time_sync: next.time_sync ? { ...next.time_sync, ...patch } : undefined,
      });
    });
  };
  const apiAuth = useMemo(() => readAPIAuth(system), [system]);
  const managementAPI = useMemo(() => readManagementAPI(system), [system]);
  const apiTokens = apiTokensQuery.data?.items ?? (apiTokensQuery.isError ? [] : (managementAPI.tokens ?? []));
  const patchAPISec = (patch: Partial<SystemConfig['apisec']>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      return normalizeSystem({ ...next, apisec: { ...next.apisec, ...patch } });
    });
  };
  const patchAPIAuth = (patch: Partial<APISecAuthConfig>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      const auth = readAPIAuth(next);
      return normalizeSystem({
        ...next,
        apisec: {
          ...next.apisec,
          auth: { ...auth, ...patch },
        },
      });
    });
  };
  const patchManagementAPI = (patch: Partial<ManagementAPIConfig>) => {
    setDraft((current) => {
      const next = baseSystem(current);
      const management = readManagementAPI(next);
      return normalizeSystem({
        ...next,
        apisec: {
          ...next.apisec,
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
      toast.success(t('system.apiTokenCreated'));
    },
    onError: (error) => toast.error(error.message),
  });
  const revokeAPITokenMutation = useMutation({
    mutationFn: revokeManagementAPIToken,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['management-api-tokens'] });
      queryClient.invalidateQueries({ queryKey: ['system'] });
      toast.success(t('system.apiTokenRevoked'));
      setRevokeTokenId(null);
    },
    onError: (error) => toast.error(error.message),
  });
  const submitAPIToken = () => {
    if (latestAPIToken) {
      toast.warning(t('system.apiTokenClearBeforeCreate'));
      return;
    }
    const name = apiTokenDraft.name.trim();
    if (!name) {
      toast.warning(t('system.apiTokenNameRequired'));
      return;
    }
    if (apiTokenDraft.scopes.length === 0) {
      toast.warning(t('system.apiTokenScopesRequired'));
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

  const tokenPageSize = 6;
  const tokenPageCount = Math.max(1, Math.ceil(apiTokens.length / tokenPageSize));
  const pagedTokens = apiTokens.slice(apiTokenPage * tokenPageSize, (apiTokenPage + 1) * tokenPageSize);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('system.title')}</h1>
          <p>{t('system.subtitle')}</p>
        </div>
      </header>

      {systemQuery.isError && (
        <QueryErrorState
          message={systemQuery.error instanceof Error ? systemQuery.error.message : undefined}
          onRetry={() => { void systemQuery.refetch(); }}
          retrying={systemQuery.isFetching}
        />
      )}

      <section className="panel system-settings-panel">
        <Tabs className="system-tabs" defaultValue="runtime">
          <TabsList className="system-tabs-list w-full justify-start flex-wrap h-auto">
            <TabsTrigger value="runtime" className="tab-title"><ServerCog size={15} />{t('system.runtime')}</TabsTrigger>
            <TabsTrigger value="console" className="tab-title"><Image size={15} />{t('system.consoleLogin')}</TabsTrigger>
            <TabsTrigger value="storage" className="tab-title"><Database size={15} />{t('system.storage')}</TabsTrigger>
            <TabsTrigger value="apisec" className="tab-title"><ShieldAlert size={15} />{t('system.apiSecurity')}</TabsTrigger>
          </TabsList>

          <TabsContent value="runtime">
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.interface')}</h2>
                <Button onClick={() => saveMutation.mutate({ server: system.server, ...(system.time_sync ? { time_sync: system.time_sync } : {}), tls: system.tls, logging: system.logging })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
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
                      <Select value={theme} onValueChange={(value) => setTheme(value as ThemeName)}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {themeOptions.map((option) => <SelectItem key={option.value} value={option.value}>{t(option.labelKey)}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </label>
                    <label>
                      <span>{t('system.language')}</span>
                      <Select
                        value={language}
                        onValueChange={(value) => {
                          const next = value as Language;
                          setLanguage(next);
                          void i18n.changeLanguage(next);
                        }}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="zh-CN">中文</SelectItem>
                          <SelectItem value="en-US">English</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label className="switch-line">
                      <span>{t('system.showAiAssistantFab')}</span>
                      <Switch checked={aiAssistantFabVisible} onCheckedChange={setAiAssistantFabVisible} />
                    </label>
                    <label><span>HTTP</span><Input value={system.server.listen} onChange={(e) => patchSystem({ server: { ...system.server, listen: e.target.value } })} /></label>
                    <label><span>HTTPS</span><Input value={system.server.listen_tls} onChange={(e) => patchSystem({ server: { ...system.server, listen_tls: e.target.value } })} /></label>
                    <label><span>HTTP/3 UDP</span><Input value={system.server.listen_http3} onChange={(e) => patchSystem({ server: { ...system.server, listen_http3: e.target.value } })} /></label>
                    <label><span>{t('system.adminListen')}</span><Input value={system.server.admin_listen} onChange={(e) => patchSystem({ server: { ...system.server, admin_listen: e.target.value } })} /></label>
                    <label className="switch-line"><span>{t('system.adminPublic')}</span><Switch checked={system.server.admin_public} onCheckedChange={(admin_public) => patchSystem({ server: { ...system.server, admin_public } })} /></label>
                    <label className="switch-line"><span>HTTP/3</span><Switch checked={system.server.http3.enabled} onCheckedChange={(enabled) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, enabled } } })} /></label>
                    <label className="switch-line"><span>0-RTT</span><Switch checked={system.server.http3.zero_rtt} onCheckedChange={(zero_rtt) => patchSystem({ server: { ...system.server, http3: { ...system.server.http3, zero_rtt } } })} /></label>
                  </div>
                </section>
                <section className="system-fieldset">
                  <header>
                    <strong>TLS</strong>
                    <span>{t('system.tlsHint')}</span>
                  </header>
                  <div className="site-detail-grid system-tls-grid">
                    <label className="switch-line"><span>{t('system.adminTls')}</span><Switch checked={system.server.admin_tls.enabled} onCheckedChange={(enabled) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, enabled } } })} /></label>
                    <label className="switch-line"><span>{t('system.autoCert')}</span><Switch checked={system.tls.auto_cert} onCheckedChange={(auto_cert) => patchSystem({ tls: { ...system.tls, auto_cert } })} /></label>
                    <label className="switch-line"><span>HSTS</span><Switch checked={system.tls.hsts} onCheckedChange={(hsts) => patchSystem({ tls: { ...system.tls, hsts } })} /></label>
                    <label className="wide-field system-path-field"><span>{t('system.adminTlsCert')}</span><Input value={system.server.admin_tls.cert_file} onChange={(e) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, cert_file: e.target.value } } })} /></label>
                    <label className="wide-field system-path-field"><span>{t('system.adminTlsKey')}</span><Input value={system.server.admin_tls.key_file} onChange={(e) => patchSystem({ server: { ...system.server, admin_tls: { ...system.server.admin_tls, key_file: e.target.value } } })} /></label>
                    <label className="wide-field system-path-field"><span>{t('sites.certFile')}</span><Input value={system.tls.cert_file} onChange={(e) => patchSystem({ tls: { ...system.tls, cert_file: e.target.value } })} /></label>
                    <label className="wide-field system-path-field"><span>{t('sites.keyFile')}</span><Input value={system.tls.key_file} onChange={(e) => patchSystem({ tls: { ...system.tls, key_file: e.target.value } })} /></label>
                  </div>
                </section>
                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.logging')}</strong>
                    <span>{t('system.loggingHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label><span>{t('system.logPath')}</span><Input value={system.logging.output.file.path} onChange={(e) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, path: e.target.value } } } })} /></label>
                    <label><span>{t('system.logMaxBackups')}</span><Input type="number" value={system.logging.output.file.max_backups} min={1} max={365} onChange={(e) => patchSystem({ logging: { ...system.logging, output: { ...system.logging.output, file: { ...system.logging.output.file, max_backups: Number(e.target.value || 1) } } } })} /></label>
                  </div>
                </section>
                {system.time_sync && <TimeSyncPanel value={system.time_sync} onChange={patchTimeSync} />}
              </div>
            </div>
          </TabsContent>

          <TabsContent value="console">
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.consoleLogin')}</h2>
                <Button onClick={() => saveMutation.mutate({ console: system.console })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
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
                        onCheckedChange={(enabled) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaMode')}</span>
                      <Select
                        value={system.console.login.captcha.mode || 'slider'}
                        onValueChange={(mode) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, mode } })}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="slider">{t('system.loginCaptchaSlider')}</SelectItem>
                          <SelectItem value="pow">{t('system.loginCaptchaPow')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaMaxNumber')}</span>
                      <Input
                        type="number"
                        min={1000}
                        max={50000000}
                        step={1000}
                        value={system.console.login.captcha.max_number}
                        onChange={(e) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, max_number: Number(e.target.value || 75000) } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginCaptchaTTL')}</span>
                      <Input
                        type="number"
                        min={30}
                        max={600}
                        step={30}
                        value={durationSeconds(system.console.login.captcha.ttl)}
                        onChange={(e) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, ttl: secondsToDuration(Number(e.target.value)) } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderTolerance')}</span>
                      <Input
                        type="number"
                        min={2}
                        max={20}
                        value={system.console.login.captcha.slider.tolerance}
                        onChange={(e) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, tolerance: Number(e.target.value || 6) } } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderMinDrag')}</span>
                      <Input
                        type="number"
                        min={100}
                        max={10000}
                        step={50}
                        value={durationMilliseconds(system.console.login.captcha.slider.min_drag)}
                        onChange={(e) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, min_drag: millisecondsToDuration(Number(e.target.value || 450)) } } })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.loginSliderPowEnabled')}</span>
                      <Switch
                        checked={system.console.login.captcha.slider.pow_enabled}
                        onCheckedChange={(pow_enabled) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, pow_enabled } } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginSliderPowMax')}</span>
                      <Input
                        type="number"
                        min={1000}
                        max={50000000}
                        step={1000}
                        disabled={!system.console.login.captcha.slider.pow_enabled}
                        value={system.console.login.captcha.slider.pow_max_number}
                        onChange={(e) => patchConsoleLogin({ captcha: { ...system.console.login.captcha, slider: { ...system.console.login.captcha.slider, pow_max_number: Number(e.target.value || 12000) } } })}
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
                        onCheckedChange={(enabled) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.securityEntryPath')}</span>
                      <Input
                        value={system.console.login.security_entry.path}
                        placeholder="/__cheesewaf-entry"
                        onChange={(e) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, path: e.target.value } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.securityEntryCookie')}</span>
                      <Input
                        value={system.console.login.security_entry.cookie_name}
                        placeholder="cheesewaf_admin_entry"
                        onChange={(e) => patchConsoleLogin({ security_entry: { ...system.console.login.security_entry, cookie_name: e.target.value } })}
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
                        onCheckedChange={(enabled) => patchConsoleLogin({ background: { ...system.console.login.background, enabled } })}
                      />
                    </label>
                    <label>
                      <span>{t('system.loginBackgroundType')}</span>
                      <Select
                        value={system.console.login.background.type || 'auto'}
                        onValueChange={(type) => patchConsoleLogin({ background: { ...system.console.login.background, type } })}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="auto">{t('system.loginBackgroundAuto')}</SelectItem>
                          <SelectItem value="image">{t('system.loginBackgroundImage')}</SelectItem>
                          <SelectItem value="video">{t('system.loginBackgroundVideo')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.loginBackgroundURL')}</span>
                      <Input
                        value={system.console.login.background.url}
                        placeholder="https://example.com/admin-bg.webp"
                        onChange={(e) => patchConsoleLogin({ background: { ...system.console.login.background, url: e.target.value } })}
                      />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset">
                  <header>
                    <strong>{t('system.loginBranding')}</strong>
                    <span>{t('system.loginBrandingHint')}</span>
                  </header>
                  <div className="site-detail-grid">
                    <label className="wide-field">
                      <span>{t('system.loginCopyright')}</span>
                      <Input
                        value={system.console.login.copyright ?? ''}
                        placeholder="Copyright © CheeseWAF. All rights reserved."
                        onChange={(e) => patchConsoleLogin({ copyright: e.target.value })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.loginShowProductVersion')}</span>
                      <Switch
                        checked={system.console.login.show_product_version !== false}
                        onCheckedChange={(show_product_version) => patchConsoleLogin({ show_product_version })}
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
                        onCheckedChange={(enabled) => patchChinaBoundary({ enabled })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundarySourceType')}</span>
                      <Select
                        value={system.console.map.china_boundary.source_type || 'file'}
                        onValueChange={(source_type) => patchChinaBoundary({ source_type })}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="file">{t('system.mapBoundaryFile')}</SelectItem>
                          <SelectItem value="url">{t('system.mapBoundaryURL')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.mapBoundarySource')}</span>
                      <Input
                        value={system.console.map.china_boundary.source}
                        placeholder={system.console.map.china_boundary.source_type === 'url' ? 'https://example.com/china-boundary.geojson' : './data/maps/china-boundary.geojson'}
                        onChange={(e) => patchChinaBoundary({ source: e.target.value })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundaryLicense')}</span>
                      <Input
                        value={system.console.map.china_boundary.license}
                        placeholder={t('system.mapBoundaryLicensePlaceholder')}
                        onChange={(e) => patchChinaBoundary({ license: e.target.value })}
                      />
                    </label>
                    <label>
                      <span>{t('system.mapBoundaryReviewID')}</span>
                      <Input
                        value={system.console.map.china_boundary.review_id}
                        placeholder={t('system.mapBoundaryReviewIDPlaceholder')}
                        onChange={(e) => patchChinaBoundary({ review_id: e.target.value })}
                      />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.mapBoundaryAttribution')}</span>
                      <Input
                        value={system.console.map.china_boundary.attribution}
                        placeholder={t('system.mapBoundaryAttributionPlaceholder')}
                        onChange={(e) => patchChinaBoundary({ attribution: e.target.value })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.mapBoundaryAllowInsecure')}</span>
                      <Switch
                        checked={system.console.map.china_boundary.allow_insecure}
                        onCheckedChange={(allow_insecure) => patchChinaBoundary({ allow_insecure })}
                      />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.mapBoundaryAllowPrivate')}</span>
                      <Switch
                        checked={system.console.map.china_boundary.allow_private}
                        onCheckedChange={(allow_private) => patchChinaBoundary({ allow_private })}
                      />
                    </label>
                  </div>
                </section>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="storage">
            <div className="system-section">
              <div className="system-section-title">
                <h2>{t('system.storage')}</h2>
                <Button onClick={() => saveMutation.mutate({ storage: system.storage })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
              </div>
              <div className="storage-grid">
                <StoragePanel title="SQLite" enabled action={() => storageTestMutation.mutate('sqlite')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.path')}</span><Input value={system.storage.sqlite.path} onChange={(e) => patchStorage('sqlite', { path: e.target.value })} /></label>
                </StoragePanel>

                <StoragePanel title="Redis" enabled={system.storage.redis.enabled} onToggle={(enabled) => patchStorage('redis', { enabled })} action={() => storageTestMutation.mutate('redis')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.address')}</span><Input value={system.storage.redis.address} onChange={(e) => patchStorage('redis', { address: e.target.value })} /></label>
                </StoragePanel>

                <StoragePanel title="PostgreSQL" enabled={system.storage.postgresql.enabled} onToggle={(enabled) => patchStorage('postgresql', { enabled })} action={() => storageTestMutation.mutate('postgresql')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.dsn')}</span><Input type="password" value={system.storage.postgresql.dsn} onChange={(e) => patchStorage('postgresql', { dsn: e.target.value })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.postgresql.table} onChange={(e) => patchStorage('postgresql', { table: e.target.value })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><Input type="number" value={durationSeconds(system.storage.postgresql.timeout)} min={1} max={120} onChange={(e) => patchStorage('postgresql', { timeout: secondsToDuration(Number(e.target.value)) })} /></label>
                </StoragePanel>

                <StoragePanel title="Elasticsearch" enabled={system.storage.elasticsearch.enabled} onToggle={(enabled) => patchStorage('elasticsearch', { enabled })} action={() => storageTestMutation.mutate('elasticsearch')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.elasticsearch.endpoint} onChange={(e) => patchStorage('elasticsearch', { endpoint: e.target.value })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.elasticsearch.allow_private_endpoint} onCheckedChange={(allow_private_endpoint) => patchStorage('elasticsearch', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.index')}</span><Input value={system.storage.elasticsearch.index} onChange={(e) => patchStorage('elasticsearch', { index: e.target.value })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.elasticsearch.username} onChange={(e) => patchStorage('elasticsearch', { username: e.target.value })} /></label>
                  <label><span>{t('system.apiKey')}</span><Input type="password" value={system.storage.elasticsearch.api_key} onChange={(e) => patchStorage('elasticsearch', { api_key: e.target.value })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><Input type="number" value={durationSeconds(system.storage.elasticsearch.timeout)} min={1} max={120} onChange={(e) => patchStorage('elasticsearch', { timeout: secondsToDuration(Number(e.target.value)) })} /></label>
                </StoragePanel>

                <StoragePanel title="ClickHouse" enabled={system.storage.clickhouse.enabled} onToggle={(enabled) => patchStorage('clickhouse', { enabled })} action={() => storageTestMutation.mutate('clickhouse')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.clickhouse.endpoint} onChange={(e) => patchStorage('clickhouse', { endpoint: e.target.value })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.clickhouse.allow_private_endpoint} onCheckedChange={(allow_private_endpoint) => patchStorage('clickhouse', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.database')}</span><Input value={system.storage.clickhouse.database} onChange={(e) => patchStorage('clickhouse', { database: e.target.value })} /></label>
                  <label><span>{t('system.table')}</span><Input value={system.storage.clickhouse.table} onChange={(e) => patchStorage('clickhouse', { table: e.target.value })} /></label>
                  <label><span>{t('setup.username')}</span><Input value={system.storage.clickhouse.username} onChange={(e) => patchStorage('clickhouse', { username: e.target.value })} /></label>
                </StoragePanel>

                <StoragePanel title="VictoriaLogs" enabled={system.storage.victorialogs.enabled} onToggle={(enabled) => patchStorage('victorialogs', { enabled })} action={() => storageTestMutation.mutate('victorialogs')} loading={storageTestMutation.isPending}>
                  <label><span>{t('system.endpoint')}</span><Input value={system.storage.victorialogs.endpoint} onChange={(e) => patchStorage('victorialogs', { endpoint: e.target.value })} /></label>
                  <label className="switch-line"><span>{t('system.allowPrivateStorageEndpoint')}</span><Switch checked={system.storage.victorialogs.allow_private_endpoint} onCheckedChange={(allow_private_endpoint) => patchStorage('victorialogs', { allow_private_endpoint })} /></label>
                  <label><span>{t('system.timeoutSeconds')}</span><Input type="number" value={durationSeconds(system.storage.victorialogs.timeout)} min={1} max={120} onChange={(e) => patchStorage('victorialogs', { timeout: secondsToDuration(Number(e.target.value)) })} /></label>
                </StoragePanel>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="apisec">
            <div className="system-section">
              <div className="system-section-title">
                <h2><KeyRound size={16} /> {t('system.jwtAuth')}</h2>
                <Button onClick={() => saveMutation.mutate({ apisec: system.apisec })} loading={saveMutation.isPending} disabled={!systemQuery.isSuccess}>{t('common.save')}</Button>
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
                      <Switch checked={Boolean(system.apisec.enabled)} onCheckedChange={(enabled) => patchAPISec({ enabled })} />
                    </label>
                    <label className="switch-line">
                      <span>{t('system.jwtAuthEnabled')}</span>
                      <Switch checked={apiAuth.enabled} onCheckedChange={(enabled) => patchAPIAuth({ enabled })} />
                    </label>
                    <label>
                      <span>{t('system.jwtAlgorithms')}</span>
                      <Input value={joinList(apiAuth.jwt_algorithms)} placeholder="HS256, RS256" onChange={(e) => patchAPIAuth({ jwt_algorithms: splitList(e.target.value) })} />
                    </label>
                    <label>
                      <span>{t('system.jwtIssuers')}</span>
                      <Input value={joinList(apiAuth.jwt_issuers)} placeholder="https://issuer.example.com" onChange={(e) => patchAPIAuth({ jwt_issuers: splitList(e.target.value) })} />
                    </label>
                    <label>
                      <span>{t('system.jwtAudiences')}</span>
                      <Input value={joinList(apiAuth.jwt_audiences)} placeholder="orders-api, admin-api" onChange={(e) => patchAPIAuth({ jwt_audiences: splitList(e.target.value) })} />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.requiredScopes')}</span>
                      <Input value={joinList(apiAuth.required_scopes)} placeholder="orders:read, admin:read" onChange={(e) => patchAPIAuth({ required_scopes: splitList(e.target.value) })} />
                    </label>
                  </div>
                </section>

                <section className="system-fieldset management-api-fieldset">
                  <header className="fieldset-header-action">
                    <div>
                      <strong><KeyRound size={15} /> {t('system.managementAPI')}</strong>
                      <span>{t('system.managementAPIHint')}</span>
                    </div>
                    <Switch checked={managementAPI.enabled} onCheckedChange={(enabled) => patchManagementAPI({ enabled })} />
                  </header>
                  <div className="api-token-create-grid">
                    <label>
                      <span>{t('system.apiTokenName')}</span>
                      <Input value={apiTokenDraft.name} placeholder={t('system.apiTokenNamePlaceholder')} onChange={(e) => setAPITokenDraft((draft) => ({ ...draft, name: e.target.value }))} />
                    </label>
                    <label>
                      <span>{t('system.apiTokenScopes')}</span>
                      <Input
                        value={apiTokenDraft.scopes.join(', ')}
                        placeholder="read:system"
                        onChange={(e) => setAPITokenDraft((draft) => ({ ...draft, scopes: splitList(e.target.value) }))}
                      />
                    </label>
                    <label>
                      <span>{t('system.apiTokenTTL')}</span>
                      <Select
                        value={apiTokenDraft.ttl === '' ? '__none__' : apiTokenDraft.ttl}
                        onValueChange={(ttl) => setAPITokenDraft((draft) => ({ ...draft, ttl: ttl === '__none__' ? '' : ttl }))}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="1h">1h</SelectItem>
                          <SelectItem value="24h">24h</SelectItem>
                          <SelectItem value="168h">7d</SelectItem>
                          <SelectItem value="720h">30d</SelectItem>
                          <SelectItem value="__none__">{t('system.apiTokenNoExpiry')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </label>
                    <label className="wide-field">
                      <span>{t('system.apiTokenNotes')}</span>
                      <Input value={apiTokenDraft.notes} placeholder={t('system.apiTokenNotesPlaceholder')} onChange={(e) => setAPITokenDraft((draft) => ({ ...draft, notes: e.target.value }))} />
                    </label>
                    <Button loading={createAPITokenMutation.isPending} disabled={!managementAPI.enabled || Boolean(latestAPIToken)} onClick={submitAPIToken}>
                      {t('system.createAPIToken')}
                    </Button>
                  </div>
                  {latestAPIToken && (
                    <div className="cluster-result-note cluster-result-note-ok api-token-secret">
                      <strong>{t('system.apiTokenSecretTitle')}</strong>
                      <span>{t('system.apiTokenSecretHint')}</span>
                      <code>{latestAPIToken}</code>
                      <div className="cluster-token-actions">
                        <Button variant="outline" onClick={() => void copyText(latestAPIToken, t('system.apiTokenCopied'), t('system.apiTokenCopyFailed'))}><Copy size={15} />{t('system.copyAPIToken')}</Button>
                        <Button variant="outline" onClick={() => {
                          setLatestAPIToken('');
                          toast.success(t('system.apiTokenCleared'));
                        }}>{t('system.clearAPIToken')}</Button>
                      </div>
                    </div>
                  )}
                  {apiTokensQuery.isError && (
                    <QueryErrorState
                      message={apiTokensQuery.error instanceof Error ? apiTokensQuery.error.message : undefined}
                      onRetry={() => { void apiTokensQuery.refetch(); }}
                      retrying={apiTokensQuery.isFetching}
                    />
                  )}
                  <div className="relative">
                    {apiTokensQuery.isFetching && <div className="absolute inset-0 z-10 bg-background/40" aria-busy />}
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{t('system.apiTokenName')}</TableHead>
                          <TableHead>{t('system.apiTokenScopes')}</TableHead>
                          <TableHead>{t('system.apiTokenExpires')}</TableHead>
                          <TableHead>{t('common.status')}</TableHead>
                          <TableHead>{t('common.actions')}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pagedTokens.map((item: ManagementAPIToken) => (
                          <TableRow key={item.id}>
                            <TableCell><div className="api-token-name"><strong>{item.name}</strong><span>{item.prefix}</span></div></TableCell>
                            <TableCell><span className="api-token-scope-list">{(item.scopes || []).map((scope) => <Badge key={scope} variant="secondary">{scope}</Badge>)}</span></TableCell>
                            <TableCell>{formatSystemTimestamp(item.expires_at, t('system.apiTokenNoExpiry'))}</TableCell>
                            <TableCell><Badge variant={item.enabled ? 'success' : 'secondary'}>{item.enabled ? t('system.enabled') : t('system.disabled')}</Badge></TableCell>
                            <TableCell>
                              <Button
                                size="sm"
                                variant="destructive"
                                disabled={!item.enabled}
                                loading={revokeAPITokenMutation.isPending && revokeTokenId === item.id}
                                onClick={() => setRevokeTokenId(item.id)}
                              >
                                {t('common.revoke')}
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    {apiTokens.length > tokenPageSize && (
                      <div className="flex items-center justify-end gap-2 py-2">
                        <Button size="sm" variant="outline" disabled={apiTokenPage <= 0} onClick={() => setAPITokenPage((p) => p - 1)}>{t('common.prev')}</Button>
                        <span className="text-sm text-muted-foreground">{apiTokenPage + 1}/{tokenPageCount}</span>
                        <Button size="sm" variant="outline" disabled={apiTokenPage >= tokenPageCount - 1} onClick={() => setAPITokenPage((p) => p + 1)}>{t('common.next')}</Button>
                      </div>
                    )}
                  </div>
                </section>

                <section className="system-fieldset">
                  <header className="fieldset-header-action">
                    <div>
                      <strong>{t('system.apiAuthEndpointPolicies')}</strong>
                      <span>{t('system.apiAuthEndpointPoliciesHint')}</span>
                    </div>
                    <Button size="sm" variant="outline" onClick={addAPIAuthEndpoint}><Plus size={14} />{t('common.add')}</Button>
                  </header>
                  <div className="endpoint-policy-list">
                    {apiAuth.endpoint_policies.length === 0 ? (
                      <div className="empty-state"><ShieldAlert size={16} /> {t('system.noEndpointPolicies')}</div>
                    ) : apiAuth.endpoint_policies.map((policy, index) => (
                      <section className="endpoint-policy-row" key={`${policy.id}-${index}`}>
                        <div className="endpoint-policy-head">
                          <Switch checked={policy.enabled} onCheckedChange={(enabled) => patchAPIAuthEndpoint(index, { enabled })} />
                          <Input value={policy.id} placeholder="orders-write" onChange={(e) => patchAPIAuthEndpoint(index, { id: e.target.value })} />
                          <Button size="sm" variant="destructive" onClick={() => removeAPIAuthEndpoint(index)}><Trash2 size={13} />{t('common.delete')}</Button>
                        </div>
                        <div className="site-detail-grid">
                          <label>
                            <span>{t('apisec.method')}</span>
                            <Select value={policy.method || 'GET'} onValueChange={(method) => patchAPIAuthEndpoint(index, { method })}>
                              <SelectTrigger><SelectValue /></SelectTrigger>
                              <SelectContent>
                                {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((method) => (
                                  <SelectItem key={method} value={method}>{method}</SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </label>
                          <label>
                            <span>{t('system.pathPattern')}</span>
                            <Input value={policy.path_pattern} placeholder="^/api/orders$" onChange={(e) => patchAPIAuthEndpoint(index, { path_pattern: e.target.value })} />
                          </label>
                          <label>
                            <span>{t('system.jwtIssuers')}</span>
                            <Input value={joinList(policy.jwt_issuers)} onChange={(e) => patchAPIAuthEndpoint(index, { jwt_issuers: splitList(e.target.value) })} />
                          </label>
                          <label>
                            <span>{t('system.jwtAudiences')}</span>
                            <Input value={joinList(policy.jwt_audiences)} onChange={(e) => patchAPIAuthEndpoint(index, { jwt_audiences: splitList(e.target.value) })} />
                          </label>
                          <label className="wide-field">
                            <span>{t('system.requiredScopes')}</span>
                            <Input value={joinList(policy.required_scopes)} onChange={(e) => patchAPIAuthEndpoint(index, { required_scopes: splitList(e.target.value) })} />
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
                      <Input type="password" value={apiAuth.jwt_shared_secret} onChange={(e) => patchAPIAuth({ jwt_shared_secret: e.target.value })} />
                    </label>
                    <label>
                      <span>{t('system.jwtPublicKeyFile')}</span>
                      <Input value={apiAuth.jwt_public_key_file} onChange={(e) => patchAPIAuth({ jwt_public_key_file: e.target.value })} />
                    </label>
                    <label className="wide-field">
                      <span>{t('system.jwtPublicKeyPEM')}</span>
                      <Textarea
                        rows={4}
                        value={apiAuth.jwt_public_key_pem}
                        onChange={(e) => patchAPIAuth({ jwt_public_key_pem: e.target.value })}
                      />
                    </label>
                    <label>
                      <span>{t('system.jwksFile')}</span>
                      <Input value={apiAuth.jwks_file} onChange={(e) => patchAPIAuth({ jwks_file: e.target.value })} />
                    </label>
                    <label>
                      <span>{t('system.jwksURL')}</span>
                      <Input value={apiAuth.jwks_url} placeholder="https://issuer.example.com/.well-known/jwks.json" onChange={(e) => patchAPIAuth({ jwks_url: e.target.value })} />
                    </label>
                    <label>
                      <span>{t('system.jwksCacheFile')}</span>
                      <Input value={apiAuth.jwks_cache_file} onChange={(e) => patchAPIAuth({ jwks_cache_file: e.target.value })} />
                    </label>
                    <label>
                      <span>{t('system.jwksRefreshInterval')}</span>
                      <Input
                        type="number"
                        min={60}
                        step={60}
                        value={durationSeconds(apiAuth.jwks_refresh_interval)}
                        onChange={(e) => patchAPIAuth({ jwks_refresh_interval: secondsToDuration(Number(e.target.value || 0)) })}
                      />
                    </label>
                    <label>
                      <span>{t('system.jwksJSON')}</span>
                      <Textarea
                        rows={4}
                        value={apiAuth.jwks_json}
                        onChange={(e) => patchAPIAuth({ jwks_json: e.target.value })}
                      />
                    </label>
                  </div>
                </section>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </section>

      <Dialog open={Boolean(revokeTokenId)} onOpenChange={(open) => { if (!open) setRevokeTokenId(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('system.apiTokenRevokeConfirmTitle')}</DialogTitle>
            <DialogDescription>{t('system.apiTokenRevokeConfirm')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeTokenId(null)}>{t('common.cancel')}</Button>
            <Button
              variant="destructive"
              loading={revokeAPITokenMutation.isPending}
              onClick={() => {
                if (revokeTokenId) revokeAPITokenMutation.mutate(revokeTokenId);
              }}
            >
              {t('common.revoke')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
    jwks_cache_file: stringValue(auth.jwks_cache_file) || './data/apisec/jwks-cache.json',
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
    toast.success(successMessage);
  } catch {
    toast.error(failureMessage);
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
        <div className="flex items-center gap-2">
          {onToggle && <Switch checked={enabled} onCheckedChange={onToggle} />}
          <Button size="sm" variant="outline" onClick={action} loading={loading}>{t('system.test')}</Button>
        </div>
      </div>
      <div className="storage-card-body">{children}</div>
    </section>
  );
}
