import {
  Button,
  Empty,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Select,
  Space,
  Spin,
  Steps,
  Switch,
  Tabs,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle2, CircleAlert, Clock3, KeyRound, LockKeyhole, Network, Plus, Save, ShieldCheck, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { APIRequestError, deleteSite, fetchACMEProviders, fetchSite, issueSiteACMECertificate, updateSite } from '../../api/client';
import type { ACMEDNSProvider, ACMEEvent, ACMEIssueRequest, Site, SiteAdvanced, SiteRewriteRule } from '../../types/api';
import { asCSV, normalizeSite, splitList } from './siteModel';
import './SiteDetailPage.css';

type EnvRow = { id: string; key: string; value: string };
type DurationUnit = 's' | 'm' | 'h' | 'd';
type ByteUnit = 'KB' | 'MB' | 'GB';

const acmeStepOrder = ['validate', 'prepare', 'account', 'dns_create', 'issue', 'deploy', 'dns_cleanup', 'notify'];

export default function SiteDetailPage() {
  const { t } = useTranslation();
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [site, setSite] = useState<Site | null>(null);
  const [acmeEvents, setAcmeEvents] = useState<ACMEEvent[]>([]);
  const [envRows, setEnvRows] = useState<EnvRow[]>([]);
  const { data, error, isError, isLoading, refetch } = useQuery({
    queryKey: ['site', id],
    queryFn: () => fetchSite(id),
    retry: false,
    enabled: Boolean(id),
  });

  useEffect(() => {
    if (data) {
      const next = normalizeSite(data);
      setSite(next);
      setEnvRows(envToRows(next.advanced.certificate.acme.env));
    }
  }, [data]);

  const {
    data: acmeProvidersData = [],
    error: acmeProvidersError,
    isError: acmeProvidersFailed,
    isLoading: acmeProvidersLoading,
    refetch: refetchACMEProviders,
  } = useQuery({
    queryKey: ['acme-providers'],
    queryFn: fetchACMEProviders,
    retry: false,
  });
  const acmeProviderList = useMemo(() => normalizeACMEProviderList(acmeProvidersData), [acmeProvidersData]);

  const saveMutation = useMutation({
    mutationFn: (payload: Site) => updateSite(payload.id, normalizeSite(payload)),
    onSuccess: (saved) => {
      const next = normalizeSite(saved);
      setSite(next);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      queryClient.invalidateQueries({ queryKey: ['site', id] });
      ArcoMessage.success(t('sites.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const deleteMutation = useMutation({
    mutationFn: () => deleteSite(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      ArcoMessage.success(t('sites.deleted'));
      navigate('/sites');
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const acmeMutation = useMutation({
    mutationFn: (payload: ACMEIssueRequest) => issueSiteACMECertificate(id, payload),
    onSuccess: (response) => {
      const next = normalizeSite(response.site);
      setSite(next);
      setEnvRows(envToRows(next.advanced.certificate.acme.env));
      setAcmeEvents(response.events ?? response.result?.events ?? []);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      queryClient.invalidateQueries({ queryKey: ['site', id] });
      ArcoMessage.success(t('sites.acmeIssued'));
    },
    onError: (error: Error) => {
      const data = error instanceof APIRequestError ? error.data as { events?: ACMEEvent[]; result?: { events?: ACMEEvent[] } } | undefined : undefined;
      setAcmeEvents(data?.events ?? data?.result?.events ?? []);
      ArcoMessage.error(error.message);
    },
  });
  const selectedProvider = useMemo(
    () => acmeProviderList.find((provider) => provider.id === site?.advanced.certificate.acme.provider_id),
    [acmeProviderList, site?.advanced.certificate.acme.provider_id],
  );
  const isMutating = saveMutation.isPending || deleteMutation.isPending || acmeMutation.isPending;

  if (isLoading) {
    return <Spin className="page-spinner" />;
  }
  if (isError) {
    return (
      <section className="page-surface site-detail-page">
        <header className="page-header">
          <div className="site-title-stack">
            <Button icon={<ArrowLeft size={16} />} onClick={() => navigate('/sites')}>{t('common.back')}</Button>
            <div><h1>{t('sites.title')}</h1></div>
          </div>
        </header>
        <div className="inline-error site-detail-load-error" role="alert">
          <span>{queryErrorMessage(error, t('sites.notFound'))}</span>
          <Button size="small" onClick={() => refetch()}>{t('common.retry')}</Button>
        </div>
      </section>
    );
  }
  if (!site) {
    return <Empty description={t('sites.notFound')} />;
  }

  const updateField = <K extends keyof Site>(key: K, value: Site[K]) => {
    setSite((current) => current ? { ...current, [key]: value } : current);
  };
  const updateAdvanced = <K extends keyof SiteAdvanced>(section: K, patch: Partial<SiteAdvanced[K]>) => {
    setSite((current) => current
      ? {
        ...current,
        advanced: {
          ...current.advanced,
          [section]: {
            ...(current.advanced[section] as Record<string, unknown>),
            ...(patch as Record<string, unknown>),
          } as SiteAdvanced[K],
        },
      }
      : current);
  };
  const updateCertificate = (patch: Partial<SiteAdvanced['certificate']>) => updateAdvanced('certificate', patch);
  const updateACME = (patch: Partial<SiteAdvanced['certificate']['acme']>) => {
    setSite((current) => current
      ? {
        ...current,
        advanced: {
          ...current.advanced,
          certificate: {
            ...current.advanced.certificate,
            acme: {
              ...current.advanced.certificate.acme,
              ...patch,
            },
          },
        },
      }
      : current);
  };
  const syncEnvRows = (rows: EnvRow[]) => {
    setEnvRows(rows);
    updateACME({ env: rowsToEnv(rows) });
  };
  const updateRewrite = (index: number, patch: Partial<SiteRewriteRule>) => {
    setSite((current) => {
      if (!current) {
        return current;
      }
      return {
        ...current,
        advanced: {
          ...current.advanced,
          rewrite: current.advanced.rewrite.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)),
        },
      };
    });
  };
  const addRewrite = () => {
    setSite((current) => {
      if (!current) {
        return current;
      }
      return {
        ...current,
        advanced: {
          ...current.advanced,
          rewrite: [
            ...current.advanced.rewrite,
            { id: `rewrite-${Date.now()}`, pattern: '', replacement: '', redirect_code: 0, enabled: false },
          ],
        },
      };
    });
  };
  const removeRewrite = (idToRemove: string) => {
    setSite((current) => current
      ? { ...current, advanced: { ...current.advanced, rewrite: current.advanced.rewrite.filter((rule) => rule.id !== idToRemove) } }
      : current);
  };
  const submitACME = () => {
    if (!site) {
      return;
    }
    const acme = site.advanced.certificate.acme;
    const payload: ACMEIssueRequest = {
      provider_id: acme.provider_id,
      dns_api: acme.dns_api,
      dns_env: rowsToEnv(envRows),
      account_email: acme.account_email,
      server: acme.server,
      key_type: acme.key_type,
      auto_renew: site.advanced.certificate.auto_renew,
      notify: acme.notify,
    };
    setAcmeEvents(initialACMEEvents());
    acmeMutation.mutate(payload);
  };
  const saveSite = () => {
    const problem = validateSiteDraft(site, t);
    if (problem) {
      ArcoMessage.warning(problem);
      return;
    }
    saveMutation.mutate(site);
  };

  return (
    <section className="page-surface site-detail-page">
      <header className="page-header">
        <div className="site-title-stack">
          <Button icon={<ArrowLeft size={16} />} disabled={isMutating} onClick={() => navigate('/sites')}>
            {t('common.back')}
          </Button>
          <div>
            <h1 title={site.name}>{site.name}</h1>
            <p title={site.domains.join(', ')}>{site.domains.join(', ')}</p>
          </div>
        </div>
        <Space wrap className="site-detail-actions">
          <Tag color={site.enabled ? 'green' : 'gray'}>{site.enabled ? t('common.online') : t('sites.disabled')}</Tag>
          <Button status="danger" icon={<Trash2 size={16} />} disabled={isMutating} loading={deleteMutation.isPending} onClick={() => {
            if (window.confirm(t('sites.deleteConfirm'))) {
              deleteMutation.mutate();
            }
          }}>
            {t('common.delete')}
          </Button>
          <Button type="primary" icon={<Save size={16} />} disabled={isMutating} loading={saveMutation.isPending} onClick={saveSite}>
            {t('common.save')}
          </Button>
        </Space>
      </header>

      <div className="site-detail-summary">
        <div><span>{t('sites.domain')}</span><strong>{site.domains.length}</strong></div>
        <div><span>{t('sites.upstream')}</span><strong>{site.upstreams.length}</strong></div>
        <div><span>{t('sites.listen')}</span><strong>:{site.listen_port}</strong></div>
        <div><span>{t('sites.wafMode')}</span><strong>{modeText(site.waf_mode, t)}</strong></div>
      </div>

      <fieldset className="panel site-detail-panel site-detail-fieldset" disabled={isMutating} aria-busy={isMutating}>
        <Tabs defaultActiveTab="basic" className="site-detail-tabs">
          <Tabs.TabPane key="basic" title={<span className="tab-title"><Network size={15} />{t('sites.stepBasic')}</span>}>
            <section className="site-form-section">
              <header className="site-form-section-header">
                <strong>{t('sites.basicIngress')}</strong>
                <span>{t('sites.basicIngressHint')}</span>
              </header>
              <div className="site-detail-grid">
              <label><span>{t('sites.name')}</span><Input value={site.name} onChange={(value) => updateField('name', value)} /></label>
              <label><span>{t('sites.domain')}</span><Input value={asCSV(site.domains)} placeholder="example.com, www.example.com" onChange={(value) => updateField('domains', splitList(value))} /><em>{t('sites.domainHint')}</em></label>
              <label><span>{t('sites.upstream')}</span><Input value={asCSV(site.upstreams)} placeholder="127.0.0.1:9000, https://origin.example.com" onChange={(value) => updateField('upstreams', splitList(value))} /><em>{t('sites.upstreamHint')}</em></label>
              <label><span>{t('sites.listen')}</span><InputNumber value={site.listen_port} min={1} max={65535} onChange={(value) => updateField('listen_port', Number(value || 80))} /></label>
              <label>
                <span>{t('sites.loadBalance')}</span>
                <Select value={site.loadbalance} onChange={(value) => updateField('loadbalance', value as string)}>
                  <Select.Option value="round_robin">{t('sites.lbRoundRobin')}</Select.Option>
                  <Select.Option value="weighted">{t('sites.lbWeighted')}</Select.Option>
                  <Select.Option value="ip_hash">{t('sites.lbIPHash')}</Select.Option>
                </Select>
              </label>
              <label className="switch-line"><span>{t('common.online')}</span><Switch checked={site.enabled} onChange={(value) => updateField('enabled', value)} /></label>
              </div>
            </section>

            <section className="site-form-section">
              <header className="site-form-section-header">
                <strong>{t('sites.originSettings')}</strong>
                <span>{t('sites.originSettingsHint')}</span>
              </header>
              <div className="site-detail-grid">
              <label>
                <span>{t('sites.originScheme')}</span>
                <Select value={site.advanced.origin.scheme} onChange={(value) => updateAdvanced('origin', { scheme: value as string })}>
                  <Select.Option value="http">HTTP</Select.Option>
                  <Select.Option value="https">HTTPS</Select.Option>
                </Select>
              </label>
              <label className="switch-line"><span>{t('sites.passHost')}</span><Switch checked={site.advanced.origin.pass_host} onChange={(value) => updateAdvanced('origin', { pass_host: value })} /></label>
              <label><span>{t('sites.hostHeader')}</span><Input value={site.advanced.origin.host_header} onChange={(value) => updateAdvanced('origin', { host_header: value })} /></label>
              <label><span>{t('sites.proxyTimeout')}</span><DurationStringInput value={site.advanced.origin.proxy_timeout} fallback="30s" onChange={(value) => updateAdvanced('origin', { proxy_timeout: value })} /><em>{t('sites.proxyTimeoutHint')}</em></label>
              <label><span>{t('sites.maxBody')}</span><ByteUnitInput value={site.advanced.origin.max_body_bytes} minBytes={1024} onChange={(value) => updateAdvanced('origin', { max_body_bytes: value })} /><em>{t('sites.maxBodyHint')}</em></label>
              <label><span>{t('sites.maxHeader')}</span><ByteUnitInput value={site.advanced.origin.max_header_size} minBytes={1024} defaultUnit="KB" onChange={(value) => updateAdvanced('origin', { max_header_size: value })} /><em>{t('sites.maxHeaderHint')}</em></label>
              </div>
            </section>
          </Tabs.TabPane>

          <Tabs.TabPane key="tls" title={<span className="tab-title"><LockKeyhole size={15} />{t('sites.stepTls')}</span>}>
            <div className="site-detail-grid">
              <label className="switch-line"><span>{t('sites.enableSsl')}</span><Switch checked={site.enable_ssl} onChange={(value) => updateField('enable_ssl', value)} /></label>
              <label>
                <span>{t('sites.certificateMode')}</span>
                <Select value={site.advanced.certificate.mode} onChange={(value) => updateAdvanced('certificate', { mode: value as string })}>
                  <Select.Option value="file">{t('sites.certFile')}</Select.Option>
                  <Select.Option value="inline">{t('sites.certInline')}</Select.Option>
                  <Select.Option value="acme">{t('sites.certAcme')}</Select.Option>
                </Select>
              </label>
              <label><span>{t('sites.certFile')}</span><Input value={site.cert_file ?? ''} onChange={(value) => updateField('cert_file', value)} /></label>
              <label><span>{t('sites.keyFile')}</span><Input value={site.key_file ?? ''} onChange={(value) => updateField('key_file', value)} /></label>
              <label className="wide-field"><span>{t('sites.certPem')}</span><Input.TextArea value={site.advanced.certificate.cert_pem ?? ''} autoSize={{ minRows: 4, maxRows: 8 }} onChange={(value) => updateAdvanced('certificate', { cert_pem: value })} /></label>
              <label className="wide-field"><span>{t('sites.keyPem')}</span><Input.TextArea value={site.advanced.certificate.key_pem ?? ''} autoSize={{ minRows: 4, maxRows: 8 }} onChange={(value) => updateAdvanced('certificate', { key_pem: value })} /></label>
              <label className="switch-line"><span>{t('sites.autoRenew')}</span><Switch checked={site.advanced.certificate.auto_renew} onChange={(value) => updateAdvanced('certificate', { auto_renew: value })} /></label>
              <label className="switch-line"><span>{t('sites.forceHttps')}</span><Switch checked={site.advanced.certificate.force_https} onChange={(value) => updateAdvanced('certificate', { force_https: value })} /></label>
              <label className="switch-line"><span>{t('sites.hsts')}</span><Switch checked={site.advanced.certificate.hsts} onChange={(value) => updateAdvanced('certificate', { hsts: value })} /></label>
              <label>
                <span>{t('sites.minTls')}</span>
                <Select value={site.advanced.certificate.min_tls_version} onChange={(value) => updateAdvanced('certificate', { min_tls_version: value as string })}>
                  <Select.Option value="1.2">TLS 1.2</Select.Option>
                  <Select.Option value="1.3">TLS 1.3</Select.Option>
                </Select>
              </label>
            </div>
            <ACMEWizard
              site={site}
              providers={acmeProviderList}
              providersError={acmeProvidersFailed ? queryErrorMessage(acmeProvidersError, t('sites.notFound')) : ''}
              providersLoading={acmeProvidersLoading}
              selectedProviderName={selectedProvider?.name}
              envRows={envRows}
              events={acmeEvents}
              loading={acmeMutation.isPending}
              onEnableMode={() => {
                updateField('enable_ssl', true);
                updateCertificate({ mode: 'acme', auto_renew: true, force_https: true, hsts: true });
              }}
              onPatchACME={updateACME}
              onEnvRowsChange={syncEnvRows}
              onIssue={submitACME}
              onRetryProviders={() => refetchACMEProviders()}
              t={t}
            />
          </Tabs.TabPane>

          <Tabs.TabPane key="protection" title={<span className="tab-title"><ShieldCheck size={15} />{t('sites.stepProtection')}</span>}>
            <section className="site-form-section">
              <header className="site-form-section-header">
                <strong>{t('sites.sitePolicy')}</strong>
                <span>{t('sites.sitePolicyHint')}</span>
              </header>
              <div className="site-detail-grid">
              <label className="switch-line"><span>{t('sites.wafEnabled')}</span><Switch checked={site.waf_enabled} onChange={(value) => updateField('waf_enabled', value)} /></label>
              <label>
                <span>{t('sites.wafMode')}</span>
                <Select value={site.waf_mode} onChange={(value) => updateField('waf_mode', value as string)}>
                  <Select.Option value="block">{t('sites.modeBlock')}</Select.Option>
                  <Select.Option value="monitor">{t('sites.modeMonitor')}</Select.Option>
                  <Select.Option value="off">{t('sites.modeOff')}</Select.Option>
                </Select>
              </label>
              {[
                ['web_attack', t('sites.webAttackLevel')],
                ['api_security', t('sites.apiSecurityLevel')],
                ['bot_cc', t('sites.botCCLevel')],
                ['threat_intel', t('sites.threatIntelLevel')],
              ].map(([key, label]) => (
                <label key={String(key)}>
                  <span>{label}</span>
                  <Select
                    value={site.advanced.policy[key as keyof Site['advanced']['policy']] || ''}
                    onChange={(value) => updateAdvanced('policy', { [key]: value } as Partial<Site['advanced']['policy']>)}
                  >
                    <Select.Option value="">{t('sites.levelInherit')}</Select.Option>
                    <Select.Option value="off">{t('sites.levelOff')}</Select.Option>
                    <Select.Option value="low">{t('sites.levelLow')}</Select.Option>
                    <Select.Option value="smart">{t('sites.levelSmart')}</Select.Option>
                    <Select.Option value="high">{t('sites.levelHigh')}</Select.Option>
                    <Select.Option value="strict">{t('sites.levelStrict')}</Select.Option>
                  </Select>
                </label>
              ))}
              </div>
            </section>

            <section className="site-form-section">
              <header className="site-form-section-header">
                <strong>{t('sites.detectors')}</strong>
                <span>{t('sites.detectorsHint')}</span>
              </header>
              <div className="site-protection-switch-grid">
              {[
                ['semantic_sql', 'SQLi'],
                ['semantic_xss', 'XSS'],
                ['semantic_rce', 'RCE'],
                ['semantic_lfi', 'LFI'],
                ['semantic_xxe', 'XXE'],
                ['semantic_ssrf', 'SSRF'],
                ['semantic_nosql', 'NoSQLi'],
                ['semantic_ssti', 'SSTI'],
                ['bot', 'Bot'],
                ['ratelimit', t('protection.ratelimit')],
                ['acl', t('protection.acl')],
                ['apisec', t('nav.apisec')],
              ].map(([key, label]) => (
                <label className="switch-line" key={String(key)}>
                  <span>{label}</span>
                  <Switch
                    checked={Boolean(site.advanced.protection[key as keyof Site['advanced']['protection']])}
                    onChange={(value) => updateAdvanced('protection', { [key]: value } as Partial<Site['advanced']['protection']>)}
                  />
                </label>
              ))}
              </div>
            </section>

            <section className="site-form-section">
              <header className="site-form-section-header">
                <strong>{t('sites.responseAndAccess')}</strong>
                <span>{t('sites.responseAndAccessHint')}</span>
              </header>
              <div className="site-detail-grid">
              <label className="switch-line"><span>{t('sites.responseInspection')}</span><Switch checked={site.advanced.response.enabled} onChange={(value) => updateAdvanced('response', { enabled: value })} /></label>
              <label><span>{t('sites.responseMaxBody')}</span><ByteUnitInput value={site.advanced.response.max_body_bytes} minBytes={1024} onChange={(value) => updateAdvanced('response', { max_body_bytes: value })} /></label>
              <label className="wide-field"><span>{t('sites.sensitivePatterns')}</span><Input value={asCSV(site.advanced.response.sensitive_patterns)} placeholder="password, token, secret" onChange={(value) => updateAdvanced('response', { sensitive_patterns: splitList(value) })} /><em>{t('sites.sensitivePatternsHint')}</em></label>
              <label className="switch-line"><span>{t('sites.authEnabled')}</span><Switch checked={site.advanced.access_control.auth_enabled} onChange={(value) => updateAdvanced('access_control', { auth_enabled: value })} /></label>
              <label className="switch-line"><span>{t('sites.waitingRoom')}</span><Switch checked={site.advanced.access_control.waiting_room} onChange={(value) => updateAdvanced('access_control', { waiting_room: value })} /></label>
              <label className="switch-line"><span>{t('sites.dynamicGuard')}</span><Switch checked={site.advanced.access_control.dynamic_guard} onChange={(value) => updateAdvanced('access_control', { dynamic_guard: value })} /></label>
              <label className="wide-field"><span>{t('sites.trustedCidrs')}</span><Input value={asCSV(site.advanced.access_control.trusted_cidrs)} placeholder="203.0.113.10, 198.51.100.0/24" onChange={(value) => updateAdvanced('access_control', { trusted_cidrs: splitList(value) })} /><em>{t('sites.trustedCidrsHint')}</em></label>
              </div>
            </section>
          </Tabs.TabPane>

          <Tabs.TabPane key="health" title={<span className="tab-title"><CheckCircle2 size={15} />{t('sites.healthCheck')}</span>}>
            <div className="site-detail-grid">
              <label className="switch-line"><span>{t('sites.healthCheck')}</span><Switch checked={site.advanced.health_check.enabled} onChange={(value) => updateAdvanced('health_check', { enabled: value })} /></label>
              <label><span>{t('sites.healthPath')}</span><Input value={site.advanced.health_check.path} onChange={(value) => updateAdvanced('health_check', { path: value })} /></label>
              <label><span>{t('sites.healthInterval')}</span><DurationStringInput value={site.advanced.health_check.interval} fallback="30s" onChange={(value) => updateAdvanced('health_check', { interval: value })} /></label>
              <label><span>{t('sites.healthTimeout')}</span><DurationStringInput value={site.advanced.health_check.timeout} fallback="3s" onChange={(value) => updateAdvanced('health_check', { timeout: value })} /></label>
              <label><span>{t('sites.healthyThreshold')}</span><InputNumber value={site.advanced.health_check.healthy_threshold} min={1} onChange={(value) => updateAdvanced('health_check', { healthy_threshold: Number(value || 1) })} /></label>
              <label><span>{t('sites.unhealthyThreshold')}</span><InputNumber value={site.advanced.health_check.unhealthy_threshold} min={1} onChange={(value) => updateAdvanced('health_check', { unhealthy_threshold: Number(value || 1) })} /></label>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="rewrite" title={t('sites.rewrite')}>
            <div className="rewrite-toolbar">
              <Button icon={<Plus size={15} />} onClick={addRewrite}>{t('common.add')}</Button>
            </div>
            <div className="rewrite-list">
              {site.advanced.rewrite.map((rule, index) => (
                <div className="rewrite-row" key={rule.id}>
                  <div className="rewrite-row-head">
                    <label className="switch-line"><span>{t('sites.rewriteEnabled')}</span><Switch checked={rule.enabled} onChange={(value) => updateRewrite(index, { enabled: value })} /></label>
                    <Button status="danger" icon={<Trash2 size={15} />} onClick={() => removeRewrite(rule.id)}>{t('common.delete')}</Button>
                  </div>
                  <div className="rewrite-row-grid">
                    <label><span>{t('sites.rewritePattern')}</span><Input value={rule.pattern} placeholder="^/old/(.*)$" onChange={(value) => updateRewrite(index, { pattern: value })} /></label>
                    <label><span>{t('sites.rewriteReplacement')}</span><Input value={rule.replacement} placeholder="/new/$1" onChange={(value) => updateRewrite(index, { replacement: value })} /></label>
                    <label><span>{t('sites.rewriteCode')}</span><InputNumber value={rule.redirect_code} min={0} max={308} onChange={(value) => updateRewrite(index, { redirect_code: Number(value || 0) })} /></label>
                  </div>
                </div>
              ))}
              {!site.advanced.rewrite.length && <Empty description={t('sites.noRewrite')} />}
            </div>
          </Tabs.TabPane>
        </Tabs>
      </fieldset>
    </section>
  );
}

function modeText(mode: string, t: (key: string) => string) {
  if (mode === 'block') {
    return t('sites.modeBlock');
  }
  if (mode === 'monitor') {
    return t('sites.modeMonitor');
  }
  if (mode === 'off') {
    return t('sites.modeOff');
  }
  return mode || '-';
}

function DurationStringInput({
  value,
  fallback,
  onChange,
}: {
  value?: string | number;
  fallback: string;
  onChange: (next: string) => void;
}) {
  const { t } = useTranslation();
  const parts = durationStringToParts(value, fallback);
  const [unit, setUnit] = useState<DurationUnit>(parts.unit);
  useEffect(() => {
    setUnit(parts.unit);
  }, [parts.unit, parts.amount]);
  const emit = (amount: number | string | null | undefined, nextUnit = unit) => {
    const numeric = Math.max(1, Math.round(Number(amount || 1)));
    onChange(`${numeric}${nextUnit}`);
  };
  return (
    <div className="compound-input site-unit-input">
      <InputNumber min={1} value={parts.amount} onChange={(next) => emit(next)} />
      <Select value={unit} onChange={(next) => { const nextUnit = String(next) as DurationUnit; setUnit(nextUnit); emit(parts.amount, nextUnit); }}>
        <Select.Option value="s">{t('common.seconds')}</Select.Option>
        <Select.Option value="m">{t('common.minutes')}</Select.Option>
        <Select.Option value="h">{t('common.hours')}</Select.Option>
        <Select.Option value="d">{t('common.days')}</Select.Option>
      </Select>
    </div>
  );
}

function ByteUnitInput({
  value,
  minBytes = 0,
  defaultUnit = 'MB',
  onChange,
}: {
  value?: number;
  minBytes?: number;
  defaultUnit?: ByteUnit;
  onChange: (next: number) => void;
}) {
  const parts = bytesToUnitParts(value, defaultUnit);
  const [unit, setUnit] = useState<ByteUnit>(parts.unit);
  useEffect(() => {
    setUnit(parts.unit);
  }, [parts.unit, parts.amount]);
  const emit = (amount: number | string | null | undefined, nextUnit = unit) => {
    const numeric = Math.max(0, Number(amount || 0));
    onChange(Math.max(minBytes, Math.round(numeric * byteUnitMultiplier(nextUnit))));
  };
  return (
    <div className="compound-input site-unit-input">
      <InputNumber min={0} value={parts.amount} precision={parts.unit === 'GB' || parts.unit === 'MB' ? 2 : 0} onChange={(next) => emit(next)} />
      <Select value={unit} onChange={(next) => { const nextUnit = String(next) as ByteUnit; setUnit(nextUnit); emit(parts.amount, nextUnit); }}>
        <Select.Option value="KB">KB</Select.Option>
        <Select.Option value="MB">MB</Select.Option>
        <Select.Option value="GB">GB</Select.Option>
      </Select>
    </div>
  );
}

function durationStringToParts(value: string | number | undefined, fallback: string): { amount: number; unit: DurationUnit } {
  const raw = String(value || fallback).trim();
  const match = raw.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/i);
  if (!match) {
    return durationStringToParts(fallback, '30s');
  }
  const amount = Math.max(1, Math.round(Number(match[1]) || 1));
  const unit = String(match[2] || 's').toLowerCase();
  if (unit === 'ms') {
    return { amount: Math.max(1, Math.round(amount / 1000)), unit: 's' };
  }
  if (unit === 'm' || unit === 'h' || unit === 'd') {
    return { amount, unit };
  }
  return { amount, unit: 's' };
}

function bytesToUnitParts(value: number | undefined, defaultUnit: ByteUnit): { amount: number; unit: ByteUnit } {
  const bytes = Math.max(0, Number(value || 0));
  const units: ByteUnit[] = ['GB', 'MB', 'KB'];
  for (const unit of units) {
    const divisor = byteUnitMultiplier(unit);
    if (bytes >= divisor && bytes % divisor === 0) {
      return { amount: bytes / divisor, unit };
    }
  }
  if (bytes > 0) {
    const divisor = byteUnitMultiplier(defaultUnit);
    return { amount: Number((bytes / divisor).toFixed(defaultUnit === 'KB' ? 0 : 2)), unit: defaultUnit };
  }
  return { amount: 0, unit: defaultUnit };
}

function byteUnitMultiplier(unit: ByteUnit) {
  switch (unit) {
    case 'GB':
      return 1024 * 1024 * 1024;
    case 'MB':
      return 1024 * 1024;
    default:
      return 1024;
  }
}

function validateSiteDraft(site: Site, t: (key: string) => string) {
  if (!site.name.trim()) {
    return t('sites.validationName');
  }
  if (!site.domains.some((domain) => domain.trim())) {
    return t('sites.validationDomain');
  }
  if (!site.upstreams.some((upstream) => upstream.trim())) {
    return t('sites.validationUpstream');
  }
  if (!Number.isInteger(site.listen_port) || site.listen_port < 1 || site.listen_port > 65535) {
    return t('sites.validationListen');
  }
  if (site.enable_ssl && site.advanced.certificate.mode === 'file' && (!site.cert_file?.trim() || !site.key_file?.trim())) {
    return t('sites.validationCertFile');
  }
  if (site.enable_ssl && site.advanced.certificate.mode === 'inline' && (!site.advanced.certificate.cert_pem?.trim() || !site.advanced.certificate.key_pem?.trim())) {
    return t('sites.validationCertInline');
  }
  for (const rule of site.advanced.rewrite) {
    if (!rule.enabled) {
      continue;
    }
    if (!rule.pattern.trim()) {
      return t('sites.validationRewrite');
    }
    try {
      new RegExp(rule.pattern);
    } catch {
      return t('sites.validationRewrite');
    }
  }
  return '';
}

function ACMEWizard({
  site,
  providers,
  providersError,
  providersLoading,
  selectedProviderName,
  envRows,
  events,
  loading,
  onEnableMode,
  onPatchACME,
  onEnvRowsChange,
  onIssue,
  onRetryProviders,
  t,
}: {
  site: Site;
  providers: Array<{ id: string; name: string; api: string; env?: Record<string, string> }>;
  providersError?: string;
  providersLoading: boolean;
  selectedProviderName?: string;
  envRows: EnvRow[];
  events: ACMEEvent[];
  loading: boolean;
  onEnableMode: () => void;
  onPatchACME: (patch: Partial<Site['advanced']['certificate']['acme']>) => void;
  onEnvRowsChange: (rows: EnvRow[]) => void;
  onIssue: () => void;
  onRetryProviders: () => void;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  const acme = site.advanced.certificate.acme;
  const currentStep = Math.max(0, acmeStepOrder.findIndex((step) => {
    const event = latestEvent(events, step);
    return event?.status === 'running' || event?.status === 'failed';
  }));
  const canIssue = Boolean(site.domains.length && acme.dns_api && (acme.provider_id || envRows.some((row) => row.key.trim() && row.value.trim())));
  const updateEnv = (id: string, patch: Partial<EnvRow>) => {
    onEnvRowsChange(envRows.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  };
  const addEnv = () => onEnvRowsChange([...envRows, { id: `env-${Date.now()}`, key: '', value: '' }]);
  const removeEnv = (id: string) => onEnvRowsChange(envRows.filter((row) => row.id !== id));

  return (
    <section className="acme-wizard">
      <header className="acme-wizard-header">
        <div>
          <h2><KeyRound size={17} /> {t('sites.acmeWizardTitle')}</h2>
          <p>{t('sites.acmeWizardHint')}</p>
        </div>
        <Space wrap>
          <Tag color={site.advanced.certificate.mode === 'acme' ? 'green' : 'gray'}>{site.advanced.certificate.mode === 'acme' ? t('sites.certAcme') : t('sites.acmeNotActive')}</Tag>
          <Button onClick={onEnableMode}>{t('sites.acmeUseMode')}</Button>
          <Button type="primary" loading={loading} disabled={!canIssue} onClick={onIssue}>
            {t('sites.acmeIssue')}
          </Button>
        </Space>
      </header>

      <div className="acme-layout">
        <section className="acme-config-block">
          {providersError && (
            <div className="inline-error acme-provider-error" role="alert">
              <span>{providersError}</span>
              <Button size="small" onClick={onRetryProviders}>{t('common.retry')}</Button>
            </div>
          )}
          <div className="site-detail-grid acme-config-grid">
            <label>
              <span>{t('sites.acmeProvider')}</span>
              <Select
                value={acme.provider_id}
                allowClear
                loading={providersLoading}
                placeholder={t('sites.acmeProviderPlaceholder')}
                onChange={(providerID) => {
                  const provider = providers.find((item) => item.id === providerID);
                  onPatchACME({ provider_id: String(providerID ?? ''), dns_api: provider?.api ?? acme.dns_api });
                }}
              >
                {providers.map((provider) => (
                  <Select.Option key={provider.id} value={provider.id}>
                    {provider.name || provider.id} · {provider.api}
                  </Select.Option>
                ))}
              </Select>
            </label>
            <label>
              <span>{t('sites.acmeDNSAPI')}</span>
              <Input value={acme.dns_api} placeholder="dns_cf" onChange={(dns_api) => onPatchACME({ dns_api })} />
            </label>
            <label>
              <span>{t('sites.acmeAccountEmail')}</span>
              <Input value={acme.account_email} placeholder="ops@example.com" onChange={(account_email) => onPatchACME({ account_email })} />
            </label>
            <label>
              <span>{t('sites.acmeServer')}</span>
              <Select value={acme.server || 'letsencrypt'} onChange={(server) => onPatchACME({ server: server as string })}>
                <Select.Option value="letsencrypt">Let's Encrypt</Select.Option>
                <Select.Option value="zerossl">ZeroSSL</Select.Option>
                <Select.Option value="https://acme-v02.api.letsencrypt.org/directory">Let's Encrypt API</Select.Option>
                <Select.Option value="https://acme-staging-v02.api.letsencrypt.org/directory">Let's Encrypt Staging</Select.Option>
              </Select>
            </label>
            <label>
              <span>{t('sites.acmeKeyType')}</span>
              <Select value={acme.key_type || 'ec-256'} onChange={(key_type) => onPatchACME({ key_type: key_type as string })}>
                <Select.Option value="ec-256">ECDSA P-256</Select.Option>
                <Select.Option value="ec-384">ECDSA P-384</Select.Option>
                <Select.Option value="2048">RSA 2048</Select.Option>
                <Select.Option value="3072">RSA 3072</Select.Option>
                <Select.Option value="4096">RSA 4096</Select.Option>
              </Select>
            </label>
            <label className="switch-line">
              <span>{t('sites.acmeNotify')}</span>
              <Switch checked={acme.notify} onChange={(notify) => onPatchACME({ notify })} />
            </label>
          </div>
        </section>

        <section className="acme-env-block">
          <header className="fieldset-header-action">
            <div>
              <strong>{t('sites.acmeDNSEnv')}</strong>
              <span>{selectedProviderName ? t('sites.acmeProviderUsingSavedEnv', { name: selectedProviderName }) : t('sites.acmeDNSEnvHint')}</span>
            </div>
            <Button size="small" icon={<Plus size={14} />} onClick={addEnv}>{t('common.add')}</Button>
          </header>
          <div className="acme-env-list">
            {envRows.map((row) => (
              <div className="acme-env-row" key={row.id}>
                <Input value={row.key} placeholder="CF_TOKEN" onChange={(key) => updateEnv(row.id, { key: key.toUpperCase().replace(/[^A-Z0-9_]/g, '') })} />
                <Input.Password value={row.value} placeholder={t('sites.acmeSecretValue')} onChange={(value) => updateEnv(row.id, { value })} />
                <Button
                  icon={<Trash2 size={14} />}
                  status="danger"
                  aria-label={t('common.delete')}
                  title={t('common.delete')}
                  onClick={() => removeEnv(row.id)}
                />
              </div>
            ))}
            {!envRows.length && (
              <div className="empty-state"><CircleAlert size={16} /> {t('sites.acmeDNSEnvEmpty')}</div>
            )}
          </div>
        </section>
      </div>

      <section className="acme-pipeline">
        <Steps current={currentStep} size="small" className="acme-steps">
          {acmeStepOrder.map((step) => {
            const event = latestEvent(events, step);
            const status = event?.status === 'failed' ? 'error' : event?.status === 'succeeded' ? 'finish' : event?.status === 'running' ? 'process' : 'wait';
            return <Steps.Step key={step} status={status} title={t(`sites.acmeStep.${step}`)} description={event?.message} />;
          })}
        </Steps>
        <div className="acme-events">
          {events.length ? events.map((event, index) => (
            <details className={`acme-event acme-event-${event.status}`} key={`${event.step}-${index}`} open={event.status === 'failed'}>
              <summary>
                <span><Clock3 size={14} /> {t(`sites.acmeStep.${event.step}`)}</span>
                <Tag color={event.status === 'failed' ? 'red' : event.status === 'succeeded' ? 'green' : 'blue'}>{stepStatusText(event.status, t)}</Tag>
              </summary>
              <p>{event.message}</p>
              {event.output && <pre>{event.output}</pre>}
            </details>
          )) : (
            <div className="empty-state"><LockKeyhole size={16} /> {t('sites.acmeNoEvents')}</div>
          )}
        </div>
      </section>
    </section>
  );
}

function queryErrorMessage(error: unknown, fallbackMessage: string) {
  return error instanceof Error && error.message.trim() ? error.message : fallbackMessage;
}

function envToRows(env: Record<string, string> | undefined): EnvRow[] {
  return Object.entries(env ?? {}).map(([key, value]) => ({ id: `env-${key}-${Math.random().toString(16).slice(2)}`, key, value }));
}

function rowsToEnv(rows: EnvRow[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim().toUpperCase();
    if (key && row.value.trim()) {
      env[key] = row.value;
    }
  }
  return env;
}

function latestEvent(events: ACMEEvent[], step: string) {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    if (events[index].step === step) {
      return events[index];
    }
  }
  return undefined;
}

function initialACMEEvents(): ACMEEvent[] {
  return acmeStepOrder.map((step) => ({
    step,
    status: 'pending',
    timestamp: new Date().toISOString(),
  }));
}

function stepStatusText(status: string, t: (key: string) => string) {
  if (status === 'succeeded') {
    return t('sites.acmeSucceeded');
  }
  if (status === 'failed') {
    return t('sites.acmeFailed');
  }
  if (status === 'running') {
    return t('sites.acmeRunning');
  }
  return t('sites.acmePending');
}

function normalizeACMEProviderList(value: unknown): ACMEDNSProvider[] {
  const maybeList = Array.isArray(value)
    ? value
    : value && typeof value === 'object'
      ? Object.values(value as Record<string, unknown>).find((item) => Array.isArray(item))
      : [];
  if (!Array.isArray(maybeList)) {
    return [];
  }
  return maybeList
    .filter((item): item is Partial<ACMEDNSProvider> => Boolean(item) && typeof item === 'object')
    .map((item) => ({
      id: String(item.id ?? '').trim(),
      name: String(item.name ?? item.id ?? '').trim(),
      api: String(item.api ?? '').trim(),
      env: item.env && typeof item.env === 'object' && !Array.isArray(item.env)
        ? Object.fromEntries(Object.entries(item.env).map(([key, val]) => [key, String(val ?? '')]))
        : {},
      enabled: item.enabled !== false,
    }))
    .filter((provider) => provider.id !== '');
}
