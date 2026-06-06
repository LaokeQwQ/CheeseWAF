import {
  Button,
  Empty,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Select,
  Space,
  Spin,
  Switch,
  Tabs,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle2, LockKeyhole, Network, Plus, Save, ShieldCheck, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { deleteSite, fetchSite, updateSite } from '../../api/client';
import type { Site, SiteAdvanced, SiteRewriteRule } from '../../types/api';
import { asCSV, normalizeSite, splitList } from './siteModel';

export default function SiteDetailPage() {
  const { t } = useTranslation();
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [site, setSite] = useState<Site | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ['site', id],
    queryFn: () => fetchSite(id),
    retry: false,
    enabled: Boolean(id),
  });

  useEffect(() => {
    if (data) {
      setSite(normalizeSite(data));
    }
  }, [data]);

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

  if (isLoading) {
    return <Spin className="page-spinner" />;
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
            { id: `rewrite-${Date.now()}`, pattern: '^/old/(.*)$', replacement: '/new/$1', redirect_code: 0, enabled: true },
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

  return (
    <section className="page-surface">
      <header className="page-header">
        <div className="site-title-stack">
          <Button icon={<ArrowLeft size={16} />} onClick={() => navigate('/sites')}>
            {t('common.back')}
          </Button>
          <div>
            <h1>{site.name}</h1>
            <p>{site.domains.join(', ')}</p>
          </div>
        </div>
        <Space wrap>
          <Tag color={site.enabled ? 'green' : 'gray'}>{site.enabled ? t('common.online') : t('sites.disabled')}</Tag>
          <Button status="danger" icon={<Trash2 size={16} />} loading={deleteMutation.isPending} onClick={() => {
            if (window.confirm(t('sites.deleteConfirm'))) {
              deleteMutation.mutate();
            }
          }}>
            {t('common.delete')}
          </Button>
          <Button type="primary" icon={<Save size={16} />} loading={saveMutation.isPending} onClick={() => saveMutation.mutate(site)}>
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

      <section className="panel">
        <Tabs defaultActiveTab="basic">
          <Tabs.TabPane key="basic" title={<span className="tab-title"><Network size={15} />{t('sites.stepBasic')}</span>}>
            <div className="site-detail-grid">
              <label><span>{t('sites.name')}</span><Input value={site.name} onChange={(value) => updateField('name', value)} /></label>
              <label><span>{t('sites.domain')}</span><Input value={asCSV(site.domains)} onChange={(value) => updateField('domains', splitList(value))} /></label>
              <label><span>{t('sites.upstream')}</span><Input value={asCSV(site.upstreams)} onChange={(value) => updateField('upstreams', splitList(value))} /></label>
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
              <label>
                <span>{t('sites.originScheme')}</span>
                <Select value={site.advanced.origin.scheme} onChange={(value) => updateAdvanced('origin', { scheme: value as string })}>
                  <Select.Option value="http">HTTP</Select.Option>
                  <Select.Option value="https">HTTPS</Select.Option>
                </Select>
              </label>
              <label className="switch-line"><span>{t('sites.passHost')}</span><Switch checked={site.advanced.origin.pass_host} onChange={(value) => updateAdvanced('origin', { pass_host: value })} /></label>
              <label><span>{t('sites.hostHeader')}</span><Input value={site.advanced.origin.host_header} onChange={(value) => updateAdvanced('origin', { host_header: value })} /></label>
              <label><span>{t('sites.proxyTimeout')}</span><Input value={String(site.advanced.origin.proxy_timeout)} onChange={(value) => updateAdvanced('origin', { proxy_timeout: value })} /></label>
              <label><span>{t('sites.maxBody')}</span><InputNumber value={site.advanced.origin.max_body_bytes} min={1024} step={1024 * 1024} onChange={(value) => updateAdvanced('origin', { max_body_bytes: Number(value || 0) })} /></label>
              <label><span>{t('sites.maxHeader')}</span><InputNumber value={site.advanced.origin.max_header_size} min={1024} step={1024} onChange={(value) => updateAdvanced('origin', { max_header_size: Number(value || 0) })} /></label>
            </div>
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
          </Tabs.TabPane>

          <Tabs.TabPane key="protection" title={<span className="tab-title"><ShieldCheck size={15} />{t('sites.stepProtection')}</span>}>
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
              {[
                ['semantic_sql', 'SQLi'],
                ['semantic_xss', 'XSS'],
                ['semantic_rce', 'RCE'],
                ['semantic_lfi', 'LFI'],
                ['semantic_xxe', 'XXE'],
                ['semantic_ssrf', 'SSRF'],
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
              <label className="switch-line"><span>{t('sites.responseInspection')}</span><Switch checked={site.advanced.response.enabled} onChange={(value) => updateAdvanced('response', { enabled: value })} /></label>
              <label><span>{t('sites.responseMaxBody')}</span><InputNumber value={site.advanced.response.max_body_bytes} min={1024} step={1024 * 1024} onChange={(value) => updateAdvanced('response', { max_body_bytes: Number(value || 0) })} /></label>
              <label className="wide-field"><span>{t('sites.sensitivePatterns')}</span><Input value={asCSV(site.advanced.response.sensitive_patterns)} onChange={(value) => updateAdvanced('response', { sensitive_patterns: splitList(value) })} /></label>
              <label className="switch-line"><span>{t('sites.authEnabled')}</span><Switch checked={site.advanced.access_control.auth_enabled} onChange={(value) => updateAdvanced('access_control', { auth_enabled: value })} /></label>
              <label className="switch-line"><span>{t('sites.waitingRoom')}</span><Switch checked={site.advanced.access_control.waiting_room} onChange={(value) => updateAdvanced('access_control', { waiting_room: value })} /></label>
              <label className="switch-line"><span>{t('sites.dynamicGuard')}</span><Switch checked={site.advanced.access_control.dynamic_guard} onChange={(value) => updateAdvanced('access_control', { dynamic_guard: value })} /></label>
              <label className="wide-field"><span>{t('sites.trustedCidrs')}</span><Input value={asCSV(site.advanced.access_control.trusted_cidrs)} onChange={(value) => updateAdvanced('access_control', { trusted_cidrs: splitList(value) })} /></label>
            </div>
          </Tabs.TabPane>

          <Tabs.TabPane key="health" title={<span className="tab-title"><CheckCircle2 size={15} />{t('sites.healthCheck')}</span>}>
            <div className="site-detail-grid">
              <label className="switch-line"><span>{t('sites.healthCheck')}</span><Switch checked={site.advanced.health_check.enabled} onChange={(value) => updateAdvanced('health_check', { enabled: value })} /></label>
              <label><span>{t('sites.healthPath')}</span><Input value={site.advanced.health_check.path} onChange={(value) => updateAdvanced('health_check', { path: value })} /></label>
              <label><span>{t('sites.healthInterval')}</span><Input value={String(site.advanced.health_check.interval)} onChange={(value) => updateAdvanced('health_check', { interval: value })} /></label>
              <label><span>{t('sites.healthTimeout')}</span><Input value={String(site.advanced.health_check.timeout)} onChange={(value) => updateAdvanced('health_check', { timeout: value })} /></label>
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
                  <Switch checked={rule.enabled} onChange={(value) => updateRewrite(index, { enabled: value })} />
                  <Input value={rule.pattern} placeholder="^/old/(.*)$" onChange={(value) => updateRewrite(index, { pattern: value })} />
                  <Input value={rule.replacement} placeholder="/new/$1" onChange={(value) => updateRewrite(index, { replacement: value })} />
                  <InputNumber value={rule.redirect_code} min={0} max={308} onChange={(value) => updateRewrite(index, { redirect_code: Number(value || 0) })} />
                  <Button status="danger" icon={<Trash2 size={15} />} onClick={() => removeRewrite(rule.id)} />
                </div>
              ))}
              {!site.advanced.rewrite.length && <Empty description={t('sites.noRewrite')} />}
            </div>
          </Tabs.TabPane>
        </Tabs>
      </section>
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
