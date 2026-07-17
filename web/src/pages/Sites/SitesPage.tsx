import {
  Button,
  Empty,
  Input,
  InputNumber,
  Message as ArcoMessage,
  Modal,
  Select,
  Space,
  Steps,
  Switch,
  Table,
  Tag,
} from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, LockKeyhole, Network, Plus, Route, Server, ShieldCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { createSite, fetchSites } from '../../api/client';
import type { Site } from '../../types/api';
import { defaultSiteAdvanced, splitList } from './siteModel';
import './SitesPage.css';

type WizardDraft = {
  name: string;
  domains: string;
  upstreams: string;
  listenPort: number;
  loadbalance: string;
  enabled: boolean;
  wafEnabled: boolean;
  wafMode: string;
  enableSSL: boolean;
  certFile: string;
  keyFile: string;
  certPEM: string;
  keyPEM: string;
  certificateMode: string;
  forceHTTPS: boolean;
  hsts: boolean;
  minTLSVersion: string;
  originScheme: string;
  passHost: boolean;
  hostHeader: string;
  proxyTimeout: string;
  maxBodyBytes: number;
  healthCheck: boolean;
  healthPath: string;
  bot: boolean;
  ratelimit: boolean;
  acl: boolean;
  apisec: boolean;
};

const initialDraft: WizardDraft = {
  name: '',
  domains: '',
  upstreams: '',
  listenPort: 80,
  loadbalance: 'round_robin',
  enabled: true,
  wafEnabled: true,
  wafMode: 'block',
  enableSSL: false,
  certFile: '',
  keyFile: '',
  certPEM: '',
  keyPEM: '',
  certificateMode: 'file',
  forceHTTPS: false,
  hsts: true,
  minTLSVersion: '1.2',
  originScheme: 'http',
  passHost: true,
  hostHeader: '',
  proxyTimeout: '30s',
  maxBodyBytes: 64 * 1024 * 1024,
  healthCheck: false,
  healthPath: '/',
  bot: false,
  ratelimit: true,
  acl: true,
  apisec: true,
};

export default function SitesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [draft, setDraft] = useState<WizardDraft>(initialDraft);
  const { data, error, isError, isLoading, refetch } = useQuery({
    queryKey: ['sites'],
    queryFn: fetchSites,
    retry: false,
  });
  const mutation = useMutation({
    mutationFn: createSite,
    onSuccess: (site) => {
      ArcoMessage.success(t('sites.created'));
      setOpen(false);
      setStep(0);
      setDraft(initialDraft);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      navigate(`/sites/${site.id}`);
    },
    onError: (error) => ArcoMessage.error(error.message),
  });
  const rows = data ?? [];
  const basicStepValid = useMemo(
    () => Boolean(draft.name.trim() && splitList(draft.domains).length && splitList(draft.upstreams).length),
    [draft],
  );
  const tlsStepValid = useMemo(() => {
    if (!draft.enableSSL || draft.certificateMode === 'acme') {
      return true;
    }
    if (draft.certificateMode === 'inline') {
      return Boolean(draft.certPEM.trim() && draft.keyPEM.trim());
    }
    return Boolean(draft.certFile.trim() && draft.keyFile.trim());
  }, [draft]);
  const canCreate = basicStepValid && tlsStepValid;
  const canAdvance = step === 0 ? basicStepValid : step === 1 ? tlsStepValid : true;

  const updateDraft = <K extends keyof WizardDraft>(key: K, value: WizardDraft[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
  };
  const closeWizard = () => {
    setOpen(false);
    setStep(0);
    setDraft(initialDraft);
  };
  const renderMode = (mode: string) => {
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
  };
  const createPayload = (): Partial<Site> => ({
    name: draft.name.trim(),
    domains: splitList(draft.domains),
    upstreams: splitList(draft.upstreams),
    listen_port: draft.listenPort,
    loadbalance: draft.loadbalance,
    enable_ssl: draft.enableSSL,
    cert_file: draft.enableSSL && draft.certificateMode === 'file' ? draft.certFile.trim() : '',
    key_file: draft.enableSSL && draft.certificateMode === 'file' ? draft.keyFile.trim() : '',
    waf_enabled: draft.wafEnabled,
    waf_mode: draft.wafMode,
    enabled: draft.enabled,
    advanced: {
      ...defaultSiteAdvanced,
      certificate: {
        ...defaultSiteAdvanced.certificate,
        mode: draft.certificateMode,
        cert_pem: draft.enableSSL && draft.certificateMode === 'inline' ? draft.certPEM.trim() : '',
        key_pem: draft.enableSSL && draft.certificateMode === 'inline' ? draft.keyPEM.trim() : '',
        force_https: draft.forceHTTPS,
        hsts: draft.hsts,
        min_tls_version: draft.minTLSVersion,
      },
      origin: {
        ...defaultSiteAdvanced.origin,
        scheme: draft.originScheme,
        pass_host: draft.passHost,
        host_header: draft.hostHeader.trim(),
        proxy_timeout: draft.proxyTimeout,
        max_body_bytes: draft.maxBodyBytes,
      },
      health_check: {
        ...defaultSiteAdvanced.health_check,
        enabled: draft.healthCheck,
        path: draft.healthPath || '/',
      },
      protection: {
        ...defaultSiteAdvanced.protection,
        bot: draft.bot,
        ratelimit: draft.ratelimit,
        acl: draft.acl,
        apisec: draft.apisec,
      },
    },
  });

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('sites.title')}</h1>
          <p>{t('sites.subtitle')}</p>
        </div>
        <Button type="primary" icon={<Plus size={16} />} onClick={() => setOpen(true)}>
          {t('sites.create')}
        </Button>
      </header>

      <section className="table-panel sites-list-panel">
        {isError && (
          <div className="inline-error sites-query-error" role="alert">
            <span>{queryErrorMessage(error, t('common.noData'))}</span>
            <Button size="small" onClick={() => refetch()}>{t('common.retry')}</Button>
          </div>
        )}
        <div className="sites-desktop-table">
          <Table
            rowKey="id"
            pagination={false}
            loading={isLoading}
            data={rows}
            className="sites-table"
            scroll={{ x: 920 }}
            noDataElement={<Empty description={t('common.noData')} />}
            columns={[
              {
                title: t('sites.name'),
                dataIndex: 'name',
                ellipsis: true,
                render: (name: string, record: Site) => (
                  <button className="table-link site-table-link" title={name} type="button" onClick={() => navigate(`/sites/${record.id}`)}>
                    <Server size={16} />
                    <span>{name}</span>
                  </button>
                ),
              },
              {
                title: t('sites.domain'),
                ellipsis: true,
                render: (_: unknown, record: Site) => {
                  const value = record.domains?.join(', ') || '-';
                  return <span className="site-table-text" title={value}>{value}</span>;
                },
              },
              {
                title: t('sites.upstream'),
                ellipsis: true,
                render: (_: unknown, record: Site) => {
                  const value = record.upstreams?.join(', ') || '-';
                  return <span className="site-table-text" title={value}>{value}</span>;
                },
              },
              {
                title: t('sites.listen'),
                dataIndex: 'listen_port',
                width: 88,
                render: (port: number) => <code>:{port || 80}</code>,
              },
              {
                title: t('sites.mode'),
                dataIndex: 'waf_mode',
                width: 100,
                render: (mode: string) => <Tag color={mode === 'block' ? 'green' : mode === 'monitor' ? 'orange' : 'gray'}>{renderMode(mode)}</Tag>,
              },
              {
                title: t('sites.status'),
                dataIndex: 'enabled',
                width: 96,
                render: (enabled: boolean) => <Tag color={enabled ? 'green' : 'gray'}>{enabled ? t('common.online') : t('sites.disabled')}</Tag>,
              },
              {
                title: t('common.actions'),
                width: 104,
                fixed: 'right' as const,
                render: (_: unknown, record: Site) => (
                  <div className="site-table-actions">
                    <Button size="small" onClick={() => navigate(`/sites/${record.id}`)}>
                      {t('sites.manage')}
                    </Button>
                  </div>
                ),
              },
            ]}
          />
        </div>
        <div className="sites-mobile-list">
          {isLoading ? <div className="skeleton-list" /> : rows.length ? rows.map((site) => {
            const domains = site.domains?.join(', ') || '-';
            const upstreams = site.upstreams?.join(', ') || '-';
            return (
              <article className="mobile-data-card sites-mobile-card" key={site.id}>
                <header>
                  <button className="sites-mobile-title" title={site.name} type="button" onClick={() => navigate(`/sites/${site.id}`)}>
                    <Server size={17} />
                    <strong>{site.name}</strong>
                  </button>
                  <Tag color={site.enabled ? 'green' : 'gray'}>{site.enabled ? t('common.online') : t('sites.disabled')}</Tag>
                </header>
                <dl>
                  <div><dt>{t('sites.domain')}</dt><dd title={domains}>{domains}</dd></div>
                  <div><dt>{t('sites.upstream')}</dt><dd title={upstreams}>{upstreams}</dd></div>
                  <div><dt>{t('sites.listen')}</dt><dd><code>:{site.listen_port || 80}</code></dd></div>
                  <div><dt>{t('sites.mode')}</dt><dd>{renderMode(site.waf_mode)}</dd></div>
                </dl>
                <footer>
                  <Button type="primary" onClick={() => navigate(`/sites/${site.id}`)}>{t('sites.manage')}</Button>
                </footer>
              </article>
            );
          }) : !isError ? <Empty description={t('common.noData')} /> : null}
        </div>
      </section>

      <Modal
        className="site-wizard-modal"
        title={t('sites.create')}
        visible={open}
        onCancel={closeWizard}
        footer={(
          <div className="modal-actions">
            <Button disabled={step === 0} onClick={() => setStep((value) => Math.max(0, value - 1))}>
              {t('common.back')}
            </Button>
            {step < 3 ? (
              <Button type="primary" disabled={!canAdvance} onClick={() => setStep((value) => Math.min(3, value + 1))}>
                {t('common.next')}
              </Button>
            ) : (
              <Button type="primary" disabled={!canCreate} loading={mutation.isPending} onClick={() => mutation.mutate(createPayload())}>
                {t('common.finish')}
              </Button>
            )}
          </div>
        )}
      >
        <Steps current={step + 1} size="small" className="setup-steps">
          <Steps.Step title={t('sites.stepBasic')} icon={<Network size={16} />} />
          <Steps.Step title={t('sites.stepTls')} icon={<LockKeyhole size={16} />} />
          <Steps.Step title={t('sites.stepProtection')} icon={<ShieldCheck size={16} />} />
          <Steps.Step title={t('sites.stepReview')} icon={<CheckCircle2 size={16} />} />
        </Steps>

        {step === 0 && (
          <div className="site-wizard-grid">
            <div className="site-flow" aria-hidden>
              <div className="site-flow-node">{t('sites.flowClient')}</div>
              <Route size={18} />
              <div className="site-flow-node site-flow-node-active">CheeseWAF</div>
              <Route size={18} />
              <div className="site-flow-node">{t('sites.flowOrigin')}</div>
            </div>
            <div className="form-grid">
              <label>
                <span>{t('sites.name')}</span>
                <Input value={draft.name} placeholder="portal.example.com" onChange={(value) => updateDraft('name', value)} />
              </label>
              <label>
                <span>{t('sites.domain')}</span>
                <Input value={draft.domains} placeholder="example.com, www.example.com" onChange={(value) => updateDraft('domains', value)} />
              </label>
              <label>
                <span>{t('sites.upstream')}</span>
                <Input value={draft.upstreams} placeholder="127.0.0.1:9000, 10.0.0.12:8080" onChange={(value) => updateDraft('upstreams', value)} />
              </label>
              <label>
                <span>{t('sites.listen')}</span>
                <InputNumber value={draft.listenPort} min={1} max={65535} onChange={(value) => updateDraft('listenPort', Number(value || 80))} />
              </label>
              <label>
                <span>{t('sites.loadBalance')}</span>
                <Select value={draft.loadbalance} onChange={(value) => updateDraft('loadbalance', value as string)}>
                  <Select.Option value="round_robin">{t('sites.lbRoundRobin')}</Select.Option>
                  <Select.Option value="weighted">{t('sites.lbWeighted')}</Select.Option>
                  <Select.Option value="ip_hash">{t('sites.lbIPHash')}</Select.Option>
                </Select>
              </label>
              <label>
                <span>{t('sites.originScheme')}</span>
                <Select value={draft.originScheme} onChange={(value) => updateDraft('originScheme', value as string)}>
                  <Select.Option value="http">HTTP</Select.Option>
                  <Select.Option value="https">HTTPS</Select.Option>
                </Select>
              </label>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="form-grid">
            <label className="switch-line"><span>{t('sites.enableSsl')}</span><Switch checked={draft.enableSSL} onChange={(value) => updateDraft('enableSSL', value)} /></label>
            <label>
              <span>{t('sites.certificateMode')}</span>
              <Select value={draft.certificateMode} onChange={(value) => updateDraft('certificateMode', value as string)}>
                <Select.Option value="file">{t('sites.certFile')}</Select.Option>
                <Select.Option value="inline">{t('sites.certInline')}</Select.Option>
                <Select.Option value="acme">{t('sites.certAcme')}</Select.Option>
              </Select>
            </label>
            {draft.enableSSL && draft.certificateMode === 'file' && (
              <>
                <label><span>{t('sites.certFile')}</span><Input value={draft.certFile} placeholder="/etc/cheesewaf/certs/site.crt" onChange={(value) => updateDraft('certFile', value)} /></label>
                <label><span>{t('sites.keyFile')}</span><Input value={draft.keyFile} placeholder="/etc/cheesewaf/certs/site.key" onChange={(value) => updateDraft('keyFile', value)} /></label>
              </>
            )}
            {draft.enableSSL && draft.certificateMode === 'inline' && (
              <>
                <label className="wide-field"><span>{t('sites.certPem')}</span><Input.TextArea value={draft.certPEM} autoSize={{ minRows: 4, maxRows: 8 }} onChange={(value) => updateDraft('certPEM', value)} /></label>
                <label className="wide-field"><span>{t('sites.keyPem')}</span><Input.TextArea value={draft.keyPEM} autoSize={{ minRows: 4, maxRows: 8 }} onChange={(value) => updateDraft('keyPEM', value)} /></label>
              </>
            )}
            <label className="switch-line"><span>{t('sites.forceHttps')}</span><Switch checked={draft.forceHTTPS} onChange={(value) => updateDraft('forceHTTPS', value)} /></label>
            <label className="switch-line"><span>{t('sites.hsts')}</span><Switch checked={draft.hsts} onChange={(value) => updateDraft('hsts', value)} /></label>
            <label>
              <span>{t('sites.minTls')}</span>
              <Select value={draft.minTLSVersion} onChange={(value) => updateDraft('minTLSVersion', value as string)}>
                <Select.Option value="1.2">TLS 1.2</Select.Option>
                <Select.Option value="1.3">TLS 1.3</Select.Option>
              </Select>
            </label>
          </div>
        )}

        {step === 2 && (
          <div className="form-grid">
            <label className="switch-line"><span>{t('sites.wafEnabled')}</span><Switch checked={draft.wafEnabled} onChange={(value) => updateDraft('wafEnabled', value)} /></label>
            <label>
              <span>{t('sites.wafMode')}</span>
              <Select value={draft.wafMode} onChange={(value) => updateDraft('wafMode', value as string)}>
                <Select.Option value="block">{t('sites.modeBlock')}</Select.Option>
                <Select.Option value="monitor">{t('sites.modeMonitor')}</Select.Option>
                <Select.Option value="off">{t('sites.modeOff')}</Select.Option>
              </Select>
            </label>
            <label><span>{t('sites.proxyTimeout')}</span><Input value={draft.proxyTimeout} placeholder="30s" onChange={(value) => updateDraft('proxyTimeout', value)} /></label>
            <label><span>{t('sites.maxBody')}</span><InputNumber value={draft.maxBodyBytes} min={1024} step={1024 * 1024} onChange={(value) => updateDraft('maxBodyBytes', Number(value || 0))} /></label>
            <label className="switch-line"><span>{t('sites.passHost')}</span><Switch checked={draft.passHost} onChange={(value) => updateDraft('passHost', value)} /></label>
            <label><span>{t('sites.hostHeader')}</span><Input value={draft.hostHeader} placeholder="origin.example.internal" onChange={(value) => updateDraft('hostHeader', value)} /></label>
            <label className="switch-line"><span>Bot</span><Switch checked={draft.bot} onChange={(value) => updateDraft('bot', value)} /></label>
            <label className="switch-line"><span>{t('protection.ratelimit')}</span><Switch checked={draft.ratelimit} onChange={(value) => updateDraft('ratelimit', value)} /></label>
            <label className="switch-line"><span>{t('protection.acl')}</span><Switch checked={draft.acl} onChange={(value) => updateDraft('acl', value)} /></label>
            <label className="switch-line"><span>{t('nav.apisec')}</span><Switch checked={draft.apisec} onChange={(value) => updateDraft('apisec', value)} /></label>
            <label className="switch-line"><span>{t('sites.healthCheck')}</span><Switch checked={draft.healthCheck} onChange={(value) => updateDraft('healthCheck', value)} /></label>
            <label><span>{t('sites.healthPath')}</span><Input value={draft.healthPath} placeholder="/health" onChange={(value) => updateDraft('healthPath', value)} /></label>
          </div>
        )}

        {step === 3 && (
          <div className="site-review">
            <strong>{draft.name || '-'}</strong>
            <span>{splitList(draft.domains).join(', ') || '-'}</span>
            <div>
              <Tag color="blue">{draft.originScheme.toUpperCase()}</Tag>
              <Tag color={draft.wafMode === 'block' ? 'green' : 'orange'}>{renderMode(draft.wafMode)}</Tag>
              <Tag color={draft.enableSSL ? 'green' : 'gray'}>{draft.enableSSL ? 'TLS' : 'HTTP'}</Tag>
            </div>
            <Space wrap>
              {splitList(draft.upstreams).map((upstream) => <code key={upstream}>{upstream}</code>)}
            </Space>
          </div>
        )}
      </Modal>
    </section>
  );
}

function queryErrorMessage(error: unknown, fallbackMessage: string) {
  return error instanceof Error && error.message.trim() ? error.message : fallbackMessage;
}
