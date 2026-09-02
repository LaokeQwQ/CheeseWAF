import {
  Badge,
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Empty,
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
  Textarea,
  toast,
} from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, FileDown, LockKeyhole, Network, Plus, Route, Server, ShieldCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { createSite, fetchSites, importNginx } from '../../api/client';
import type { Site } from '../../types/api';
import {
  NGINX_IMPORT_MAX_BYTES,
  type NginxImportIssue,
  type NginxImportRow,
  countNginxServerBlocks,
  defaultSiteAdvanced,
  nginxImportPayload,
  nginxImportRows,
  splitList,
} from './siteModel';
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

const wizardSteps = [
  { key: 'basic', icon: Network },
  { key: 'tls', icon: LockKeyhole },
  { key: 'protection', icon: ShieldCheck },
  { key: 'review', icon: CheckCircle2 },
] as const;

type NginxPhase = 'input' | 'preview' | 'result';

type NginxOutcome = { name: string; ok: boolean; message: string };

/** Written out in full so the locale dead-key audit can see every key. */
const nginxIssueKeys: Record<NginxImportIssue, string> = {
  '': '',
  name: 'sites.import.issue.name',
  domain: 'sites.import.issue.domain',
  upstream: 'sites.import.issue.upstream',
};

const nginxSample = [
  'server {',
  '    listen 80;',
  '    server_name example.com www.example.com;',
  '',
  '    location / {',
  '        proxy_pass http://127.0.0.1:9000;',
  '    }',
  '}',
].join('\n');

export default function SitesPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(0);
  const [draft, setDraft] = useState<WizardDraft>(initialDraft);
  const [nginxOpen, setNginxOpen] = useState(false);
  const [nginxPhase, setNginxPhase] = useState<NginxPhase>('input');
  const [nginxText, setNginxText] = useState('');
  const [nginxMessage, setNginxMessage] = useState('');
  const [nginxRows, setNginxRows] = useState<NginxImportRow[]>([]);
  const [nginxSkipped, setNginxSkipped] = useState(0);
  const [nginxSelection, setNginxSelection] = useState<number[]>([]);
  const [nginxResults, setNginxResults] = useState<NginxOutcome[]>([]);
  const [parsing, setParsing] = useState(false);
  const [importing, setImporting] = useState(false);
  const { data, error, isError, isLoading, refetch } = useQuery({
    queryKey: ['sites'],
    queryFn: fetchSites,
    retry: false,
  });
  const mutation = useMutation({
    mutationFn: createSite,
    onSuccess: (site) => {
      toast.success(t('sites.created'));
      setOpen(false);
      setStep(0);
      setDraft(initialDraft);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
      navigate(`/sites/${site.id}`);
    },
    onError: (error) => toast.error(error.message),
  });

  const resetNginx = () => {
    setNginxPhase('input');
    setNginxText('');
    setNginxMessage('');
    setNginxRows([]);
    setNginxSkipped(0);
    setNginxSelection([]);
    setNginxResults([]);
  };
  const closeNginx = () => {
    setNginxOpen(false);
    resetNginx();
  };
  const parseNginxConfig = async () => {
    if (!nginxText.trim()) {
      setNginxMessage(t('sites.import.empty'));
      return;
    }
    if (new TextEncoder().encode(nginxText).length > NGINX_IMPORT_MAX_BYTES) {
      setNginxMessage(t('sites.import.tooLarge'));
      return;
    }
    setParsing(true);
    setNginxMessage('');
    try {
      const parsed = await importNginx(nginxText);
      const nextRows = nginxImportRows(parsed);
      setNginxRows(nextRows);
      setNginxSkipped(Math.max(0, countNginxServerBlocks(nginxText) - nextRows.length));
      setNginxSelection(
        nextRows.map((row, index) => (row.issue ? -1 : index)).filter((index) => index >= 0),
      );
      if (nextRows.length === 0) {
        setNginxMessage(t('sites.import.noServerBlock'));
        return;
      }
      setNginxPhase('preview');
    } catch (error) {
      setNginxMessage(error instanceof Error && error.message.trim() ? error.message : t('common.loadFailed'));
    } finally {
      setParsing(false);
    }
  };
  const confirmNginxImport = async () => {
    setImporting(true);
    const outcomes: NginxOutcome[] = [];
    let created = 0;
    for (const index of nginxSelection) {
      const row = nginxRows[index];
      if (!row) {
        continue;
      }
      try {
        await createSite(nginxImportPayload(row));
        outcomes.push({ name: row.name, ok: true, message: '' });
        created += 1;
      } catch (error) {
        outcomes.push({ name: row.name, ok: false, message: error instanceof Error ? error.message : '' });
      }
    }
    setImporting(false);
    setNginxResults(outcomes);
    setNginxPhase('result');
    if (created > 0) {
      toast.success(t('sites.import.imported', { count: created }));
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    } else {
      toast.error(t('sites.import.noneImported'));
    }
  };
  const toggleNginxRow = (index: number, checked: boolean) => {
    setNginxSelection((current) => (checked ? [...current, index] : current.filter((item) => item !== index)));
  };

  const rows = data ?? [];
  const nginxBlockedRows = nginxRows.filter((row) => row.issue).length;
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
  const createPayload = (): Partial<Site> => {
    const isAcme = draft.certificateMode === 'acme';
    const enableSSL = isAcme ? true : draft.enableSSL;
    return {
      name: draft.name.trim(),
      domains: splitList(draft.domains),
      upstreams: splitList(draft.upstreams),
      listen_port: draft.listenPort,
      loadbalance: draft.loadbalance,
      enable_ssl: enableSSL,
      cert_file: enableSSL && draft.certificateMode === 'file' ? draft.certFile.trim() : '',
      key_file: enableSSL && draft.certificateMode === 'file' ? draft.keyFile.trim() : '',
      waf_enabled: draft.wafEnabled,
      waf_mode: draft.wafMode,
      paranoia_level: 3,
      enabled: draft.enabled,
      advanced: {
        ...defaultSiteAdvanced,
        access_log_enabled: true,
        certificate: {
          ...defaultSiteAdvanced.certificate,
          mode: draft.certificateMode,
          cert_pem: enableSSL && draft.certificateMode === 'inline' ? draft.certPEM.trim() : '',
          key_pem: enableSSL && draft.certificateMode === 'inline' ? draft.keyPEM.trim() : '',
          auto_renew: isAcme ? true : defaultSiteAdvanced.certificate.auto_renew,
          force_https: isAcme ? true : draft.forceHTTPS,
          hsts: isAcme ? true : draft.hsts,
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
    };
  };

  const stepTitles = [
    t('sites.stepBasic'),
    t('sites.stepTls'),
    t('sites.stepProtection'),
    t('sites.stepReview'),
  ];

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('sites.title')}</h1>
          <p>{t('sites.subtitle')}</p>
        </div>
        <div className="sites-header-actions">
          <Button variant="outline" onClick={() => { resetNginx(); setNginxOpen(true); }}>
            <FileDown size={16} />
            {t('sites.import.action')}
          </Button>
          <Button onClick={() => setOpen(true)}>
            <Plus size={16} />
            {t('sites.create')}
          </Button>
        </div>
      </header>

      <section className="table-panel sites-list-panel">
        {isError && (
          <div className="inline-error sites-query-error" role="alert">
            <span>{queryErrorMessage(error, t('common.noData'))}</span>
            <Button size="sm" onClick={() => refetch()}>{t('common.retry')}</Button>
          </div>
        )}
        <div className="sites-desktop-table">
          {isLoading ? (
            <div className="skeleton-list" role="status" />
          ) : rows.length === 0 ? (
            <Empty description={t('common.noData')} />
          ) : (
            <Table className="sites-table">
              <TableHeader>
                <TableRow>
                  <TableHead>{t('sites.name')}</TableHead>
                  <TableHead>{t('sites.domain')}</TableHead>
                  <TableHead>{t('sites.upstream')}</TableHead>
                  <TableHead className="w-[88px]">{t('sites.listen')}</TableHead>
                  <TableHead className="w-[100px]">{t('sites.mode')}</TableHead>
                  <TableHead className="w-[96px]">{t('sites.status')}</TableHead>
                  <TableHead className="w-[104px]">{t('common.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((site) => {
                  const domains = site.domains?.join(', ') || '-';
                  const upstreams = site.upstreams?.join(', ') || '-';
                  return (
                    <TableRow key={site.id}>
                      <TableCell>
                        <button className="table-link site-table-link" title={site.name} type="button" onClick={() => navigate(`/sites/${site.id}`)}>
                          <Server size={16} />
                          <span>{site.name}</span>
                        </button>
                      </TableCell>
                      <TableCell>
                        <span className="site-table-text" title={domains}>{domains}</span>
                      </TableCell>
                      <TableCell>
                        <span className="site-table-text" title={upstreams}>{upstreams}</span>
                      </TableCell>
                      <TableCell>
                        <code>{site.listen_port == null || site.listen_port === 0 ? '—' : `:${site.listen_port}`}</code>
                      </TableCell>
                      <TableCell>
                        <Badge variant={site.waf_mode === 'block' ? 'success' : site.waf_mode === 'monitor' ? 'warning' : 'secondary'}>
                          {renderMode(site.waf_mode)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={site.enabled ? 'success' : 'secondary'}>
                          {site.enabled ? t('common.online') : t('sites.disabled')}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="site-table-actions">
                          <Button size="sm" variant="outline" onClick={() => navigate(`/sites/${site.id}`)}>
                            {t('sites.manage')}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
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
                  <Badge variant={site.enabled ? 'success' : 'secondary'}>
                    {site.enabled ? t('common.online') : t('sites.disabled')}
                  </Badge>
                </header>
                <dl>
                  <div><dt>{t('sites.domain')}</dt><dd title={domains}>{domains}</dd></div>
                  <div><dt>{t('sites.upstream')}</dt><dd title={upstreams}>{upstreams}</dd></div>
                  <div><dt>{t('sites.listen')}</dt><dd><code>{site.listen_port == null || site.listen_port === 0 ? '—' : `:${site.listen_port}`}</code></dd></div>
                  <div><dt>{t('sites.mode')}</dt><dd>{renderMode(site.waf_mode)}</dd></div>
                </dl>
                <footer>
                  <Button onClick={() => navigate(`/sites/${site.id}`)}>{t('sites.manage')}</Button>
                </footer>
              </article>
            );
          }) : !isError ? <Empty description={t('common.noData')} /> : null}
        </div>
      </section>

      <Dialog open={open} onOpenChange={(next) => { if (!next) closeWizard(); else setOpen(true); }}>
        <DialogContent className="site-wizard-modal max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('sites.create')}</DialogTitle>
          </DialogHeader>

          <div className="setup-steps flex flex-wrap gap-2 mb-4" role="list">
            {wizardSteps.map((item, index) => {
              const Icon = item.icon;
              const active = index === step;
              const done = index < step;
              return (
                <div
                  key={item.key}
                  role="listitem"
                  className={`flex items-center gap-1.5 rounded-md px-2 py-1 text-xs ${active ? 'bg-primary text-primary-foreground' : done ? 'bg-muted text-foreground' : 'text-muted-foreground'}`}
                >
                  <Icon size={14} />
                  <span>{stepTitles[index]}</span>
                </div>
              );
            })}
          </div>

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
                  <Input value={draft.name} placeholder="portal.example.com" onChange={(e) => updateDraft('name', e.target.value)} />
                </label>
                <label>
                  <span>{t('sites.domain')}</span>
                  <Input value={draft.domains} placeholder="example.com, www.example.com" onChange={(e) => updateDraft('domains', e.target.value)} />
                </label>
                <label>
                  <span>{t('sites.upstream')}</span>
                  <Input value={draft.upstreams} placeholder="127.0.0.1:9000, 10.0.0.12:8080" onChange={(e) => updateDraft('upstreams', e.target.value)} />
                </label>
                <label>
                  <span>{t('sites.listen')}</span>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    value={draft.listenPort}
                    onChange={(e) => updateDraft('listenPort', Number(e.target.value || 80))}
                  />
                  <em>{t('sites.listenHint')}</em>
                </label>
                <label>
                  <span>{t('sites.loadBalance')}</span>
                  <Select value={draft.loadbalance} onValueChange={(value) => updateDraft('loadbalance', value)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="round_robin">{t('sites.lbRoundRobin')}</SelectItem>
                      <SelectItem value="weighted">{t('sites.lbWeighted')}</SelectItem>
                      <SelectItem value="ip_hash">{t('sites.lbIPHash')}</SelectItem>
                    </SelectContent>
                  </Select>
                </label>
                <label>
                  <span>{t('sites.originScheme')}</span>
                  <Select value={draft.originScheme} onValueChange={(value) => updateDraft('originScheme', value)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="http">HTTP</SelectItem>
                      <SelectItem value="https">HTTPS</SelectItem>
                    </SelectContent>
                  </Select>
                </label>
              </div>
            </div>
          )}

          {step === 1 && (
            <div className="form-grid">
              <label className="switch-line">
                <span>{t('sites.enableSsl')}</span>
                <Switch checked={draft.enableSSL} onCheckedChange={(value) => updateDraft('enableSSL', value)} />
              </label>
              <label>
                <span>{t('sites.certificateMode')}</span>
                <Select value={draft.certificateMode} onValueChange={(value) => updateDraft('certificateMode', value)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="file">{t('sites.certFile')}</SelectItem>
                    <SelectItem value="inline">{t('sites.certInline')}</SelectItem>
                    <SelectItem value="acme">{t('sites.certAcme')}</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              {draft.enableSSL && draft.certificateMode === 'file' && (
                <>
                  <label>
                    <span>{t('sites.certFile')}</span>
                    <Input value={draft.certFile} placeholder="/etc/cheesewaf/certs/site.crt" onChange={(e) => updateDraft('certFile', e.target.value)} />
                  </label>
                  <label>
                    <span>{t('sites.keyFile')}</span>
                    <Input value={draft.keyFile} placeholder="/etc/cheesewaf/certs/site.key" onChange={(e) => updateDraft('keyFile', e.target.value)} />
                  </label>
                </>
              )}
              {draft.enableSSL && draft.certificateMode === 'inline' && (
                <>
                  <label className="wide-field">
                    <span>{t('sites.certPem')}</span>
                    <Textarea value={draft.certPEM} rows={4} onChange={(e) => updateDraft('certPEM', e.target.value)} />
                  </label>
                  <label className="wide-field">
                    <span>{t('sites.keyPem')}</span>
                    <Textarea value={draft.keyPEM} rows={4} onChange={(e) => updateDraft('keyPEM', e.target.value)} />
                  </label>
                </>
              )}
              <label className="switch-line">
                <span>{t('sites.forceHttps')}</span>
                <Switch checked={draft.forceHTTPS} onCheckedChange={(value) => updateDraft('forceHTTPS', value)} />
              </label>
              <label className="switch-line">
                <span>{t('sites.hsts')}</span>
                <Switch checked={draft.hsts} onCheckedChange={(value) => updateDraft('hsts', value)} />
              </label>
              <label>
                <span>{t('sites.minTls')}</span>
                <Select value={draft.minTLSVersion} onValueChange={(value) => updateDraft('minTLSVersion', value)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1.2">TLS 1.2</SelectItem>
                    <SelectItem value="1.3">TLS 1.3</SelectItem>
                  </SelectContent>
                </Select>
              </label>
            </div>
          )}

          {step === 2 && (
            <div className="form-grid">
              <label className="switch-line">
                <span>{t('sites.wafEnabled')}</span>
                <Switch checked={draft.wafEnabled} onCheckedChange={(value) => updateDraft('wafEnabled', value)} />
              </label>
              <label>
                <span>{t('sites.wafMode')}</span>
                <Select value={draft.wafMode} onValueChange={(value) => updateDraft('wafMode', value)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="block">{t('sites.modeBlock')}</SelectItem>
                    <SelectItem value="monitor">{t('sites.modeMonitor')}</SelectItem>
                    <SelectItem value="off">{t('sites.modeOff')}</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('sites.proxyTimeout')}</span>
                <Input value={draft.proxyTimeout} placeholder="30s" onChange={(e) => updateDraft('proxyTimeout', e.target.value)} />
              </label>
              <label>
                <span>{t('sites.maxBody')}</span>
                <Input
                  type="number"
                  min={1024}
                  step={1024 * 1024}
                  value={draft.maxBodyBytes}
                  onChange={(e) => updateDraft('maxBodyBytes', Number(e.target.value || 0))}
                />
              </label>
              <label className="switch-line">
                <span>{t('sites.passHost')}</span>
                <Switch checked={draft.passHost} onCheckedChange={(value) => updateDraft('passHost', value)} />
              </label>
              <label>
                <span>{t('sites.hostHeader')}</span>
                <Input value={draft.hostHeader} placeholder="origin.example.internal" onChange={(e) => updateDraft('hostHeader', e.target.value)} />
              </label>
              <label className="switch-line">
                <span>{t('protection.bot')}</span>
                <Switch checked={draft.bot} onCheckedChange={(value) => updateDraft('bot', value)} />
              </label>
              <label className="switch-line">
                <span>{t('protection.ratelimit')}</span>
                <Switch checked={draft.ratelimit} onCheckedChange={(value) => updateDraft('ratelimit', value)} />
              </label>
              <label className="switch-line">
                <span>{t('protection.acl')}</span>
                <Switch checked={draft.acl} onCheckedChange={(value) => updateDraft('acl', value)} />
              </label>
              <label className="switch-line">
                <span>{t('nav.apisec')}</span>
                <Switch checked={draft.apisec} onCheckedChange={(value) => updateDraft('apisec', value)} />
              </label>
              <label className="switch-line">
                <span>{t('sites.healthCheck')}</span>
                <Switch checked={draft.healthCheck} onCheckedChange={(value) => updateDraft('healthCheck', value)} />
              </label>
              <label>
                <span>{t('sites.healthPath')}</span>
                <Input value={draft.healthPath} placeholder="/health" onChange={(e) => updateDraft('healthPath', e.target.value)} />
              </label>
            </div>
          )}

          {step === 3 && (
            <div className="site-review">
              <strong>{draft.name || '-'}</strong>
              <span>{splitList(draft.domains).join(', ') || '-'}</span>
              <div className="flex flex-wrap gap-2">
                <Badge variant="default">{draft.originScheme.toUpperCase()}</Badge>
                <Badge variant={draft.wafMode === 'block' ? 'success' : 'warning'}>{renderMode(draft.wafMode)}</Badge>
                <Badge variant={draft.enableSSL ? 'success' : 'secondary'}>{draft.enableSSL ? 'TLS' : 'HTTP'}</Badge>
              </div>
              <div className="flex flex-wrap gap-2">
                {splitList(draft.upstreams).map((upstream) => <code key={upstream}>{upstream}</code>)}
              </div>
            </div>
          )}

          <DialogFooter className="modal-actions">
            <Button variant="outline" disabled={step === 0} onClick={() => setStep((value) => Math.max(0, value - 1))}>
              {t('common.back')}
            </Button>
            {step < 3 ? (
              <Button disabled={!canAdvance} onClick={() => setStep((value) => Math.min(3, value + 1))}>
                {t('common.next')}
              </Button>
            ) : (
              <Button disabled={!canCreate} loading={mutation.isPending} onClick={() => mutation.mutate(createPayload())}>
                {t('common.finish')}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={nginxOpen} onOpenChange={(next) => { if (!next) closeNginx(); else setNginxOpen(true); }}>
        <DialogContent className="site-wizard-modal max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t('sites.import.title')}</DialogTitle>
          </DialogHeader>

          {nginxPhase === 'input' && (
            <div className="nginx-import-form">
              <p className="nginx-import-hint">{t('sites.import.hint')}</p>
              <label className="wide-field">
                <span>{t('sites.import.config')}</span>
                <Textarea
                  className="nginx-import-text"
                  rows={12}
                  value={nginxText}
                  placeholder={nginxSample}
                  onChange={(event) => setNginxText(event.target.value)}
                />
              </label>
              {nginxMessage ? (
                <div className="inline-error nginx-import-message" role="alert">
                  <span>{nginxMessage}</span>
                </div>
              ) : null}
            </div>
          )}

          {nginxPhase === 'preview' && (
            <div className="nginx-import-preview">
              <p className="nginx-import-hint">
                {t('sites.import.summary', { parsed: nginxRows.length, skipped: nginxSkipped })}
              </p>
              {nginxBlockedRows > 0 && (
                <p className="nginx-import-hint">
                  {t('sites.import.incompatible', { count: nginxBlockedRows })}
                </p>
              )}
              <div className="nginx-import-list">
                {nginxRows.map((row, index) => (
                  <label key={`${row.name || 'unnamed'}-${index}`} className="nginx-import-row">
                    <Checkbox
                      checked={nginxSelection.includes(index)}
                      disabled={Boolean(row.issue)}
                      onCheckedChange={(value) => toggleNginxRow(index, value === true)}
                    />
                    <span className="nginx-import-row-body">
                      <strong>{row.name || t('sites.import.unnamed')}</strong>
                      <span>{row.domains.join(', ') || '-'}</span>
                      <span>{row.upstreams.join(', ') || '-'}</span>
                      <code>{`:${row.listenPort}`}</code>
                      {row.issue ? <Badge variant="warning">{t(nginxIssueKeys[row.issue])}</Badge> : null}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {nginxPhase === 'result' && (
            <div className="nginx-import-result">
              <p className="nginx-import-hint">
                {t('sites.import.resultSummary', {
                  success: nginxResults.filter((item) => item.ok).length,
                  failed: nginxResults.filter((item) => !item.ok).length,
                })}
              </p>
              <ul className="nginx-import-list">
                {nginxResults.map((item, index) => (
                  <li key={`${item.name}-${index}`} className="nginx-import-row">
                    <Badge variant={item.ok ? 'success' : 'destructive'}>
                      {item.ok ? t('sites.import.success') : t('sites.import.failed')}
                    </Badge>
                    <span className="nginx-import-row-body">
                      <strong>{item.name}</strong>
                      {item.message ? <span>{item.message}</span> : null}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <DialogFooter className="modal-actions">
            {nginxPhase === 'input' && (
              <>
                <Button variant="outline" onClick={closeNginx}>{t('common.cancel')}</Button>
                <Button loading={parsing} onClick={() => void parseNginxConfig()}>{t('sites.import.parse')}</Button>
              </>
            )}
            {nginxPhase === 'preview' && (
              <>
                <Button variant="outline" disabled={importing} onClick={() => setNginxPhase('input')}>
                  {t('common.back')}
                </Button>
                <Button
                  loading={importing}
                  disabled={nginxSelection.length === 0}
                  onClick={() => void confirmNginxImport()}
                >
                  {importing ? t('sites.import.importing') : t('sites.import.confirm')}
                </Button>
              </>
            )}
            {nginxPhase === 'result' && (
              <Button onClick={closeNginx}>{t('common.close')}</Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function queryErrorMessage(error: unknown, fallbackMessage: string) {
  return error instanceof Error && error.message.trim() ? error.message : fallbackMessage;
}
