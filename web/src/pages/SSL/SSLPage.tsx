import {
  Button,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  toast,
} from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig, updateSystemConfig } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { useServerDraft } from '../../hooks/useServerDraft';
import type { SystemConfig } from '../../types/api';
import { fallbackSystem, normalizeSystem } from '../System/systemModel';

type DNSProvider = SystemConfig['acme']['dns_providers'][number];

const SYSTEMD_RESTART_PROFILE = 'systemd-restart';
const SYSTEMD_RESTART_COMMAND = '/usr/bin/systemctl restart cheesewaf.service';

function reloadProfile(value: string) {
  return value === SYSTEMD_RESTART_PROFILE || value === SYSTEMD_RESTART_COMMAND
    ? SYSTEMD_RESTART_PROFILE
    : 'disabled';
}

export default function SSLPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const systemQuery = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });
  const { data, isError, isFetching, isSuccess, isLoading, error, refetch } = systemQuery;
  const serverSystem = useMemo(() => (data ? normalizeSystem(data) : undefined), [data]);
  const { draft, setDraft, markClean } = useServerDraft(serverSystem);
  const system = draft ?? fallbackSystem;

  const saveMutation = useMutation({
    mutationFn: updateSystemConfig,
    onSuccess: (saved) => {
      markClean(normalizeSystem(saved));
      queryClient.invalidateQueries({ queryKey: ['system'] });
      toast.success(t('system.saved'));
    },
    onError: (mutationError) => toast.error(mutationError.message),
  });

  const patchACME = (patch: Partial<SystemConfig['acme']>) => {
    setDraft((current) => {
      const base = current ?? fallbackSystem;
      return normalizeSystem({ ...base, acme: { ...base.acme, ...patch } });
    });
  };
  const updateProvider = (index: number, patch: Partial<DNSProvider>) => {
    const providers = system.acme.dns_providers.map((provider, providerIndex) => (
      providerIndex === index ? { ...provider, ...patch } : provider
    ));
    patchACME({ dns_providers: providers });
  };
  const setProviderEnv = (index: number, env: Record<string, string>) => {
    updateProvider(index, { env });
  };
  const addProvider = () => {
    patchACME({
      dns_providers: [
        ...system.acme.dns_providers,
        { id: `dns-${Date.now()}-${Math.random().toString(16).slice(2)}`, name: '', api: 'dns_cf', enabled: true, env: {} },
      ],
    });
  };
  const removeProvider = (index: number) => {
    patchACME({ dns_providers: system.acme.dns_providers.filter((_, providerIndex) => providerIndex !== index) });
  };

  if (!draft && isLoading) {
    return (
      <section className="page-surface ssl-page">
        <header className="page-header">
          <div>
            <h1>{t('ssl.title')}</h1>
            <p>{t('ssl.subtitle')}</p>
          </div>
        </header>
        <div className="empty-state" role="status">{t('common.loading')}</div>
      </section>
    );
  }

  if (isError && !draft) {
    return (
      <section className="page-surface ssl-page">
        <header className="page-header">
          <div>
            <h1>{t('ssl.title')}</h1>
            <p>{t('ssl.subtitle')}</p>
          </div>
        </header>
        <QueryErrorState
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => { void refetch(); }}
          retrying={isFetching}
        />
      </section>
    );
  }

  return (
    <section className="page-surface ssl-page">
      <header className="page-header">
        <div>
          <h1>{t('ssl.title')}</h1>
          <p>{t('ssl.subtitle')}</p>
        </div>
        <Button
          onClick={() => saveMutation.mutate({ acme: system.acme })}
          loading={saveMutation.isPending}
          disabled={!isSuccess}
        >
          {t('common.save')}
        </Button>
      </header>

      {isError && (
        <QueryErrorState
          message={error instanceof Error ? error.message : undefined}
          onRetry={() => { void refetch(); }}
          retrying={isFetching}
        />
      )}

      <div className="ssl-settings-grid">
        <section className="system-fieldset">
          <header>
            <strong>{t('system.acmeDefaults')}</strong>
            <span>{t('system.acmeHint')}</span>
          </header>
          <div className="site-detail-grid">
            <label className="switch-line">
              <span>{t('system.acmeEnabled')}</span>
              <Switch checked={system.acme.enabled} onCheckedChange={(enabled) => patchACME({ enabled })} disabled={!isSuccess} />
            </label>
            <label className="switch-line">
              <span>{t('system.acmeNotify')}</span>
              <Switch checked={system.acme.notify} onCheckedChange={(notify) => patchACME({ notify })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmePath')}</span>
              <Input value={system.acme.acme_sh_path} placeholder="acme.sh" onChange={(e) => patchACME({ acme_sh_path: e.target.value })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeServer')}</span>
              <Select value={system.acme.server || 'letsencrypt'} onValueChange={(server) => patchACME({ server })} disabled={!isSuccess}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="letsencrypt">Let&apos;s Encrypt</SelectItem>
                  <SelectItem value="zerossl">ZeroSSL</SelectItem>
                  <SelectItem value="https://acme-v02.api.letsencrypt.org/directory">Let&apos;s Encrypt API</SelectItem>
                  <SelectItem value="https://acme-staging-v02.api.letsencrypt.org/directory">Let&apos;s Encrypt Staging</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeAccountEmail')}</span>
              <Input value={system.acme.account_email} placeholder="ops@example.com" onChange={(e) => patchACME({ account_email: e.target.value })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeKeyType')}</span>
              <Select value={system.acme.key_type || 'ec-256'} onValueChange={(key_type) => patchACME({ key_type })} disabled={!isSuccess}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ec-256">ECDSA P-256</SelectItem>
                  <SelectItem value="ec-384">ECDSA P-384</SelectItem>
                  <SelectItem value="2048">RSA 2048</SelectItem>
                  <SelectItem value="3072">RSA 3072</SelectItem>
                  <SelectItem value="4096">RSA 4096</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeHome')}</span>
              <Input value={system.acme.home} placeholder="./data/acme" onChange={(e) => patchACME({ home: e.target.value })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeCertDir')}</span>
              <Input value={system.acme.cert_dir} placeholder="./data/certs" onChange={(e) => patchACME({ cert_dir: e.target.value })} disabled={!isSuccess} />
            </label>
            <label className="wide-field">
              <span>{t('system.acmeReloadProfile')}</span>
              <Select
                value={reloadProfile(system.acme.reload_command)}
                onValueChange={(profile) => patchACME({ reload_command: profile === 'disabled' ? '' : profile })}
                disabled={!isSuccess}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="disabled">{t('system.acmeReloadDisabled')}</SelectItem>
                  <SelectItem value={SYSTEMD_RESTART_PROFILE}>{t('system.acmeReloadSystemdRestart')}</SelectItem>
                </SelectContent>
              </Select>
            </label>
          </div>
        </section>

        <section className="system-fieldset acme-provider-settings">
          <header className="fieldset-header-action">
            <div>
              <strong>{t('system.acmeDNSProviders')}</strong>
              <span>{t('system.acmeDNSProvidersHint')}</span>
            </div>
            <Button size="sm" variant="outline" onClick={addProvider} disabled={!isSuccess}>
              <Plus size={14} />
              {t('common.add')}
            </Button>
          </header>
          <div className="acme-provider-list">
            {system.acme.dns_providers.map((provider, index) => (
              <section className="acme-provider-card" key={index}>
                <div className="acme-provider-head">
                  <Switch checked={provider.enabled} onCheckedChange={(enabled) => updateProvider(index, { enabled })} disabled={!isSuccess} />
                  <Input
                    value={provider.id}
                    placeholder="cloudflare"
                    aria-label={t('system.acmeDNSProviders')}
                    onChange={(e) => updateProvider(index, { id: e.target.value })}
                    disabled={!isSuccess}
                  />
                  <Button size="sm" variant="destructive" onClick={() => removeProvider(index)} disabled={!isSuccess}>
                    <Trash2 size={13} />
                    {t('common.delete')}
                  </Button>
                </div>
                <div className="site-detail-grid">
                  <label>
                    <span>{t('sites.name')}</span>
                    <Input value={provider.name} placeholder="Cloudflare" onChange={(e) => updateProvider(index, { name: e.target.value })} disabled={!isSuccess} />
                  </label>
                  <label>
                    <span>{t('system.acmeDNSAPI')}</span>
                    <Input value={provider.api} placeholder="dns_cf" onChange={(e) => updateProvider(index, { api: e.target.value })} disabled={!isSuccess} />
                  </label>
                  <ACMEEnvEditor
                    provider={provider}
                    disabled={!isSuccess}
                    onChange={(env) => setProviderEnv(index, env)}
                  />
                </div>
              </section>
            ))}
            {!system.acme.dns_providers.length && <div className="empty-state"><KeyRound size={16} /> {t('system.acmeNoProviders')}</div>}
          </div>
        </section>
      </div>
    </section>
  );
}

type EnvRow = { id: string; key: string; value: string };

function ACMEEnvEditor({
  provider,
  disabled,
  onChange,
}: {
  provider: DNSProvider;
  disabled?: boolean;
  onChange: (env: Record<string, string>) => void;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<EnvRow[]>(() => envToRows(provider.env));
  const dirtyRef = useRef(false);
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const envSnapshot = JSON.stringify(provider.env ?? {});

  useEffect(() => {
    if (!dirtyRef.current) {
      setRows(envToRows(provider.env));
      return;
    }
    const localEnv = JSON.stringify(rowsToEnv(rowsRef.current));
    if (localEnv === envSnapshot) {
      dirtyRef.current = false;
    }
  }, [envSnapshot, provider.env]);

  const commitRows = (nextRows: EnvRow[]) => {
    dirtyRef.current = true;
    setRows(nextRows);
    onChange(rowsToEnv(nextRows));
  };

  const updateRow = (id: string, patch: Partial<EnvRow>) => {
    const nextRows = rows.map((row) => (row.id === id ? { ...row, ...patch } : row));
    if (patch.key !== undefined) {
      const normalized = patch.key.toUpperCase().replace(/[^A-Z0-9_]/g, '');
      const owner = nextRows.find((row) => row.id === id);
      if (owner) {
        owner.key = normalized;
      }
      if (normalized) {
        const duplicate = nextRows.some((row) => row.id !== id && row.key === normalized);
        if (duplicate) {
          toast.warning(t('system.acmeEnvKeyDuplicate'));
          return;
        }
      }
    }
    commitRows(nextRows);
  };

  const addRow = () => {
    commitRows([...rows, { id: `env-${Date.now()}-${Math.random().toString(16).slice(2)}`, key: '', value: '' }]);
  };

  const removeRow = (id: string) => {
    commitRows(rows.filter((row) => row.id !== id));
  };

  return (
    <div className="wide-field acme-env-editor">
      <div className="fieldset-header-action">
        <span>{t('system.acmeEnvKey')}</span>
        <Button size="sm" variant="outline" onClick={addRow} disabled={disabled}>
          <Plus size={12} />
          {t('common.add')}
        </Button>
      </div>
      {rows.map((row, slot) => (
        <div className="site-detail-grid acme-env-row" key={row.id}>
          <label>
            <span>{t('system.acmeEnvKey')} {slot + 1}</span>
            <Input
              value={row.key}
              placeholder={slot === 0 ? 'CF_TOKEN' : 'CF_ACCOUNT_ID'}
              disabled={disabled}
              onChange={(e) => updateRow(row.id, { key: e.target.value })}
            />
          </label>
          <label>
            <span>{t('system.acmeEnvValue')} {slot + 1}</span>
            <Input
              type="password"
              value={row.value}
              disabled={disabled}
              onChange={(e) => {
                const value = e.target.value;
                // Keep incomplete rows local; never invent TOKEN/SECRET keys.
                if (!row.key.trim()) {
                  dirtyRef.current = true;
                  setRows((current) => current.map((item) => (item.id === row.id ? { ...item, value } : item)));
                  return;
                }
                updateRow(row.id, { value });
              }}
            />
          </label>
          <Button
            size="icon"
            variant="destructive"
            aria-label={t('common.delete')}
            disabled={disabled}
            onClick={() => removeRow(row.id)}
          >
            <Trash2 size={12} />
          </Button>
        </div>
      ))}
    </div>
  );
}

function envToRows(env: Record<string, string> | undefined): EnvRow[] {
  return Object.entries(env ?? {}).map(([key, value]) => ({
    id: `env-${key}`,
    key,
    value,
  }));
}

function rowsToEnv(rows: EnvRow[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim().toUpperCase();
    if (!key) {
      continue;
    }
    env[key] = row.value;
  }
  return env;
}
