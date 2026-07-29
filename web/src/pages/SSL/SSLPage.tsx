import { Button, Input, Message as ArcoMessage, Select, Switch } from '@arco-design/web-react';
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
      ArcoMessage.success(t('system.saved'));
    },
    onError: (mutationError) => ArcoMessage.error(mutationError.message),
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
          type="primary"
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
              <Switch checked={system.acme.enabled} onChange={(enabled) => patchACME({ enabled })} disabled={!isSuccess} />
            </label>
            <label className="switch-line">
              <span>{t('system.acmeNotify')}</span>
              <Switch checked={system.acme.notify} onChange={(notify) => patchACME({ notify })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmePath')}</span>
              <Input value={system.acme.acme_sh_path} placeholder="acme.sh" onChange={(acme_sh_path) => patchACME({ acme_sh_path })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeServer')}</span>
              <Select value={system.acme.server || 'letsencrypt'} onChange={(server) => patchACME({ server: server as string })} disabled={!isSuccess}>
                <Select.Option value="letsencrypt">Let's Encrypt</Select.Option>
                <Select.Option value="zerossl">ZeroSSL</Select.Option>
                <Select.Option value="https://acme-v02.api.letsencrypt.org/directory">Let's Encrypt API</Select.Option>
                <Select.Option value="https://acme-staging-v02.api.letsencrypt.org/directory">Let's Encrypt Staging</Select.Option>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeAccountEmail')}</span>
              <Input value={system.acme.account_email} placeholder="ops@example.com" onChange={(account_email) => patchACME({ account_email })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeKeyType')}</span>
              <Select value={system.acme.key_type || 'ec-256'} onChange={(key_type) => patchACME({ key_type: key_type as string })} disabled={!isSuccess}>
                <Select.Option value="ec-256">ECDSA P-256</Select.Option>
                <Select.Option value="ec-384">ECDSA P-384</Select.Option>
                <Select.Option value="2048">RSA 2048</Select.Option>
                <Select.Option value="3072">RSA 3072</Select.Option>
                <Select.Option value="4096">RSA 4096</Select.Option>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeHome')}</span>
              <Input value={system.acme.home} placeholder="./data/acme" onChange={(home) => patchACME({ home })} disabled={!isSuccess} />
            </label>
            <label>
              <span>{t('system.acmeCertDir')}</span>
              <Input value={system.acme.cert_dir} placeholder="./data/certs" onChange={(cert_dir) => patchACME({ cert_dir })} disabled={!isSuccess} />
            </label>
            <label className="wide-field">
              <span>{t('system.acmeReloadCommand')}</span>
              <Input value={system.acme.reload_command} placeholder="systemctl reload cheesewaf" onChange={(reload_command) => patchACME({ reload_command })} disabled={!isSuccess} />
            </label>
          </div>
        </section>

        <section className="system-fieldset acme-provider-settings">
          <header className="fieldset-header-action">
            <div>
              <strong>{t('system.acmeDNSProviders')}</strong>
              <span>{t('system.acmeDNSProvidersHint')}</span>
            </div>
            <Button size="small" icon={<Plus size={14} />} onClick={addProvider} disabled={!isSuccess}>{t('common.add')}</Button>
          </header>
          <div className="acme-provider-list">
            {system.acme.dns_providers.map((provider, index) => (
              <section className="acme-provider-card" key={index}>
                <div className="acme-provider-head">
                  <Switch checked={provider.enabled} onChange={(enabled) => updateProvider(index, { enabled })} disabled={!isSuccess} />
                  <Input
                    value={provider.id}
                    placeholder="cloudflare"
                    aria-label={t('system.acmeDNSProviders')}
                    onChange={(id) => updateProvider(index, { id })}
                    disabled={!isSuccess}
                  />
                  <Button size="mini" status="danger" icon={<Trash2 size={13} />} onClick={() => removeProvider(index)} disabled={!isSuccess}>{t('common.delete')}</Button>
                </div>
                <div className="site-detail-grid">
                  <label><span>{t('sites.name')}</span><Input value={provider.name} placeholder="Cloudflare" onChange={(name) => updateProvider(index, { name })} disabled={!isSuccess} /></label>
                  <label><span>{t('system.acmeDNSAPI')}</span><Input value={provider.api} placeholder="dns_cf" onChange={(api) => updateProvider(index, { api })} disabled={!isSuccess} /></label>
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
          ArcoMessage.warning(t('system.acmeEnvKeyDuplicate', { defaultValue: 'Environment variable key already exists' }));
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
        <Button size="mini" icon={<Plus size={12} />} onClick={addRow} disabled={disabled}>{t('common.add')}</Button>
      </div>
      {rows.map((row, slot) => (
        <div className="site-detail-grid acme-env-row" key={row.id}>
          <label>
            <span>{t('system.acmeEnvKey')} {slot + 1}</span>
            <Input
              value={row.key}
              placeholder={slot === 0 ? 'CF_TOKEN' : 'CF_ACCOUNT_ID'}
              disabled={disabled}
              onChange={(key) => updateRow(row.id, { key })}
            />
          </label>
          <label>
            <span>{t('system.acmeEnvValue')} {slot + 1}</span>
            <Input.Password
              value={row.value}
              disabled={disabled}
              onChange={(value) => {
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
            size="mini"
            status="danger"
            icon={<Trash2 size={12} />}
            aria-label={t('common.delete')}
            disabled={disabled}
            onClick={() => removeRow(row.id)}
          />
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
