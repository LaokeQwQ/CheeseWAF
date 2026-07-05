import { Button, Input, Message as ArcoMessage, Select, Switch } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchSystemConfig, updateSystemConfig } from '../../api/client';
import type { SystemConfig } from '../../types/api';
import { fallbackSystem, normalizeSystem } from '../System/systemModel';

export default function SSLPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [system, setSystem] = useState<SystemConfig>(fallbackSystem);
  const { data } = useQuery({ queryKey: ['system'], queryFn: fetchSystemConfig, retry: false });

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
      ArcoMessage.success(t('system.saved'));
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const patchACME = (patch: Partial<SystemConfig['acme']>) => {
    setSystem((current) => normalizeSystem({ ...current, acme: { ...current.acme, ...patch } }));
  };
  const updateProvider = (index: number, patch: Partial<SystemConfig['acme']['dns_providers'][number]>) => {
    patchACME({
      dns_providers: system.acme.dns_providers.map((provider, providerIndex) => (
        providerIndex === index ? { ...provider, ...patch } : provider
      )),
    });
  };
  const updateProviderEnv = (index: number, key: string, value: string) => {
    const provider = system.acme.dns_providers[index];
    if (!provider) return;
    updateProvider(index, { env: { ...(provider.env ?? {}), [key]: value } });
  };
  const addProvider = () => {
    patchACME({
      dns_providers: [
        ...system.acme.dns_providers,
        { id: `dns-${Date.now()}`, name: '', api: 'dns_cf', enabled: true, env: {} },
      ],
    });
  };
  const removeProvider = (index: number) => {
    patchACME({ dns_providers: system.acme.dns_providers.filter((_, providerIndex) => providerIndex !== index) });
  };

  return (
    <section className="page-surface ssl-page">
      <header className="page-header">
        <div>
          <h1>{t('ssl.title')}</h1>
          <p>{t('ssl.subtitle')}</p>
        </div>
        <Button type="primary" onClick={() => saveMutation.mutate({ acme: system.acme })} loading={saveMutation.isPending}>
          {t('common.save')}
        </Button>
      </header>

      <div className="ssl-settings-grid">
        <section className="system-fieldset">
          <header>
            <strong>{t('system.acmeDefaults')}</strong>
            <span>{t('system.acmeHint')}</span>
          </header>
          <div className="site-detail-grid">
            <label className="switch-line">
              <span>{t('system.acmeEnabled')}</span>
              <Switch checked={system.acme.enabled} onChange={(enabled) => patchACME({ enabled })} />
            </label>
            <label className="switch-line">
              <span>{t('system.acmeNotify')}</span>
              <Switch checked={system.acme.notify} onChange={(notify) => patchACME({ notify })} />
            </label>
            <label>
              <span>{t('system.acmePath')}</span>
              <Input value={system.acme.acme_sh_path} placeholder="acme.sh" onChange={(acme_sh_path) => patchACME({ acme_sh_path })} />
            </label>
            <label>
              <span>{t('system.acmeServer')}</span>
              <Select value={system.acme.server || 'letsencrypt'} onChange={(server) => patchACME({ server: server as string })}>
                <Select.Option value="letsencrypt">Let's Encrypt</Select.Option>
                <Select.Option value="zerossl">ZeroSSL</Select.Option>
                <Select.Option value="https://acme-v02.api.letsencrypt.org/directory">Let's Encrypt API</Select.Option>
                <Select.Option value="https://acme-staging-v02.api.letsencrypt.org/directory">Let's Encrypt Staging</Select.Option>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeAccountEmail')}</span>
              <Input value={system.acme.account_email} placeholder="ops@example.com" onChange={(account_email) => patchACME({ account_email })} />
            </label>
            <label>
              <span>{t('system.acmeKeyType')}</span>
              <Select value={system.acme.key_type || 'ec-256'} onChange={(key_type) => patchACME({ key_type: key_type as string })}>
                <Select.Option value="ec-256">ECDSA P-256</Select.Option>
                <Select.Option value="ec-384">ECDSA P-384</Select.Option>
                <Select.Option value="2048">RSA 2048</Select.Option>
                <Select.Option value="3072">RSA 3072</Select.Option>
                <Select.Option value="4096">RSA 4096</Select.Option>
              </Select>
            </label>
            <label>
              <span>{t('system.acmeHome')}</span>
              <Input value={system.acme.home} placeholder="./data/acme" onChange={(home) => patchACME({ home })} />
            </label>
            <label>
              <span>{t('system.acmeCertDir')}</span>
              <Input value={system.acme.cert_dir} placeholder="./data/certs" onChange={(cert_dir) => patchACME({ cert_dir })} />
            </label>
            <label className="wide-field">
              <span>{t('system.acmeReloadCommand')}</span>
              <Input value={system.acme.reload_command} placeholder="systemctl reload cheesewaf" onChange={(reload_command) => patchACME({ reload_command })} />
            </label>
          </div>
        </section>

        <section className="system-fieldset acme-provider-settings">
          <header className="fieldset-header-action">
            <div>
              <strong>{t('system.acmeDNSProviders')}</strong>
              <span>{t('system.acmeDNSProvidersHint')}</span>
            </div>
            <Button size="small" icon={<Plus size={14} />} onClick={addProvider}>{t('common.add')}</Button>
          </header>
          <div className="acme-provider-list">
            {system.acme.dns_providers.map((provider, index) => (
              <section className="acme-provider-card" key={`${provider.id}-${index}`}>
                <div className="acme-provider-head">
                  <Switch checked={provider.enabled} onChange={(enabled) => updateProvider(index, { enabled })} />
                  <Input value={provider.id} placeholder="cloudflare" onChange={(id) => updateProvider(index, { id })} />
                  <Button size="mini" status="danger" icon={<Trash2 size={13} />} onClick={() => removeProvider(index)}>{t('common.delete')}</Button>
                </div>
                <div className="site-detail-grid">
                  <label><span>{t('sites.name')}</span><Input value={provider.name} placeholder="Cloudflare" onChange={(name) => updateProvider(index, { name })} /></label>
                  <label><span>{t('system.acmeDNSAPI')}</span><Input value={provider.api} placeholder="dns_cf" onChange={(api) => updateProvider(index, { api })} /></label>
                  <ACMEEnvInput provider={provider} index={index} slot={0} updateProvider={updateProvider} updateProviderEnv={updateProviderEnv} />
                  <ACMEEnvInput provider={provider} index={index} slot={1} updateProvider={updateProvider} updateProviderEnv={updateProviderEnv} />
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

function ACMEEnvInput({
  provider,
  index,
  slot,
  updateProvider,
  updateProviderEnv,
}: {
  provider: SystemConfig['acme']['dns_providers'][number];
  index: number;
  slot: number;
  updateProvider: (index: number, patch: Partial<SystemConfig['acme']['dns_providers'][number]>) => void;
  updateProviderEnv: (index: number, key: string, value: string) => void;
}) {
  const { t } = useTranslation();
  const entries = Object.entries(provider.env ?? {});
  const key = entries[slot]?.[0] ?? '';
  const value = entries[slot]?.[1] ?? '';
  return (
    <>
      <label>
        <span>{t('system.acmeEnvKey')} {slot + 1}</span>
        <Input value={key} placeholder={slot === 0 ? 'CF_TOKEN' : 'CF_ACCOUNT_ID'} onChange={(nextKey) => {
          const normalizedKey = nextKey.toUpperCase().replace(/[^A-Z0-9_]/g, '');
          const next: Record<string, string> = {};
          entries.forEach(([entryKey, entryValue], entryIndex) => {
            if (entryIndex === slot) return;
            next[entryKey] = entryValue;
          });
          if (normalizedKey) next[normalizedKey] = value;
          updateProvider(index, { env: next });
        }} />
      </label>
      <label>
        <span>{t('system.acmeEnvValue')} {slot + 1}</span>
        <Input.Password value={value} onChange={(nextValue) => updateProviderEnv(index, key || (slot === 0 ? 'TOKEN' : 'SECRET'), nextValue)} />
      </label>
    </>
  );
}
