import { Button, Empty, Input, Message, Modal, Select, Skeleton, Switch, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Cloud, Eye, FileImage, HardDrive, RefreshCw, Save, ShieldAlert, ShieldX, Trash2, Upload } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { APIRequestError } from '../../api/client';
import { deleteCAPTCHAAsset, fetchCAPTCHAAssetConfig, fetchCAPTCHAAssetPreview, fetchCAPTCHAAssets, testCAPTCHAAssetConfig, updateCAPTCHAAssetConfig, uploadCAPTCHAAsset } from '../../api/captchaAssets';
import type { CAPTCHAAsset, CAPTCHAAssetConfig, CAPTCHAAssetConfigUpdate, CAPTCHAAssetKind } from '../../types/api';
import styles from './CaptchaAssetsPanel.module.css';

const KINDS: CAPTCHAAssetKind[] = ['background', 'font', 'icon', 'logo'];
const NANOSECONDS_PER_SECOND = 1_000_000_000;

export default function CaptchaAssetsPanel() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const previewURL = useRef('');
  const [section, setSection] = useState<'assets' | 'storage'>('assets');
  const [kind, setKind] = useState<CAPTCHAAssetKind | 'all'>('all');
  const [uploadKind, setUploadKind] = useState<CAPTCHAAssetKind>('background');
  const [preview, setPreview] = useState<{ asset: CAPTCHAAsset; url: string }>();
  const [config, setConfig] = useState<CAPTCHAAssetConfigUpdate>();
  const [credentialConfigured, setCredentialConfigured] = useState(false);
  const [metadataKeyConfigured, setMetadataKeyConfigured] = useState(false);
  const assetsQuery = useQuery({ queryKey: ['captcha-assets', kind], queryFn: () => fetchCAPTCHAAssets(kind === 'all' ? undefined : kind), retry: false });
  const configQuery = useQuery({ queryKey: ['captcha-assets-config'], queryFn: fetchCAPTCHAAssetConfig, retry: false });

  useEffect(() => {
    if (!configQuery.data) return;
    setConfig(toUpdate(configQuery.data));
    setCredentialConfigured(configQuery.data.s3.credential_configured);
    setMetadataKeyConfigured(configQuery.data.s3.metadata_key_configured);
  }, [configQuery.data]);
  useEffect(() => () => { if (previewURL.current) URL.revokeObjectURL(previewURL.current); }, []);

  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadCAPTCHAAsset(uploadKind, file),
    onSuccess: () => { Message.success(t('botChallenge.captchaAssets.uploadSuccess')); void queryClient.invalidateQueries({ queryKey: ['captcha-assets'] }); },
    onError: (error) => Message.error(errorMessage(error, t('botChallenge.captchaAssets.uploadFailed'))),
  });
  const deleteMutation = useMutation({
    mutationFn: deleteCAPTCHAAsset,
    onSuccess: () => { Message.success(t('botChallenge.captchaAssets.deleteSuccess')); void queryClient.invalidateQueries({ queryKey: ['captcha-assets'] }); },
    onError: (error) => Message.error(errorMessage(error, t('botChallenge.captchaAssets.deleteFailed'))),
  });
  const previewMutation = useMutation({
    mutationFn: async (asset: CAPTCHAAsset) => ({ asset, result: await fetchCAPTCHAAssetPreview(asset.id) }),
    onSuccess: ({ asset, result }) => {
      if (previewURL.current) URL.revokeObjectURL(previewURL.current);
      previewURL.current = URL.createObjectURL(result.blob);
      setPreview({ asset, url: previewURL.current });
    },
    onError: (error) => Message.error(errorMessage(error, t('botChallenge.captchaAssets.previewFailed'))),
  });
  const saveMutation = useMutation({
    mutationFn: updateCAPTCHAAssetConfig,
    onSuccess: (saved) => { setConfig(toUpdate(saved)); setCredentialConfigured(saved.s3.credential_configured); setMetadataKeyConfigured(saved.s3.metadata_key_configured); Message.success(t('botChallenge.captchaAssets.saveSuccess')); void queryClient.invalidateQueries({ queryKey: ['captcha-assets-config'] }); },
    onError: (error) => Message.error(errorMessage(error, t('botChallenge.captchaAssets.saveFailed'))),
  });
  const testMutation = useMutation({
    mutationFn: testCAPTCHAAssetConfig,
    onSuccess: () => Message.success(t('botChallenge.captchaAssets.testSuccess')),
    onError: (error) => Message.error(errorMessage(error, t('botChallenge.captchaAssets.testFailed'))),
  });

  const forbidden = isForbidden(assetsQuery.error) || isForbidden(configQuery.error);
  return <div className={styles.panel}>
    <div className={styles.sectionTabs} role="tablist" aria-label={t('botChallenge.captchaAssets.title')}>
      <button type="button" role="tab" aria-selected={section === 'assets'} className={section === 'assets' ? styles.active : undefined} onClick={() => setSection('assets')}><FileImage size={17}/>{t('botChallenge.captchaAssets.library')}</button>
      <button type="button" role="tab" aria-selected={section === 'storage'} className={section === 'storage' ? styles.active : undefined} onClick={() => setSection('storage')}><HardDrive size={17}/>{t('botChallenge.captchaAssets.storage')}</button>
    </div>
    {forbidden ? <State icon={<ShieldX/>} title={t('botChallenge.captchaAssets.forbidden')} hint={t('botChallenge.captchaAssets.forbiddenHint')}/> : section === 'assets' ? <>
      <div className={styles.toolbar}>
        <Select value={kind} onChange={setKind} aria-label={t('botChallenge.captchaAssets.filter')}><Select.Option value="all">{t('botChallenge.captchaAssets.allTypes')}</Select.Option>{KINDS.map((item) => <Select.Option key={item} value={item}>{t(`botChallenge.captchaAssets.kinds.${item}`)}</Select.Option>)}</Select>
        <div className={styles.uploadControls}><Select value={uploadKind} onChange={setUploadKind} aria-label={t('botChallenge.captchaAssets.uploadType')}>{KINDS.map((item) => <Select.Option key={item} value={item}>{t(`botChallenge.captchaAssets.kinds.${item}`)}</Select.Option>)}</Select><input ref={fileRef} className={styles.fileInput} type="file" accept="image/*,.woff,.woff2,.ttf,.otf" onChange={(event) => { const file = event.target.files?.[0]; if (file) uploadMutation.mutate(file); event.target.value = ''; }}/><Button type="primary" icon={<Upload size={16}/>} loading={uploadMutation.isPending} onClick={() => fileRef.current?.click()}>{t('botChallenge.captchaAssets.upload')}</Button></div>
      </div>
      {assetsQuery.isLoading ? <AssetSkeleton/> : assetsQuery.isError ? <State icon={<ShieldX/>} title={t('botChallenge.captchaAssets.loadFailed')} hint={errorMessage(assetsQuery.error, '')} action={<Button icon={<RefreshCw size={16}/>} onClick={() => assetsQuery.refetch()}>{t('common.retry')}</Button>}/> : assetsQuery.data?.items.length ? <div className={styles.assetGrid}>{assetsQuery.data.items.map((asset) => <article className={styles.assetItem} key={asset.id}><div className={styles.assetIcon}><FileImage size={22}/></div><div className={styles.assetInfo}><div><strong title={asset.name}>{asset.name}</strong><Tag>{t(`botChallenge.captchaAssets.kinds.${asset.kind}`)}</Tag></div><span>{formatBytes(asset.size)} · {new Date(asset.created_at).toLocaleString(i18n.resolvedLanguage)}</span><code title={asset.sha256}>{asset.sha256.slice(0, 16)}</code></div><div className={styles.itemActions}>{asset.kind !== 'font' && <Button icon={<Eye size={16}/>} loading={previewMutation.isPending && previewMutation.variables?.id === asset.id} onClick={() => previewMutation.mutate(asset)}>{t('botChallenge.captchaAssets.preview')}</Button>}<Button status="danger" icon={<Trash2 size={16}/>} loading={deleteMutation.isPending && deleteMutation.variables === asset.id} onClick={() => confirmDelete(asset, () => deleteMutation.mutate(asset.id), t)}>{t('common.delete')}</Button></div></article>)}</div> : <Empty description={t('botChallenge.captchaAssets.empty')}/>}
    </> : configQuery.isLoading || !config ? <AssetSkeleton/> : configQuery.isError ? <State icon={<ShieldX/>} title={t('botChallenge.captchaAssets.configLoadFailed')} hint={errorMessage(configQuery.error, '')} action={<Button onClick={() => configQuery.refetch()}>{t('common.retry')}</Button>}/> : <ConfigEditor config={config} setConfig={setConfig} credentialConfigured={credentialConfigured} metadataKeyConfigured={metadataKeyConfigured} saving={saveMutation.isPending} testing={testMutation.isPending} onSave={() => saveMutation.mutate(config)} onTest={() => testMutation.mutate(config)}/>}
    <Modal visible={Boolean(preview)} title={preview?.asset.name} footer={null} onCancel={() => { setPreview(undefined); if (previewURL.current) { URL.revokeObjectURL(previewURL.current); previewURL.current = ''; } }} unmountOnExit>{preview && <div className={styles.preview}><img src={preview.url} alt={preview.asset.name}/><span>{t('botChallenge.captchaAssets.previewOneTime')}</span></div>}</Modal>
  </div>;
}

function ConfigEditor({ config, setConfig, credentialConfigured, metadataKeyConfigured, saving, testing, onSave, onTest }: { config: CAPTCHAAssetConfigUpdate; setConfig: (value: CAPTCHAAssetConfigUpdate) => void; credentialConfigured: boolean; metadataKeyConfigured: boolean; saving: boolean; testing: boolean; onSave: () => void; onTest: () => void }) {
  const { t } = useTranslation();
  const patch = (next: Partial<CAPTCHAAssetConfigUpdate>) => setConfig({ ...config, ...next });
  const patchS3 = (next: Partial<CAPTCHAAssetConfigUpdate['s3']>) => patch({ s3: { ...config.s3, ...next } });
  return <div className={styles.configArea}><div className={styles.configHeading}><div><h2>{t('botChallenge.captchaAssets.storageConfig')}</h2><p>{t('botChallenge.captchaAssets.storageHint')}</p></div><div><Button icon={<Cloud size={16}/>} loading={testing} onClick={onTest}>{t('botChallenge.captchaAssets.test')}</Button><Button type="primary" icon={<Save size={16}/>} loading={saving} onClick={onSave}>{t('common.save')}</Button></div></div><div className={styles.backendSwitch}><button type="button" className={config.backend === 'local' ? styles.activeBackend : undefined} onClick={() => patch({ backend: 'local' })}><HardDrive size={18}/><span><strong>{t('botChallenge.captchaAssets.local')}</strong><small>{t('botChallenge.captchaAssets.localHint')}</small></span></button><button type="button" className={config.backend === 's3' ? styles.activeBackend : undefined} onClick={() => patch({ backend: 's3' })}><Cloud size={18}/><span><strong>S3</strong><small>{t('botChallenge.captchaAssets.s3Hint')}</small></span></button></div>{config.backend === 'local' ? <div className={styles.formGrid}><Field label={t('botChallenge.captchaAssets.localPath')}><Input value={config.local.path} onChange={(path) => patch({ local: { path } })}/></Field></div> : <div className={styles.formGrid}><Field label={t('botChallenge.captchaAssets.endpoint')}><Input value={config.s3.endpoint} onChange={(endpoint) => patchS3({ endpoint })}/></Field><Field label={t('botChallenge.captchaAssets.bucket')}><Input value={config.s3.bucket} onChange={(bucket) => patchS3({ bucket })}/></Field><Field label={t('botChallenge.captchaAssets.region')}><Input value={config.s3.region} onChange={(region) => patchS3({ region })}/></Field><Field label={t('botChallenge.captchaAssets.prefix')}><Input value={config.s3.prefix} onChange={(prefix) => patchS3({ prefix })}/></Field><Field label={t('botChallenge.captchaAssets.credential')} hint={credentialConfigured ? t('botChallenge.captchaAssets.credentialConfigured') : t('botChallenge.captchaAssets.credentialMissing')}><Input type="password" autoComplete="new-password" value={config.s3.credential_file} placeholder={credentialConfigured ? '••••••••' : ''} onChange={(credential_file) => patchS3({ credential_file })}/></Field><Field label={t('botChallenge.captchaAssets.metadataKey')} hint={metadataKeyConfigured ? t('botChallenge.captchaAssets.metadataKeyConfigured') : t('botChallenge.captchaAssets.metadataKeyMissing')}><Input type="password" autoComplete="new-password" value={config.s3.metadata_key_file} placeholder={metadataKeyConfigured ? '••••••••' : ''} onChange={(metadata_key_file) => patchS3({ metadata_key_file })}/></Field><Field label={t('botChallenge.captchaAssets.timeout')}><Input type="number" min={1} value={String(config.s3.request_timeout / NANOSECONDS_PER_SECOND)} onChange={(value) => patchS3({ request_timeout: Math.max(1, Number(value) || 1) * NANOSECONDS_PER_SECOND })}/></Field><Toggle label={t('botChallenge.captchaAssets.useTLS')} checked={config.s3.use_tls} onChange={(use_tls) => patchS3({ use_tls })}/><Toggle label={t('botChallenge.captchaAssets.pathStyle')} checked={config.s3.path_style} onChange={(path_style) => patchS3({ path_style })}/><div className={styles.privateEndpoint}><Toggle label={t('botChallenge.captchaAssets.allowPrivateEndpoint', { defaultValue: 'Allow private or local S3 endpoints' })} checked={config.s3.allow_private_endpoint} onChange={(allow_private_endpoint) => patchS3({ allow_private_endpoint })}/>{config.s3.allow_private_endpoint && <p className={styles.riskHint} role="alert"><ShieldAlert size={17}/><span>{t('botChallenge.captchaAssets.allowPrivateEndpointRisk', { defaultValue: 'Private endpoint access lets the server connect to local, private, and link-local addresses. Enable it only for a trusted S3 endpoint.' })}</span></p>}</div></div>}</div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) { return <label className={styles.field}><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>; }
function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) { return <label className={styles.toggle}><span>{label}</span><Switch checked={checked} onChange={onChange}/></label>; }
function State({ icon, title, hint, action }: { icon: React.ReactNode; title: string; hint: string; action?: React.ReactNode }) { return <div className={styles.state}>{icon}<strong>{title}</strong><span>{hint}</span>{action}</div>; }
function AssetSkeleton() { return <div className={styles.skeleton}><Skeleton text={{ rows: 5 }} animation/></div>; }
function toUpdate(value: CAPTCHAAssetConfig): CAPTCHAAssetConfigUpdate { return { backend: value.backend, local: { ...value.local }, s3: { endpoint: value.s3.endpoint, bucket: value.s3.bucket, region: value.s3.region, path_style: value.s3.path_style, prefix: value.s3.prefix, use_tls: value.s3.use_tls, allow_private_endpoint: value.s3.allow_private_endpoint, request_timeout: value.s3.request_timeout, credential_file: '', metadata_key_file: '' }, limits: { ...value.limits } }; }
function isForbidden(error: unknown) { return error instanceof APIRequestError && error.status === 403; }
function errorMessage(error: unknown, fallback: string) { return error instanceof Error ? error.message : fallback; }
function formatBytes(size: number) { if (size < 1024) return `${size} B`; if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`; return `${(size / 1024 / 1024).toFixed(1)} MB`; }
function confirmDelete(asset: CAPTCHAAsset, onConfirm: () => void, t: ReturnType<typeof useTranslation>['t']) { Modal.confirm({ title: t('botChallenge.captchaAssets.deleteTitle'), content: t('botChallenge.captchaAssets.deleteConfirm', { name: asset.name }), okButtonProps: { status: 'danger' }, onOk: onConfirm }); }
