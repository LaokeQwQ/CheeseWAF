import { Button, Empty, Input, Message as ArcoMessage, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ChangeEvent, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCircle2, Copy, Download, ExternalLink, FileCode2, FileUp, RotateCcw, Save } from 'lucide-react';
import {
  APIRequestError,
  deleteCustomBlockPage,
  fetchBlockPageConfig,
  fetchBlockTemplates,
  previewBlockPageConfig,
  updateBlockPageConfig,
  uploadBlockPageHTML,
} from '../../api/client';
import type { BlockPageConfig } from '../../types/api';
import '../../styles/block-pages.css';
import '../../styles/arco-components';

const blockPreviewStoragePrefix = 'cheesewaf-block-page-preview-html';

export default function BlockPagesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const templatesQuery = useQuery({ queryKey: ['block-templates'], queryFn: fetchBlockTemplates, retry: false });
  const configQuery = useQuery({ queryKey: ['block-page-config'], queryFn: fetchBlockPageConfig, retry: false });
  const data = Array.isArray(templatesQuery.data) ? templatesQuery.data : [];
  const activeConfig = isBlockPageConfig(configQuery.data) ? configQuery.data : undefined;
  const [selected, setSelected] = useState('minimal');
  const [customHTML, setCustomHTML] = useState('');
  const [previewDraft, setPreviewDraft] = useState('');

  useEffect(() => {
    if (!activeConfig) {
      return;
    }
    setSelected(activeConfig.template_id || 'minimal');
    setCustomHTML(activeConfig.custom_html ?? '');
  }, [activeConfig]);

  const template = useMemo(() => data.find((item) => item.id === selected) ?? data[0], [data, selected]);
  const templateHTML = template?.html ?? '';
  const previewPayload = useMemo(() => ({
    template_id: selected,
    custom_enabled: Boolean(customHTML.trim()),
    custom_html: customHTML,
  }), [customHTML, selected]);
  const templateName = (id: string, fallback: string) => t(`blockPages.templateNames.${id}`, { defaultValue: fallback });
  const templateDescription = (id: string, fallback: string) => t(`blockPages.templateDescriptions.${id}`, { defaultValue: fallback });
  const sourceLabel = activeConfig?.custom_enabled ? t('blockPages.customActive') : t('blockPages.builtInActive', { name: templateName(template?.id ?? selected, template?.name ?? selected) });
  const isLoading = templatesQuery.isLoading || configQuery.isLoading;
  const isError = templatesQuery.isError || configQuery.isError;
  const error = templatesQuery.error ?? configQuery.error;
  const customBytes = new Blob([customHTML]).size;

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setPreviewDraft(JSON.stringify(previewPayload));
    }, 350);
    return () => window.clearTimeout(timer);
  }, [previewPayload]);

  const previewQuery = useQuery({
    queryKey: ['block-page-preview', previewDraft],
    queryFn: () => previewBlockPageConfig(JSON.parse(previewDraft) as typeof previewPayload),
    enabled: Boolean(previewDraft) && !isLoading && Boolean(template || customHTML.trim()),
    retry: false,
  });
  const previewHTML = previewQuery.data?.html ?? (customHTML.trim() ? customHTML : templateHTML);
  const safePreviewHTML = useMemo(() => sanitizeBlockPreviewHTML(previewHTML), [previewHTML]);

  const saveBuiltInMutation = useMutation({
    mutationFn: () => updateBlockPageConfig({ template_id: selected, custom_enabled: false, custom_html: activeConfig?.custom_html ?? customHTML }),
    onSuccess: async () => {
      ArcoMessage.success(t('blockPages.saved'));
      await queryClient.invalidateQueries({ queryKey: ['block-page-config'] });
    },
    onError: (mutationError: Error) => ArcoMessage.error(mutationError.message),
  });

  const saveCustomMutation = useMutation({
    mutationFn: () => updateBlockPageConfig({ template_id: selected, custom_enabled: true, custom_html: customHTML }),
    onSuccess: async () => {
      ArcoMessage.success(t('blockPages.customSaved'));
      await queryClient.invalidateQueries({ queryKey: ['block-page-config'] });
    },
    onError: (mutationError: Error) => ArcoMessage.error(mutationError.message),
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadBlockPageHTML(file, selected),
    onSuccess: async (result) => {
      setCustomHTML(result.config.custom_html);
      ArcoMessage.success(t('blockPages.uploaded', { name: result.filename }));
      await queryClient.invalidateQueries({ queryKey: ['block-page-config'] });
    },
    onError: (mutationError: Error) => ArcoMessage.error(mutationError.message),
  });

  const restoreMutation = useMutation({
    mutationFn: deleteCustomBlockPage,
    onSuccess: async () => {
      ArcoMessage.success(t('blockPages.restored'));
      await queryClient.invalidateQueries({ queryKey: ['block-page-config'] });
    },
    onError: (mutationError: Error) => ArcoMessage.error(mutationError.message),
  });

  async function copyTemplate() {
    const sourceHTML = customHTML.trim() ? customHTML : templateHTML;
    if (!sourceHTML) {
      return;
    }
    try {
      await navigator.clipboard.writeText(sourceHTML);
      ArcoMessage.success(t('blockPages.copied'));
    } catch {
      ArcoMessage.error(t('blockPages.copyFailed'));
    }
  }

  function downloadTemplate() {
    const sourceHTML = customHTML.trim() ? customHTML : templateHTML;
    if (!sourceHTML) {
      return;
    }
    const blob = new Blob([sourceHTML], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = activeConfig?.custom_enabled ? 'cheesewaf-custom-block-page.html' : `${template?.id ?? 'block-page'}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function openPreviewWindow() {
    if (!safePreviewHTML.trim()) {
      ArcoMessage.warning(t('blockPages.noPreviewContent'));
      return;
    }
    // Never open executable same-origin blob URLs. Hand HTML to the in-app
    // preview route, which renders inside a sandboxed iframe (no scripts, no same-origin).
    const token = `${blockPreviewStoragePrefix}:${crypto.randomUUID()}`;
    try {
      localStorage.setItem(token, JSON.stringify({ html: safePreviewHTML, created_at: Date.now() }));
    } catch {
      ArcoMessage.error(t('blockPages.previewOpenFailed'));
      return;
    }
    const previewURL = `/block-pages/preview?token=${encodeURIComponent(token)}`;
    const previewWindow = window.open(previewURL, '_blank', 'noopener,noreferrer');
    if (!previewWindow) {
      try {
        localStorage.removeItem(token);
      } catch {
        // ignore storage cleanup failures
      }
      ArcoMessage.error(t('blockPages.previewOpenFailed'));
    }
  }

  function saveCustom() {
    if (!configQuery.isSuccess) {
      return;
    }
    if (!customHTML.trim()) {
      ArcoMessage.warning(t('blockPages.emptyCustom'));
      return;
    }
    saveCustomMutation.mutate();
  }

  function onUploadChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) {
      return;
    }
    uploadMutation.mutate(file);
  }

  return (
    <section className="page-surface block-pages-page">
      <header className="page-header block-page-header">
        <div>
          <h1>{t('blockPages.title')}</h1>
          <p>{t('blockPages.subtitle')}</p>
        </div>
        <div className="block-page-header-actions">
          {configQuery.isSuccess && <Tag className="status-pill" icon={<CheckCircle2 size={14} />}>{sourceLabel}</Tag>}
          {isError && <Button onClick={() => { templatesQuery.refetch(); configQuery.refetch(); }}>{t('common.retry')}</Button>}
        </div>
      </header>

      {isError && (
        <div className="inline-error" role="alert">
          <span>{t('blockPages.loadFailed')}</span>
          {error instanceof APIRequestError && error.traceID && <code>{error.traceID}</code>}
          <Button size="small" onClick={() => { templatesQuery.refetch(); configQuery.refetch(); }}>{t('common.retry')}</Button>
        </div>
      )}

      <div className="block-page-grid block-page-workspace">
        <section className="panel template-panel">
          <div className="panel-heading">
            <div>
              <h2>{t('blockPages.templates')}</h2>
              <p>{t('blockPages.templatesHint')}</p>
            </div>
          </div>
          {isLoading ? <div className="skeleton-list" /> : data.length ? (
            <div className="template-list" role="list">
              {data.map((item) => (
                <button
                  type="button"
                  className={item.id === selected ? 'template-item template-item-active' : 'template-item'}
                  key={item.id}
                  onClick={() => setSelected(item.id)}
                >
                  <FileCode2 size={17} />
                  <span className="template-item-copy">
                    <span className="template-item-name">{templateName(item.id, item.name)}</span>
                    <span className="template-item-desc">{templateDescription(item.id, item.description)}</span>
                  </span>
                  <span className="template-item-id">{item.id}</span>
                </button>
              ))}
            </div>
          ) : <Empty description={t('blockPages.noTemplates')} />}
          <div className="block-template-actions">
            <Button disabled={!templateHTML} onClick={() => setCustomHTML(templateHTML)}>{t('blockPages.useAsBase')}</Button>
            <Button type="primary" loading={saveBuiltInMutation.isPending} disabled={!template || !configQuery.isSuccess} onClick={() => saveBuiltInMutation.mutate()}>{t('blockPages.useBuiltIn')}</Button>
          </div>
        </section>

        <section className="panel panel-wide block-editor-panel">
          <div className="panel-heading block-editor-heading">
            <div>
              <h2>{t('blockPages.customHtml')}</h2>
              <p>{t('blockPages.customHint')}</p>
            </div>
            <div className="block-editor-actions">
              <input ref={fileInputRef} type="file" accept=".html,.htm,text/html" hidden onChange={onUploadChange} />
              <Tag>{t('blockPages.sizeLabel', { size: formatBytes(customBytes) })}</Tag>
              <Button icon={<FileUp size={14} />} loading={uploadMutation.isPending} disabled={!configQuery.isSuccess} onClick={() => fileInputRef.current?.click()}>{t('blockPages.uploadHtml')}</Button>
              <Button icon={<RotateCcw size={14} />} loading={restoreMutation.isPending} disabled={!configQuery.isSuccess || (!activeConfig?.custom_enabled && !customHTML)} onClick={() => restoreMutation.mutate()}>{t('blockPages.restoreBuiltIn')}</Button>
              <Button icon={<Save size={14} />} type="primary" loading={saveCustomMutation.isPending} disabled={!configQuery.isSuccess} onClick={saveCustom}>{t('blockPages.saveCustom')}</Button>
            </div>
          </div>
          <Input.TextArea
            className="code-editor"
            value={customHTML}
            placeholder={t('blockPages.editorPlaceholder')}
            onChange={setCustomHTML}
            autoSize={{ minRows: 18, maxRows: 26 }}
          />
        </section>

        <section className="panel panel-wide block-preview-panel">
          <div className="panel-heading block-editor-heading">
            <div>
              <h2>{t('blockPages.preview')}</h2>
              <p>{t('blockPages.previewHint')}</p>
            </div>
            <div className="block-editor-actions">
              {previewQuery.data?.event_id && <Tag className="status-pill">{t('blockPages.previewEvent', { id: previewQuery.data.event_id })}</Tag>}
              <Button icon={<ExternalLink size={14} />} disabled={!previewHTML.trim()} onClick={openPreviewWindow}>{t('blockPages.openPreview')}</Button>
              <Button icon={<Copy size={14} />} disabled={!templateHTML && !customHTML.trim()} onClick={copyTemplate}>{t('blockPages.copyHtml')}</Button>
              <Button icon={<Download size={14} />} disabled={!templateHTML && !customHTML.trim()} onClick={downloadTemplate}>{t('blockPages.downloadHtml')}</Button>
            </div>
          </div>
          {previewQuery.error instanceof APIRequestError && (
            <div className="inline-error block-preview-error" role="alert">
              <span>{previewQuery.error.rawMessage}</span>
              {previewQuery.error.traceID && <code>{previewQuery.error.traceID}</code>}
            </div>
          )}
          <div className="block-preview-frame">
            {previewQuery.isFetching && !safePreviewHTML ? <div className="block-preview-loading">{t('blockPages.renderingPreview')}</div> : <iframe title={t('blockPages.preview')} sandbox="" referrerPolicy="no-referrer" srcDoc={safePreviewHTML} />}
          </div>
        </section>
      </div>
    </section>
  );
}

export function BlockPagePreviewWindow() {
  const { t } = useTranslation();
  const [html] = useState(() => {
    const token = new URLSearchParams(window.location.search).get('token') ?? '';
    const raw = readPreviewPayload(token);
    if (!raw) {
      return '';
    }
    try {
      const parsed = JSON.parse(raw) as { html?: string; created_at?: number };
      if (!parsed.created_at || Date.now() - parsed.created_at > 10 * 60_000) {
        return '';
      }
      return parsed.html ?? '';
    } catch {
      return '';
    }
  });
  const safeHTML = useMemo(() => sanitizeBlockPreviewHTML(html), [html]);

  useEffect(() => {
    document.title = t('blockPages.preview');
  }, [t]);

  if (!safeHTML.trim()) {
    return (
      <main className="block-preview-standalone block-preview-standalone-empty">
        <section>
          <h1>{t('blockPages.preview')}</h1>
          <p>{t('blockPages.noPreviewContent')}</p>
        </section>
      </main>
    );
  }

  return (
    <main className="block-preview-standalone">
      <iframe title={t('blockPages.preview')} sandbox="" referrerPolicy="no-referrer" srcDoc={safeHTML} />
    </main>
  );
}

function readPreviewPayload(token: string) {
  if (!token.startsWith(`${blockPreviewStoragePrefix}:`)) {
    return '';
  }
  try {
    const raw = localStorage.getItem(token);
    localStorage.removeItem(token);
    return raw ?? '';
  } catch {
    return '';
  }
}

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export function sanitizeBlockPreviewHTML(value: string) {
  const html = value.trim();
  if (!html) {
    return '';
  }
  if (typeof DOMParser === 'undefined') {
    return '';
  }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('script, iframe, object, embed, base, link[rel="import"], meta[http-equiv="refresh"]').forEach((node) => node.remove());
  doc.querySelectorAll('*').forEach((element) => {
    Array.from(element.attributes).forEach((attribute) => {
      const name = attribute.name.toLowerCase();
      if (name.startsWith('on')) {
        element.removeAttribute(attribute.name);
        return;
      }
      // Drop navigation/form targets that can escape the sandbox intent.
      if (name === 'srcset' || name === 'action' || name === 'formaction' || name === 'form' || name === 'xlink:href') {
        element.removeAttribute(attribute.name);
        return;
      }
      if (isDangerousPreviewURLAttribute(name, attribute.value)) {
        element.removeAttribute(attribute.name);
      }
    });
  });
  return `<!doctype html>\n${doc.documentElement.outerHTML}`;
}

function isDangerousPreviewURLAttribute(name: string, rawValue: string) {
  if (!['href', 'src', 'poster', 'cite', 'data', 'background'].includes(name.toLowerCase())) {
    return false;
  }
  const normalized = compactURLScheme(rawValue).toLowerCase();
  return normalized.startsWith('javascript:') || normalized.startsWith('vbscript:') || normalized.startsWith('data:');
}

function compactURLScheme(value: string) {
  let output = '';
  for (const char of value.trim()) {
    const code = char.charCodeAt(0);
    if (code <= 0x20 || code === 0x7f) {
      continue;
    }
    output += char;
  }
  return output;
}

function isBlockPageConfig(value: unknown): value is BlockPageConfig {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
