import { Button, Empty, Input, Message as ArcoMessage, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { type ChangeEvent, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCircle2, Copy, Download, FileCode2, FileUp, RotateCcw, Save } from 'lucide-react';
import {
  APIRequestError,
  deleteCustomBlockPage,
  fetchBlockPageConfig,
  fetchBlockTemplates,
  updateBlockPageConfig,
  uploadBlockPageHTML,
} from '../../api/client';

export default function BlockPagesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const templatesQuery = useQuery({ queryKey: ['block-templates'], queryFn: fetchBlockTemplates, retry: false });
  const configQuery = useQuery({ queryKey: ['block-page-config'], queryFn: fetchBlockPageConfig, retry: false });
  const data = templatesQuery.data ?? [];
  const activeConfig = configQuery.data;
  const [selected, setSelected] = useState('minimal');
  const [customHTML, setCustomHTML] = useState('');

  useEffect(() => {
    if (!activeConfig) {
      return;
    }
    setSelected(activeConfig.template_id || 'minimal');
    setCustomHTML(activeConfig.custom_html ?? '');
  }, [activeConfig]);

  const template = useMemo(() => data.find((item) => item.id === selected) ?? data[0], [data, selected]);
  const templateHTML = template?.html ?? '';
  const previewHTML = customHTML.trim() ? customHTML : templateHTML;
  const sourceLabel = activeConfig?.custom_enabled ? t('blockPages.customActive') : t('blockPages.builtInActive', { name: template?.name ?? selected });
  const isLoading = templatesQuery.isLoading || configQuery.isLoading;
  const isError = templatesQuery.isError || configQuery.isError;
  const error = templatesQuery.error ?? configQuery.error;

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
    if (!previewHTML) {
      return;
    }
    try {
      await navigator.clipboard.writeText(previewHTML);
      ArcoMessage.success(t('blockPages.copied'));
    } catch {
      ArcoMessage.error(t('blockPages.copyFailed'));
    }
  }

  function downloadTemplate() {
    if (!previewHTML) {
      return;
    }
    const blob = new Blob([previewHTML], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = activeConfig?.custom_enabled ? 'cheesewaf-custom-block-page.html' : `${template?.id ?? 'block-page'}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function saveCustom() {
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
    <section className="page-surface">
      <header className="page-header block-page-header">
        <div>
          <h1>{t('blockPages.title')}</h1>
          <p>{t('blockPages.subtitle')}</p>
        </div>
        <div className="block-page-header-actions">
          <Tag className="status-pill" icon={<CheckCircle2 size={14} />}>{sourceLabel}</Tag>
          {isError && <Button onClick={() => { templatesQuery.refetch(); configQuery.refetch(); }}>{t('common.retry')}</Button>}
        </div>
      </header>

      {isError && (
        <div className="inline-error">
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
                    <span className="template-item-name">{item.name}</span>
                    <span className="template-item-desc">{item.description}</span>
                  </span>
                  <span className="template-item-id">{item.id}</span>
                </button>
              ))}
            </div>
          ) : <Empty description={t('blockPages.noTemplates')} />}
          <div className="block-template-actions">
            <Button disabled={!templateHTML} onClick={() => setCustomHTML(templateHTML)}>{t('blockPages.useAsBase')}</Button>
            <Button type="primary" loading={saveBuiltInMutation.isPending} disabled={!template} onClick={() => saveBuiltInMutation.mutate()}>{t('blockPages.useBuiltIn')}</Button>
          </div>
        </section>

        <section className="panel panel-wide block-editor-panel">
          <div className="panel-heading block-editor-heading">
            <div>
              <h2>{t('blockPages.customHtml')}</h2>
              <p>{t('blockPages.customHint')}</p>
            </div>
            <div className="block-editor-actions">
              <input ref={fileInputRef} type="file" accept=".html,text/html" hidden onChange={onUploadChange} />
              <Button icon={<FileUp size={14} />} loading={uploadMutation.isPending} onClick={() => fileInputRef.current?.click()}>{t('blockPages.uploadHtml')}</Button>
              <Button icon={<RotateCcw size={14} />} loading={restoreMutation.isPending} disabled={!activeConfig?.custom_enabled && !customHTML} onClick={() => restoreMutation.mutate()}>{t('blockPages.restoreBuiltIn')}</Button>
              <Button icon={<Save size={14} />} type="primary" loading={saveCustomMutation.isPending} onClick={saveCustom}>{t('blockPages.saveCustom')}</Button>
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
              <Button icon={<Copy size={14} />} disabled={!previewHTML} onClick={copyTemplate}>{t('blockPages.copyHtml')}</Button>
              <Button icon={<Download size={14} />} disabled={!previewHTML} onClick={downloadTemplate}>{t('blockPages.downloadHtml')}</Button>
            </div>
          </div>
          <div className="block-preview-frame">
            <iframe title={t('blockPages.preview')} sandbox="" srcDoc={previewHTML} />
          </div>
        </section>
      </div>
    </section>
  );
}
