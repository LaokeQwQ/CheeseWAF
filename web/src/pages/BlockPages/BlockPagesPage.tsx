import { Button, Empty, Input, Message as ArcoMessage, Tag } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Copy, Download, FileCode2 } from 'lucide-react';
import { fetchBlockTemplates } from '../../api/client';

export default function BlockPagesPage() {
  const { t } = useTranslation();
  const { data = [], isError, isLoading, refetch } = useQuery({ queryKey: ['block-templates'], queryFn: fetchBlockTemplates, retry: false });
  const [selected, setSelected] = useState('minimal');
  const template = useMemo(() => data.find((item) => item.id === selected) ?? data[0], [data, selected]);
  const templateHTML = template?.html ?? '';
  const templateName = template?.name ?? t('blockPages.editor');

  async function copyTemplate() {
    if (!templateHTML) {
      return;
    }
    try {
      await navigator.clipboard.writeText(templateHTML);
      ArcoMessage.success(t('blockPages.copied'));
    } catch {
      ArcoMessage.error(t('blockPages.copyFailed'));
    }
  }

  function downloadTemplate() {
    if (!templateHTML) {
      return;
    }
    const blob = new Blob([templateHTML], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${template?.id ?? 'block-page'}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('blockPages.title')}</h1>
          <p>{t('blockPages.subtitle')}</p>
        </div>
        {isError && <Button onClick={() => refetch()}>{t('common.retry')}</Button>}
      </header>
      {isError && (
        <div className="inline-error">
          <span>{t('blockPages.loadFailed')}</span>
          <Button size="small" onClick={() => refetch()}>{t('common.retry')}</Button>
        </div>
      )}
      <div className="block-page-grid block-page-workspace">
        <section className="panel template-panel">
          <div className="panel-heading"><h2>{t('blockPages.templates')}</h2></div>
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
                  <span className="template-item-name">{item.name}</span>
                  <span className="template-item-id">{item.id}</span>
                </button>
              ))}
            </div>
          ) : <Empty description={t('blockPages.noTemplates')} />}
        </section>
        <section className="panel panel-wide block-editor-panel">
          <div className="panel-heading block-editor-heading">
            <div>
              <h2>{templateName}</h2>
              <p>{t('blockPages.systemTemplateReadonly')}</p>
            </div>
            <div className="block-editor-actions">
              <Tag>{t('blockPages.templateSource')}</Tag>
              <Button icon={<Copy size={14} />} disabled={!templateHTML} onClick={copyTemplate}>{t('blockPages.copyHtml')}</Button>
              <Button icon={<Download size={14} />} disabled={!templateHTML} onClick={downloadTemplate}>{t('blockPages.downloadHtml')}</Button>
            </div>
          </div>
          <Input.TextArea className="code-editor" value={templateHTML} readOnly autoSize={{ minRows: 18, maxRows: 26 }} />
        </section>
        <section className="panel panel-wide">
          <div className="panel-heading"><h2>{t('blockPages.preview')}</h2></div>
          <div className="block-preview-frame">
            <iframe title={t('blockPages.preview')} sandbox="" srcDoc={template?.html ?? ''} />
          </div>
        </section>
      </div>
    </section>
  );
}
