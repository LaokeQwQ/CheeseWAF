import { Button, Empty, Input, Tag } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FileCode2 } from 'lucide-react';
import { fetchBlockTemplates } from '../../api/client';

export default function BlockPagesPage() {
  const { t } = useTranslation();
  const { data = [], isError, isLoading, refetch } = useQuery({ queryKey: ['block-templates'], queryFn: fetchBlockTemplates, retry: false });
  const [selected, setSelected] = useState('minimal');
  const template = useMemo(() => data.find((item) => item.id === selected) ?? data[0], [data, selected]);

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
        <section className="panel panel-wide">
          <div className="panel-heading">
            <h2>{template?.name ?? t('blockPages.editor')}</h2>
            <Tag>{t('blockPages.templateSource')}</Tag>
          </div>
          <Input.TextArea className="code-editor" value={template?.html ?? ''} readOnly autoSize={{ minRows: 18, maxRows: 26 }} />
        </section>
        <section className="panel panel-wide">
          <div className="panel-heading"><h2>{t('blockPages.preview')}</h2></div>
          <div className="block-preview" dangerouslySetInnerHTML={{ __html: template?.html ?? '' }} />
        </section>
      </div>
    </section>
  );
}
