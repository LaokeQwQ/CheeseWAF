import { Button, Input, List, Tag } from '@arco-design/web-react';
import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { FileCode2 } from 'lucide-react';
import { fetchBlockTemplates } from '../../api/client';

export default function BlockPagesPage() {
  const { t } = useTranslation();
  const { data = [] } = useQuery({ queryKey: ['block-templates'], queryFn: fetchBlockTemplates, retry: false });
  const [selected, setSelected] = useState('minimal');
  const template = useMemo(() => data.find((item) => item.id === selected) ?? data[0], [data, selected]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('blockPages.title')}</h1>
          <p>{t('blockPages.subtitle')}</p>
        </div>
        <Button type="primary">{t('common.save')}</Button>
      </header>
      <div className="split-grid">
        <section className="panel">
          <div className="panel-heading"><h2>{t('blockPages.templates')}</h2></div>
          <List
            dataSource={data}
            render={(item) => (
              <List.Item className={item.id === selected ? 'template-item template-item-active' : 'template-item'} onClick={() => setSelected(item.id)}>
                <FileCode2 size={17} />
                <span>{item.name}</span>
                <Tag>{item.id}</Tag>
              </List.Item>
            )}
          />
        </section>
        <section className="panel panel-wide">
          <div className="panel-heading"><h2>{template?.name ?? t('blockPages.editor')}</h2></div>
          <Input.TextArea className="code-editor" value={template?.html ?? ''} autoSize={{ minRows: 18, maxRows: 26 }} />
        </section>
      </div>
    </section>
  );
}
