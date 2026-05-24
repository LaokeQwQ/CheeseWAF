import { Button, Input, Table, Tag } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import { Plus, Search, Shield } from 'lucide-react';

const entries = [
  { key: '1', ip: '127.0.0.1', list: 'whitelist', reputation: 100, tags: ['local', 'admin'] },
  { key: '2', ip: '203.0.113.18', list: 'blacklist', reputation: 12, tags: ['sqli', 'repeat'] },
  { key: '3', ip: '198.51.100.77', list: 'blacklist', reputation: 24, tags: ['xss'] },
  { key: '4', ip: '192.0.2.46', list: 'monitor', reputation: 58, tags: ['bot'] },
];

export default function IPManagePage() {
  const { t } = useTranslation();

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ip.title')}</h1>
          <p>{t('ip.subtitle')}</p>
        </div>
        <Button type="primary" icon={<Plus size={16} />}>
          IP
        </Button>
      </header>

      <div className="toolbar-row">
        <Input prefix={<Search size={16} />} placeholder={t('common.search')} allowClear />
      </div>

      <section className="table-panel">
        <Table
          rowKey="key"
          pagination={false}
          data={entries}
          columns={[
            {
              title: 'IP',
              dataIndex: 'ip',
              render: (ip: string) => (
                <span className="table-identity">
                  <Shield size={17} />
                  {ip}
                </span>
              ),
            },
            {
              title: 'List',
              dataIndex: 'list',
              render: (list: string) => {
                const label = list === 'whitelist' ? t('ip.whitelist') : list === 'blacklist' ? t('ip.blacklist') : t('common.monitor');
                const color = list === 'whitelist' ? 'green' : list === 'blacklist' ? 'red' : 'blue';
                return <Tag color={color}>{label}</Tag>;
              },
            },
            { title: t('ip.reputation'), dataIndex: 'reputation' },
            {
              title: t('ip.tags'),
              dataIndex: 'tags',
              render: (tags: string[]) => (
                <span className="tag-stack">
                  {tags.map((tag) => (
                    <Tag key={tag}>{tag}</Tag>
                  ))}
                </span>
              ),
            },
          ]}
        />
      </section>
    </section>
  );
}
