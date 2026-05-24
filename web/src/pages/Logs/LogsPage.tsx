import { Input, Select, Table, Tag } from '@arco-design/web-react';
import { useTranslation } from 'react-i18next';
import { Search } from 'lucide-react';

const logs = [
  { key: '1', trace: 'cw-9fa31c', source: '203.0.113.18', category: 'SQLi', action: 'block', time: '21:18:04' },
  { key: '2', trace: 'cw-802c7e', source: '198.51.100.77', category: 'XSS', action: 'block', time: '21:16:41' },
  { key: '3', trace: 'cw-441dda', source: '192.0.2.46', category: 'Bot', action: 'monitor', time: '21:13:20' },
  { key: '4', trace: 'cw-6de781', source: '203.0.113.91', category: 'LFI', action: 'block', time: '21:10:02' },
];

export default function LogsPage() {
  const { t } = useTranslation();

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('logs.title')}</h1>
          <p>{t('logs.subtitle')}</p>
        </div>
      </header>

      <div className="toolbar-row">
        <Input prefix={<Search size={16} />} placeholder={t('common.search')} allowClear />
        <Select placeholder={t('logs.category')} allowClear>
          <Select.Option value="SQLi">SQLi</Select.Option>
          <Select.Option value="XSS">XSS</Select.Option>
          <Select.Option value="RCE">RCE</Select.Option>
          <Select.Option value="Bot">Bot</Select.Option>
        </Select>
        <Select placeholder={t('logs.action')} allowClear>
          <Select.Option value="block">{t('common.block')}</Select.Option>
          <Select.Option value="monitor">{t('common.monitor')}</Select.Option>
        </Select>
      </div>

      <section className="table-panel">
        <Table
          rowKey="key"
          pagination={{ pageSize: 8 }}
          data={logs}
          columns={[
            { title: t('logs.trace'), dataIndex: 'trace', render: (trace: string) => <code>{trace}</code> },
            { title: t('logs.source'), dataIndex: 'source' },
            {
              title: t('logs.category'),
              dataIndex: 'category',
              render: (category: string) => <Tag color="orange">{category}</Tag>,
            },
            {
              title: t('logs.action'),
              dataIndex: 'action',
              render: (action: string) => (
                <Tag color={action === 'block' ? 'red' : 'blue'}>
                  {action === 'block' ? t('common.block') : t('common.monitor')}
                </Tag>
              ),
            },
            { title: t('logs.time'), dataIndex: 'time' },
          ]}
        />
      </section>
    </section>
  );
}
