import { Input, Select, Table, Tag } from '@arco-design/web-react';
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Search } from 'lucide-react';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';
import { displayAction, displayCategory, displayCountry } from '../../utils/display';

export default function LogsPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>();
  const [action, setAction] = useState<string>();
  const { data, isLoading } = useQuery({
    queryKey: ['logs', category, action],
    queryFn: () => fetchLogs({ limit: 250, category, action }),
    refetchInterval: 8_000,
    retry: false,
  });
  const logs = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const entries = data?.items ?? [];
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) => [
      entry.trace_id,
      entry.client_ip,
      entry.uri,
      entry.category,
      entry.action,
      entry.message,
      entry.country,
    ].some((value) => value?.toLowerCase().includes(needle)));
  }, [data?.items, search]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('logs.title')}</h1>
          <p>{t('logs.subtitle')}</p>
        </div>
      </header>

      <div className="toolbar-row">
        <Input value={search} onChange={setSearch} prefix={<Search size={16} />} placeholder={t('common.search')} allowClear />
        <Select value={category} placeholder={t('logs.category')} allowClear onChange={(value) => setCategory(value as string | undefined)}>
          <Select.Option value="sqli">SQLi</Select.Option>
          <Select.Option value="xss">XSS</Select.Option>
          <Select.Option value="rce">RCE</Select.Option>
          <Select.Option value="lfi">LFI</Select.Option>
          <Select.Option value="ssrf">SSRF</Select.Option>
          <Select.Option value="bot">Bot</Select.Option>
        </Select>
        <Select value={action} placeholder={t('logs.action')} allowClear onChange={(value) => setAction(value as string | undefined)}>
          <Select.Option value="block">{t('common.block')}</Select.Option>
          <Select.Option value="challenge">Challenge</Select.Option>
          <Select.Option value="log">Log</Select.Option>
          <Select.Option value="pass">Pass</Select.Option>
          <Select.Option value="monitor">{t('common.monitor')}</Select.Option>
        </Select>
      </div>

      <section className="table-panel">
        <Table
          rowKey="key"
          pagination={{ pageSize: 8 }}
          loading={isLoading}
          data={logs.map((entry) => ({ ...entry, key: entry.id || entry.trace_id }))}
          columns={[
            { title: t('logs.trace'), dataIndex: 'trace_id', render: (trace: string, record: LogEntry) => <code className="table-code" title={trace || record.id}>{trace || record.id}</code> },
            { title: t('logs.source'), dataIndex: 'client_ip' },
            {
              title: t('logs.category'),
              dataIndex: 'category',
              render: (value: string) => (
                <span className="status-group">
                  <Tag color={value ? 'orange' : 'green'}>{displayCategory(value || 'pass', t)}</Tag>
                </span>
              ),
            },
            {
              title: t('logs.action'),
              dataIndex: 'action',
              render: (action: string) => (
                <span className="status-group">
                  <Tag color={action === 'block' ? 'red' : 'blue'}>
                    {displayAction(action, t)}
                  </Tag>
                </span>
              ),
            },
            { title: 'URI', dataIndex: 'uri', render: (uri: string) => <code className="table-code" title={uri || '-'}>{uri || '-'}</code> },
            { title: t('attackMap.country'), dataIndex: 'country', render: (value: string) => displayCountry(value, t) },
            { title: t('logs.time'), dataIndex: 'timestamp', render: formatTime },
          ]}
        />
      </section>
    </section>
  );
}

function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  return date.toLocaleString();
}
