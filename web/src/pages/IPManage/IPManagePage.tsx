import { useEffect, useMemo, useState } from 'react';
import { Button, Input, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { FileDown, Search, Shield, Tags } from 'lucide-react';
import { exportThreatIntel, fetchIPRules, updateIPTags } from '../../api/client';
import type { IPReputationEntry } from '../../types/api';

export default function IPManagePage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [draftTags, setDraftTags] = useState<Record<string, string[]>>({});
  const { data } = useQuery({ queryKey: ['ip-rules'], queryFn: fetchIPRules, retry: false });
  const entries = data?.entries ?? [];
  useEffect(() => {
    if (data?.tags) {
      setDraftTags(data.tags);
    }
  }, [data?.tags]);
  const tagMutation = useMutation({
    mutationFn: updateIPTags,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ip-rules'] }),
  });
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) {
      return entries;
    }
    return entries.filter((entry) => (
      entry.ip.toLowerCase().includes(needle)
      || entry.list.includes(needle)
      || (draftTags[entry.ip] ?? entry.tags).some((tag) => tag.includes(needle))
    ));
  }, [draftTags, entries, search]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('ip.title')}</h1>
          <p>{t('ip.subtitle')}</p>
        </div>
        <span className="table-identity">
          <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('csv')}>CSV</Button>
          <Button icon={<FileDown size={16} />} onClick={() => saveIntelFile('stix')}>STIX</Button>
          <Button type="primary" icon={<Tags size={16} />} loading={tagMutation.isPending} onClick={() => tagMutation.mutate(draftTags)}>
            {t('ip.saveTags')}
          </Button>
        </span>
      </header>

      <div className="toolbar-row">
        <Input prefix={<Search size={16} />} value={search} placeholder={t('common.search')} allowClear onChange={setSearch} />
      </div>

      <section className="table-panel">
        <Table
          rowKey="ip"
          pagination={false}
          data={filtered}
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
              title: t('ip.list'),
              dataIndex: 'list',
              render: (list: string) => {
                const label = list === 'whitelist' ? t('ip.whitelist') : list === 'blacklist' ? t('ip.blacklist') : t('common.monitor');
                const color = list === 'whitelist' ? 'green' : list === 'blacklist' ? 'red' : 'blue';
                return <Tag color={color}>{label}</Tag>;
              },
            },
            { title: t('ip.reputation'), dataIndex: 'reputation', render: (value: number) => <Tag color={reputationColor(value)}>{value}</Tag> },
            {
              title: t('ip.tags'),
              dataIndex: 'tags',
              render: (_: string[], record: IPReputationEntry) => (
                <Input
                  value={(draftTags[record.ip] ?? record.tags).join(',')}
                  onChange={(value) => setDraftTags((current) => ({ ...current, [record.ip]: splitList(value) }))}
                />
              ),
            },
            {
              title: t('ip.intel'),
              dataIndex: 'intel',
              render: (_: unknown, record: IPReputationEntry) => (
                <span className="tag-stack">
                  {record.intel.length === 0 ? <Tag>{t('common.monitor')}</Tag> : record.intel.map((item) => (
                    <Tag key={`${record.ip}-${item.id || item.value}`} color={intelColor(item.severity)}>{item.source || item.severity}</Tag>
                  ))}
                </span>
              ),
            },
            {
              title: t('ip.activity'),
              dataIndex: 'stats',
              render: (_: unknown, record: IPReputationEntry) => `${record.stats.blocked}/${record.stats.total}`,
            },
          ]}
        />
      </section>
    </section>
  );
}

async function saveIntelFile(format: 'csv' | 'stix') {
  const blob = await exportThreatIntel(format);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `cheesewaf-threat-intel.${format === 'stix' ? 'json' : 'csv'}`;
  link.click();
  URL.revokeObjectURL(url);
}

function splitList(value: string) {
  return value.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
}

function reputationColor(value: number) {
  if (value >= 80) {
    return 'green';
  }
  if (value >= 50) {
    return 'orange';
  }
  return 'red';
}

function intelColor(severity: string) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'red';
    case 'medium':
      return 'orange';
    default:
      return 'blue';
  }
}
