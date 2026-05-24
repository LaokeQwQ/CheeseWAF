import { Button, Form, Input, Modal, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Server } from 'lucide-react';
import { createSite, fetchSites } from '../../api/client';
import type { Site } from '../../types/api';

const sites = [
  {
    key: 'main',
    name: 'example.com',
    domain: 'example.com, www.example.com',
    upstream: '127.0.0.1:8080',
    mode: 'block',
    enabled: true,
  },
  {
    key: 'api',
    name: 'api.example.com',
    domain: 'api.example.com',
    upstream: '127.0.0.1:9000',
    mode: 'monitor',
    enabled: true,
  },
  {
    key: 'staging',
    name: 'staging',
    domain: 'staging.example.com',
    upstream: '127.0.0.1:7000',
    mode: 'block',
    enabled: false,
  },
];

export default function SitesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const { data } = useQuery({
    queryKey: ['sites'],
    queryFn: fetchSites,
    retry: false,
  });
  const mutation = useMutation({
    mutationFn: createSite,
    onSuccess: () => {
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ['sites'] });
    },
  });
  const rows = data?.length ? data : sites.map((site) => ({
    ...site,
    id: site.key,
    domains: site.domain.split(', '),
    upstreams: [site.upstream],
    listen_port: 80,
    enable_ssl: false,
  } as Site & { key: string; domain: string; upstream: string; mode: string }));

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('sites.title')}</h1>
          <p>{t('sites.subtitle')}</p>
        </div>
        <Button type="primary" icon={<Plus size={16} />} onClick={() => setOpen(true)}>
          {t('sites.name')}
        </Button>
      </header>

      <section className="table-panel">
        <Table
          rowKey="id"
          pagination={false}
          data={rows}
          columns={[
            {
              title: t('sites.name'),
              dataIndex: 'name',
              render: (name: string) => (
                <span className="table-identity">
                  <Server size={17} />
                  {name}
                </span>
              ),
            },
            {
              title: t('sites.domain'),
              render: (_: unknown, record: Site & { domain?: string }) =>
                record.domain ?? record.domains.join(', '),
            },
            {
              title: t('sites.upstream'),
              render: (_: unknown, record: Site & { upstream?: string }) =>
                record.upstream ?? record.upstreams.join(', '),
            },
            {
              title: t('sites.mode'),
              dataIndex: 'mode',
              render: (mode: string) => (
                <Tag color={mode === 'block' ? 'red' : 'blue'}>
                  {mode === 'block' ? t('common.block') : t('common.monitor')}
                </Tag>
              ),
            },
            {
              title: t('sites.status'),
              dataIndex: 'enabled',
              render: (enabled: boolean) => <Switch checked={enabled} size="small" />,
            },
          ]}
        />
      </section>
      <Modal
        title={t('sites.name')}
        visible={open}
        onCancel={() => setOpen(false)}
        footer={null}
      >
        <Form
          layout="vertical"
          onSubmit={(values) => mutation.mutate({
            name: values.name,
            domains: String(values.domains ?? '').split(',').map((item) => item.trim()).filter(Boolean),
            upstreams: String(values.upstreams ?? '').split(',').map((item) => item.trim()).filter(Boolean),
            enabled: true,
            listen_port: 80,
            enable_ssl: false,
          })}
        >
          <Form.Item label={t('sites.name')} field="name" required>
            <Input placeholder="example.com" />
          </Form.Item>
          <Form.Item label={t('sites.domain')} field="domains" required>
            <Input placeholder="example.com,www.example.com" />
          </Form.Item>
          <Form.Item label={t('sites.upstream')} field="upstreams" required>
            <Input placeholder="127.0.0.1:9000" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={mutation.isPending} long>
            {t('common.save')}
          </Button>
        </Form>
      </Modal>
    </section>
  );
}
