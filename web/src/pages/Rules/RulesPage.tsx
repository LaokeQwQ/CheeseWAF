import { Button, Form, Input, InputNumber, Modal, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, ShieldCheck } from 'lucide-react';
import { createRule, fetchRules } from '../../api/client';
import type { Rule } from '../../types/api';

const fallbackRules: Rule[] = [
  {
    id: 'rce-shell',
    site_id: 'default',
    name: 'Shell metacharacters',
    description: 'Detect command injection chains.',
    pattern: '(;|&&|\\|\\|)\\s*(cat|id|whoami)',
    location: 'uri',
    action: 'block',
    severity: 'critical',
    enabled: true,
    priority: 120,
  },
  {
    id: 'admin-probe',
    site_id: 'default',
    name: 'Admin probe',
    description: 'Common admin path scans.',
    pattern: '(?i)/(wp-admin|phpmyadmin|\\.git)',
    location: 'uri',
    action: 'block',
    severity: 'medium',
    enabled: true,
    priority: 180,
  },
];

export default function RulesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const { data } = useQuery({ queryKey: ['rules'], queryFn: () => fetchRules(), retry: false });
  const mutation = useMutation({
    mutationFn: createRule,
    onSuccess: () => {
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ['rules'] });
    },
  });
  const rows = data?.length ? data : fallbackRules;

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('rules.title')}</h1>
          <p>{t('rules.subtitle')}</p>
        </div>
        <Button type="primary" icon={<Plus size={16} />} onClick={() => setOpen(true)}>
          {t('rules.create')}
        </Button>
      </header>

      <section className="table-panel">
        <Table
          rowKey="id"
          pagination={{ pageSize: 8 }}
          data={rows}
          columns={[
            {
              title: t('rules.name'),
              dataIndex: 'name',
              render: (name: string) => (
                <span className="table-identity">
                  <ShieldCheck size={17} />
                  {name}
                </span>
              ),
            },
            { title: t('rules.pattern'), dataIndex: 'pattern', render: (pattern: string) => <code>{pattern}</code> },
            { title: t('rules.location'), dataIndex: 'location' },
            {
              title: t('rules.severity'),
              dataIndex: 'severity',
              render: (severity: string) => <Tag color={severity === 'critical' ? 'red' : 'orange'}>{severity}</Tag>,
            },
            { title: t('rules.priority'), dataIndex: 'priority' },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (enabled: boolean) => <Switch checked={enabled} size="small" /> },
          ]}
        />
      </section>

      <Modal title={t('rules.create')} visible={open} onCancel={() => setOpen(false)} footer={null}>
        <Form
          layout="vertical"
          onSubmit={(values) => mutation.mutate({
            site_id: values.site_id ?? 'default',
            name: values.name,
            description: values.description ?? '',
            pattern: values.pattern,
            location: values.location ?? 'uri',
            action: values.action ?? 'block',
            severity: values.severity ?? 'medium',
            priority: values.priority ?? 100,
            enabled: true,
          })}
        >
          <Form.Item label={t('rules.name')} field="name" required><Input /></Form.Item>
          <Form.Item label={t('rules.pattern')} field="pattern" required><Input /></Form.Item>
          <Form.Item label={t('rules.location')} field="location">
            <Select defaultValue="uri">
              <Select.Option value="uri">URI</Select.Option>
              <Select.Option value="header">Header</Select.Option>
              <Select.Option value="body">Body</Select.Option>
              <Select.Option value="cookie">Cookie</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label={t('rules.severity')} field="severity">
            <Select defaultValue="medium">
              <Select.Option value="low">Low</Select.Option>
              <Select.Option value="medium">Medium</Select.Option>
              <Select.Option value="high">High</Select.Option>
              <Select.Option value="critical">Critical</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item label={t('rules.priority')} field="priority"><InputNumber defaultValue={100} min={1} max={999} /></Form.Item>
          <Button type="primary" htmlType="submit" loading={mutation.isPending} long>{t('common.save')}</Button>
        </Form>
      </Modal>
    </section>
  );
}
