import { useEffect, useState } from 'react';
import { Button, Form, Input, InputNumber, Select, Switch, Table } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Gauge, ListPlus, PackageCheck, Plus, Trash2 } from 'lucide-react';
import { fetchEdgePolicy, updateEdgePolicy } from '../../api/client';
import type { EdgeConfig } from '../../types/api';

type HeaderRule = EdgeConfig['headers']['rules'][number];

const fallback: EdgeConfig = {
  headers: {
    enabled: false,
    rules: [],
  },
  cache: { enabled: false, mode: 'off', ttl: '', status_codes: [], path_prefixes: [], max_body_bytes: 0 },
  compression: { enabled: false, algorithms: [], level: 0, min_bytes: 0, content_types: [] },
};

export default function EdgePage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['edge'], queryFn: fetchEdgePolicy, retry: false });
  const [draft, setDraft] = useState<EdgeConfig>(fallback);
  useEffect(() => {
    if (data) {
      setDraft(data);
    }
  }, [data]);
  const edge = draft;
  const mutation = useMutation({
    mutationFn: updateEdgePolicy,
    onSuccess: (saved) => {
      setDraft(saved);
      queryClient.invalidateQueries({ queryKey: ['edge'] });
    },
  });
  const updateHeader = (index: number, patch: Partial<HeaderRule>) => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: current.headers.rules.map((rule, ruleIndex) => (ruleIndex === index ? { ...rule, ...patch } : rule)),
      },
    }));
  };
  const addHeader = () => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: [
          ...current.headers.rules,
          {
            id: `header-${Date.now()}`,
            name: '',
            operation: 'set',
            header: '',
            value: '',
            path_prefix: '',
            enabled: true,
          },
        ],
      },
    }));
  };
  const removeHeader = (id: string) => {
    setDraft((current) => ({
      ...current,
      headers: {
        ...current.headers,
        rules: current.headers.rules.filter((rule) => rule.id !== id),
      },
    }));
  };

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('edge.title')}</h1>
          <p>{t('edge.subtitle')}</p>
        </div>
        <Button type="primary" onClick={() => mutation.mutate(edge)} loading={mutation.isPending}>
          {t('common.save')}
        </Button>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><PackageCheck size={16} /> {t('edge.cache')}</h2></div>
          <Form
            key={`cache-${edge.cache.enabled}-${edge.cache.mode}-${edge.cache.ttl}`}
            layout="vertical"
            initialValues={{
              enabled: edge.cache.enabled,
              mode: edge.cache.mode,
              ttl: String(edge.cache.ttl),
              paths: edge.cache.path_prefixes.join(','),
              maxBody: edge.cache.max_body_bytes,
            }}
            onSubmit={(values) => {
              const next = {
              ...edge,
              cache: {
                ...edge.cache,
                enabled: values.enabled,
                mode: values.mode,
                ttl: values.ttl,
                path_prefixes: split(values.paths),
                max_body_bytes: values.maxBody,
              },
              };
              setDraft(next);
              mutation.mutate(next);
            }}
          >
            <Form.Item label={t('edge.enabled')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('edge.mode')} field="mode">
              <Select>
                <Select.Option value="public">public</Select.Option>
                <Select.Option value="private">private</Select.Option>
                <Select.Option value="off">off</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="TTL" field="ttl"><Input placeholder="5m" /></Form.Item>
            <Form.Item label={t('edge.paths')} field="paths"><Input /></Form.Item>
            <Form.Item label={t('edge.maxBody')} field="maxBody"><InputNumber min={1024} step={1024} /></Form.Item>
            <Button htmlType="submit">{t('common.save')}</Button>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Gauge size={16} /> {t('edge.compression')}</h2></div>
          <Form
            key={`compression-${edge.compression.enabled}-${edge.compression.level}-${edge.compression.min_bytes}`}
            layout="vertical"
            initialValues={{
              enabled: edge.compression.enabled,
              algorithms: edge.compression.algorithms.join(','),
              level: edge.compression.level,
              minBytes: edge.compression.min_bytes,
              types: edge.compression.content_types.join(','),
            }}
            onSubmit={(values) => {
              const next = {
              ...edge,
              compression: {
                ...edge.compression,
                enabled: values.enabled,
                algorithms: split(values.algorithms),
                level: values.level,
                min_bytes: values.minBytes,
                content_types: split(values.types),
              },
              };
              setDraft(next);
              mutation.mutate(next);
            }}
          >
            <Form.Item label={t('edge.enabled')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('edge.algorithms')} field="algorithms"><Input /></Form.Item>
            <Form.Item label={t('edge.level')} field="level"><InputNumber min={-2} max={9} /></Form.Item>
            <Form.Item label={t('edge.minBytes')} field="minBytes"><InputNumber min={0} step={512} /></Form.Item>
            <Form.Item label={t('edge.types')} field="types"><Input /></Form.Item>
            <Button htmlType="submit">{t('common.save')}</Button>
          </Form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ListPlus size={16} /> {t('edge.headers')}</h2>
          <div className="table-identity">
            <Button icon={<Plus size={14} />} onClick={addHeader}>{t('common.add')}</Button>
            <Button type="primary" onClick={() => mutation.mutate(edge)} loading={mutation.isPending}>{t('common.save')}</Button>
          </div>
        </div>
        <Table
          rowKey="id"
          pagination={false}
          data={edge.headers.rules}
          columns={[
            { title: t('rules.name'), dataIndex: 'name', render: (_: string, record: HeaderRule, index: number) => <Input value={record.name} onChange={(value) => updateHeader(index, { name: value })} /> },
            {
              title: t('edge.operation'),
              dataIndex: 'operation',
              render: (_: string, record: HeaderRule, index: number) => (
                <Select value={record.operation} onChange={(value) => updateHeader(index, { operation: value as HeaderRule['operation'] })}>
                  <Select.Option value="set">set</Select.Option>
                  <Select.Option value="add">add</Select.Option>
                  <Select.Option value="delete">delete</Select.Option>
                </Select>
              ),
            },
            { title: t('edge.header'), dataIndex: 'header', render: (_: string, record: HeaderRule, index: number) => <Input value={record.header} onChange={(value) => updateHeader(index, { header: value })} /> },
            { title: t('edge.value'), dataIndex: 'value', render: (_: string, record: HeaderRule, index: number) => <Input value={record.value} disabled={record.operation === 'delete'} onChange={(value) => updateHeader(index, { value })} /> },
            { title: t('edge.paths'), dataIndex: 'path_prefix', render: (_: string, record: HeaderRule, index: number) => <Input value={record.path_prefix} placeholder="/api/" onChange={(value) => updateHeader(index, { path_prefix: value })} /> },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (_: boolean, record: HeaderRule, index: number) => <Switch checked={record.enabled} size="small" onChange={(enabled) => updateHeader(index, { enabled })} /> },
            { title: '', dataIndex: 'action', render: (_: unknown, record: HeaderRule) => <Button status="danger" icon={<Trash2 size={14} />} onClick={() => removeHeader(record.id)} /> },
          ]}
        />
      </section>
    </section>
  );
}

function split(value: unknown) {
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}
