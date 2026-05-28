import { useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ClipboardCheck, Radar } from 'lucide-react';
import { fetchAPISecEndpoints, validateAPIRequest } from '../../api/client';
import type { APIEndpoint } from '../../types/api';

export default function APISecurityPage() {
  const { t } = useTranslation();
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const { data } = useQuery({ queryKey: ['apisec'], queryFn: fetchAPISecEndpoints, retry: false });
  const validateMutation = useMutation({
    mutationFn: validateAPIRequest,
    onSuccess: (result) => setFindings(result.findings),
  });

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('apisec.title')}</h1>
          <p>{t('apisec.subtitle')}</p>
        </div>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><Radar size={16} /> {t('apisec.discovery')}</h2></div>
          <Table
            rowKey="path"
            pagination={false}
            data={data?.endpoints ?? []}
            columns={[
              { title: 'Method', dataIndex: 'method', render: (value: string) => <Tag>{value}</Tag> },
              { title: 'Path', dataIndex: 'path', render: (value: string) => <code>{value}</code> },
              { title: t('apisec.count'), dataIndex: 'count' },
              { title: t('apisec.blocked'), dataIndex: 'blocked', render: (value: number) => <Tag color={value > 0 ? 'red' : 'green'}>{value}</Tag> },
              { title: t('apisec.status'), dataIndex: 'status_family', render: (_: unknown, record: APIEndpoint) => Object.entries(record.status_family).map(([key, value]) => <Tag key={key}>{key}:{value}</Tag>) },
            ]}
          />
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><ClipboardCheck size={16} /> {t('apisec.validation')}</h2></div>
          <Form
            layout="vertical"
            initialValues={{ method: 'GET', path: '/api/search', query: '' }}
            onSubmit={(values) => validateMutation.mutate({ method: values.method, path: values.path, query: values.query, headers: {}, content_length: 0 })}
          >
            <Form.Item label="Method" field="method">
              <Select>
                <Select.Option value="GET">GET</Select.Option>
                <Select.Option value="POST">POST</Select.Option>
                <Select.Option value="PUT">PUT</Select.Option>
                <Select.Option value="DELETE">DELETE</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label="Path" field="path"><Input /></Form.Item>
            <Form.Item label="Query" field="query"><Input placeholder="q=test" /></Form.Item>
            <Button type="primary" htmlType="submit" loading={validateMutation.isPending}>{t('apisec.validate')}</Button>
          </Form>
          <div className="event-list" style={{ marginTop: 14 }}>
            {findings.length === 0 ? <Tag color="green">{t('apisec.clean')}</Tag> : findings.map((finding) => (
              <Tag key={`${finding.schema_id}-${finding.field}`} color="orange">{String(finding.message)}</Tag>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
