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

      <div className="api-security-grid">
        <section className="panel api-discovery-panel">
          <div className="panel-heading"><h2><Radar size={16} /> {t('apisec.discovery')}</h2></div>
          <div className="table-scroll api-endpoints-table">
            <Table
              rowKey="path"
              pagination={false}
              data={data?.endpoints ?? []}
              columns={[
                { title: t('apisec.method'), dataIndex: 'method', width: 88, render: (value: string) => <Tag>{value}</Tag> },
                { title: t('apisec.path'), dataIndex: 'path', width: 180, render: (value: string) => <code className="table-code" title={value}>{value}</code> },
                { title: t('apisec.count'), dataIndex: 'count', width: 92 },
                { title: t('apisec.blocked'), dataIndex: 'blocked', width: 86, render: (value: number) => <Tag color={value > 0 ? 'red' : 'green'}>{value}</Tag> },
                {
                  title: t('apisec.status'),
                  dataIndex: 'status_family',
                  width: 240,
                  render: (_: unknown, record: APIEndpoint) => (
                    <span className="api-status-group">
                      {Object.entries(record.status_family).map(([key, value]) => <Tag key={key}>{key}: {value}</Tag>)}
                    </span>
                  ),
                },
              ]}
            />
          </div>
        </section>

        <section className="panel api-validation-panel">
          <div className="panel-heading"><h2><ClipboardCheck size={16} /> {t('apisec.validation')}</h2></div>
          <Form
            layout="vertical"
            initialValues={{ method: 'GET', path: '/api/search', query: '' }}
            onSubmit={(values) => validateMutation.mutate({ method: values.method, path: values.path, query: values.query, headers: {}, content_length: 0 })}
          >
            <Form.Item label={t('apisec.method')} field="method">
              <Select>
                <Select.Option value="GET">GET</Select.Option>
                <Select.Option value="POST">POST</Select.Option>
                <Select.Option value="PUT">PUT</Select.Option>
                <Select.Option value="DELETE">DELETE</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('apisec.path')} field="path"><Input /></Form.Item>
            <Form.Item label={t('apisec.query')} field="query"><Input placeholder="q=test" /></Form.Item>
            <Button type="primary" htmlType="submit" loading={validateMutation.isPending}>{t('apisec.validate')}</Button>
          </Form>
          <div className="event-list api-findings">
            {findings.length === 0 ? <Tag color="green">{t('apisec.clean')}</Tag> : findings.map((finding) => (
              <Tag className="api-finding-tag" key={`${finding.schema_id}-${finding.field}`} color="orange">{String(finding.message)}</Tag>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
