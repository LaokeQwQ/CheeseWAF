import { useState } from 'react';
import { Button, Form, Input, Select, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ClipboardCheck, Radar, Trash2 } from 'lucide-react';
import { fetchAPISecEndpoints, validateAPIRequest } from '../../api/client';
import type { APIEndpoint } from '../../types/api';

export default function APISecurityPage() {
  const { t } = useTranslation();
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const [ignoredEndpoints, setIgnoredEndpoints] = useState<Set<string>>(new Set());
  const { data } = useQuery({ queryKey: ['apisec'], queryFn: fetchAPISecEndpoints, retry: false });
  const validateMutation = useMutation({ mutationFn: validateAPIRequest, onSuccess: (result) => setFindings(result.findings) });
  const visibleEndpoints = (data?.endpoints ?? []).filter((ep) => !ignoredEndpoints.has(ep.method + ep.path));

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
          <div className="api-endpoints-table">
            <Table rowKey={(r) => r.method + r.path} pagination={false} data={visibleEndpoints}
              columns={[
                { title: t('apisec.method'), dataIndex: 'method', width: 72, render: (v: string) => <Tag>{v}</Tag> },
                { title: t('apisec.path'), dataIndex: 'path', render: (v: string) => <code className="table-code api-endpoint-path" title={v}>{v}</code> },
                { title: t('apisec.count'), dataIndex: 'count', width: 76 },
                { title: t('apisec.blocked'), dataIndex: 'blocked', width: 72, render: (v: number) => <Tag color={v > 0 ? 'red' : 'green'}>{v}</Tag> },
                { title: t('apisec.status'), dataIndex: 'status_family', width: 150,
                  render: (_: unknown, rec: APIEndpoint) => (
                    <span className="api-status-group">{Object.entries(rec.status_family).map(([k, v]) => <Tag key={k}>{k}: {v}</Tag>)}</span>
                  ),
                },
                { title: '', dataIndex: 'actions', width: 88,
                  render: (_: unknown, rec: APIEndpoint) => (
                    <span className="api-table-actions">
                      <Button size="mini" icon={<Trash2 size={14} />} onClick={() => setIgnoredEndpoints((prev) => new Set([...prev, rec.method + rec.path]))}>{t('common.ignore')}</Button>
                    </span>
                  ),
                },
              ]}
              tableLayoutFixed
            />
          </div>
          <div className="api-endpoints-mobile">
            {visibleEndpoints.map((endpoint) => (
              <article className="api-endpoint-card" key={endpoint.method + endpoint.path}>
                <div className="api-endpoint-card-heading">
                  <Tag>{endpoint.method}</Tag>
                  <code title={endpoint.path}>{endpoint.path}</code>
                </div>
                <dl>
                  <div><dt>{t('apisec.count')}</dt><dd>{endpoint.count}</dd></div>
                  <div><dt>{t('apisec.blocked')}</dt><dd><Tag color={endpoint.blocked > 0 ? 'red' : 'green'}>{endpoint.blocked}</Tag></dd></div>
                  <div><dt>{t('apisec.status')}</dt><dd className="api-status-group">{Object.entries(endpoint.status_family).map(([key, value]) => <Tag key={key}>{key}: {value}</Tag>)}</dd></div>
                </dl>
                <Button size="small" icon={<Trash2 size={14} />} onClick={() => setIgnoredEndpoints((prev) => new Set([...prev, endpoint.method + endpoint.path]))}>{t('common.ignore')}</Button>
              </article>
            ))}
          </div>
        </section>
        <section className="panel api-validation-panel">
          <div className="panel-heading"><h2><ClipboardCheck size={16} /> {t('apisec.validation')}</h2></div>
          <p className="field-help">{t('apisec.validationHint')}</p>
          <Form layout="vertical" initialValues={{ method: 'GET', path: '/api/search', query: '', headers: '' }}
            onSubmit={(values) => validateMutation.mutate({ method: values.method, path: values.path, query: values.query, headers: parseHeaders(values.headers), content_length: 0 })}
          >
            <Form.Item label={t('apisec.method')} field="method">
              <Select><Select.Option value="GET">GET</Select.Option><Select.Option value="POST">POST</Select.Option><Select.Option value="PUT">PUT</Select.Option><Select.Option value="DELETE">DELETE</Select.Option></Select>
            </Form.Item>
            <Form.Item label={t('apisec.path')} field="path"><Input placeholder="/api/search" /></Form.Item>
            <Form.Item label={t('apisec.query')} field="query"><Input placeholder="q=test&page=1" /></Form.Item>
            <Form.Item label={t('apisec.headers')} field="headers"><Input placeholder="Content-Type: application/json" /></Form.Item>
            <Button type="primary" htmlType="submit" loading={validateMutation.isPending}>{t('apisec.validate')}</Button>
          </Form>
          <div className="event-list api-findings">
            {findings.length === 0 ? <Tag color="green">{t('apisec.clean')}</Tag> : findings.map((f, i) => <Tag className="api-finding-tag" key={i} color="orange">{String(f.message)}</Tag>)}
          </div>
        </section>
      </div>
    </section>
  );
}

function parseHeaders(value: string) {
  const headers: Record<string, string> = {};
  for (const line of String(value ?? '').split('\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) headers[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
  }
  return headers;
}
