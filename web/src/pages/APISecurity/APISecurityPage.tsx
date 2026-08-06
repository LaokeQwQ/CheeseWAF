import { useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Select, Table, Tag } from '../../ui';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ClipboardCheck, Radar, RotateCcw, Trash2 } from 'lucide-react';
import { fetchAPISecEndpoints, validateAPIRequest } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import type { APIEndpoint } from '../../types/api';

export default function APISecurityPage() {
  const { t } = useTranslation();
  const [findings, setFindings] = useState<Array<Record<string, unknown>>>([]);
  const [hasValidated, setHasValidated] = useState(false);
  const [ignoredEndpoints, setIgnoredEndpoints] = useState<Set<string>>(new Set());
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['apisec'],
    queryFn: fetchAPISecEndpoints,
    retry: false,
  });
  const validateMutation = useMutation({
    mutationFn: validateAPIRequest,
    onSuccess: (result) => {
      setFindings(result.findings);
      setHasValidated(true);
    },
    onError: (error) => {
      ArcoMessage.error(error.message || t('common.requestFailed'));
    },
  });
  const allEndpoints = data?.endpoints ?? [];
  const visibleEndpoints = allEndpoints.filter((ep) => !ignoredEndpoints.has(ep.method + ep.path));
  const ignoredList = allEndpoints.filter((ep) => ignoredEndpoints.has(ep.method + ep.path));

  function ignoreEndpoint(key: string) {
    setIgnoredEndpoints((prev) => new Set([...prev, key]));
  }

  function restoreEndpoint(key: string) {
    setIgnoredEndpoints((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
  }

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
          {isError && !data ? (
            <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />
          ) : (
            <>
              <div className="api-endpoints-table">
                <Table
                  rowKey={(r) => r.method + r.path}
                  pagination={false}
                  loading={isLoading}
                  data={visibleEndpoints}
                  columns={[
                    { title: t('apisec.method'), dataIndex: 'method', width: 72, render: (v: string) => <Tag>{v}</Tag> },
                    { title: t('apisec.path'), dataIndex: 'path', render: (v: string) => <code className="table-code api-endpoint-path" title={v}>{v}</code> },
                    { title: t('apisec.count'), dataIndex: 'count', width: 76 },
                    { title: t('apisec.blocked'), dataIndex: 'blocked', width: 72, render: (v: number) => <Tag color={v > 0 ? 'red' : 'green'}>{v}</Tag> },
                    {
                      title: t('apisec.status'),
                      dataIndex: 'status_family',
                      width: 150,
                      render: (_: unknown, rec: APIEndpoint) => (
                        <span className="api-status-group">{Object.entries(rec.status_family).map(([k, v]) => <Tag key={k}>{k}: {v}</Tag>)}</span>
                      ),
                    },
                    {
                      title: '',
                      dataIndex: 'actions',
                      width: 88,
                      render: (_: unknown, rec: APIEndpoint) => (
                        <span className="api-table-actions">
                          <Button
                            size="mini"
                            icon={<Trash2 size={14} />}
                            onClick={() => ignoreEndpoint(rec.method + rec.path)}
                          >
                            {t('common.ignore')}
                          </Button>
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
                    <Button size="small" icon={<Trash2 size={14} />} onClick={() => ignoreEndpoint(endpoint.method + endpoint.path)}>{t('common.ignore')}</Button>
                  </article>
                ))}
              </div>
              {ignoredList.length > 0 && (
                <div className="api-ignored-list" style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: 13, opacity: 0.8 }}>{t('common.ignore')}: {ignoredList.length}</span>
                  {ignoredList.map((endpoint) => {
                    const key = endpoint.method + endpoint.path;
                    return (
                      <Button
                        key={key}
                        size="mini"
                        icon={<RotateCcw size={12} />}
                        title={`${endpoint.method} ${endpoint.path}`}
                        aria-label={`${t('common.reset')}: ${endpoint.method} ${endpoint.path}`}
                        onClick={() => restoreEndpoint(key)}
                      >
                        {endpoint.method} · {t('common.reset')}
                      </Button>
                    );
                  })}
                  {ignoredList.length > 1 && (
                    <Button size="mini" onClick={() => setIgnoredEndpoints(new Set())}>
                      {t('common.reset')}
                    </Button>
                  )}
                </div>
              )}
            </>
          )}
        </section>
        <section className="panel api-validation-panel">
          <div className="panel-heading"><h2><ClipboardCheck size={16} /> {t('apisec.validation')}</h2></div>
          <p className="field-help">{t('apisec.validationHint')}</p>
          <Form
            layout="vertical"
            initialValues={{ method: 'GET', path: '/api/search', query: '', headers: '' }}
            onSubmit={(values) => validateMutation.mutate({
              method: values.method,
              path: values.path,
              query: values.query,
              headers: parseHeaders(values.headers),
              content_length: 0,
            })}
          >
            <Form.Item label={t('apisec.method')} field="method">
              <Select>
                <Select.Option value="GET">GET</Select.Option>
                <Select.Option value="POST">POST</Select.Option>
                <Select.Option value="PUT">PUT</Select.Option>
                <Select.Option value="DELETE">DELETE</Select.Option>
              </Select>
            </Form.Item>
            <Form.Item label={t('apisec.path')} field="path"><Input placeholder="/api/search" /></Form.Item>
            <Form.Item label={t('apisec.query')} field="query"><Input placeholder="q=test&page=1" /></Form.Item>
            <Form.Item label={t('apisec.headers')} field="headers"><Input placeholder="Content-Type: application/json" /></Form.Item>
            <Button type="primary" htmlType="submit" loading={validateMutation.isPending}>{t('apisec.validate')}</Button>
          </Form>
          <div className="event-list api-findings">
            {!hasValidated
              ? null
              : findings.length === 0
                ? <Tag color="green">{t('apisec.clean')}</Tag>
                : findings.map((f, i) => <Tag className="api-finding-tag" key={i} color="orange">{String(f.message)}</Tag>)}
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
