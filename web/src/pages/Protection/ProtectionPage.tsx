import { Button, Form, Input, InputNumber, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Globe2, ShieldAlert, TimerReset } from 'lucide-react';
import { fetchProtection, updateACLProtection, updateIPProtection, updateRateLimit } from '../../api/client';
import type { ACLRule, ProtectionConfig } from '../../types/api';

const fallback: ProtectionConfig = {
  ip: { whitelist: ['127.0.0.1', '::1'], blacklist: [], tags: {}, geoip: { enabled: false, database: './data/GeoLite2-Country.mmdb', blocked_countries: [], country_cidrs: {} } },
  ratelimit: { enabled: true, default: { requests: 100, window: '60s', burst: 20 } },
  acl: { enabled: true, rules: [{ id: 'deny-debug', name: 'Deny debug', method: '', path_prefix: '/debug', header: '', header_value: '', action: 'block', severity: 'high', enabled: true }] },
};

export default function ProtectionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ['protection'], queryFn: fetchProtection, retry: false });
  const protection = data ?? fallback;
  const ipMutation = useMutation({ mutationFn: updateIPProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const rateMutation = useMutation({ mutationFn: updateRateLimit, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const aclMutation = useMutation({ mutationFn: updateACLProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('protection.title')}</h1>
          <p>{t('protection.subtitle')}</p>
        </div>
      </header>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><Globe2 size={16} /> {t('protection.geoip')}</h2></div>
          <Form
            layout="vertical"
            initialValues={{
              enabled: protection.ip.geoip.enabled,
              blocked: protection.ip.geoip.blocked_countries.join(','),
              whitelist: protection.ip.whitelist.join(','),
              blacklist: protection.ip.blacklist.join(','),
            }}
            onSubmit={(values) => ipMutation.mutate({
              ...protection.ip,
              whitelist: splitList(values.whitelist),
              blacklist: splitList(values.blacklist),
              geoip: { ...protection.ip.geoip, enabled: values.enabled, blocked_countries: splitList(values.blocked).map((item) => item.toUpperCase()) },
            })}
          >
            <Form.Item label={t('protection.geoip')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('protection.blockedCountries')} field="blocked"><Input placeholder="CN,RU" /></Form.Item>
            <Form.Item label={t('ip.whitelist')} field="whitelist"><Input /></Form.Item>
            <Form.Item label={t('ip.blacklist')} field="blacklist"><Input /></Form.Item>
            <Button type="primary" htmlType="submit" loading={ipMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><TimerReset size={16} /> {t('protection.ratelimit')}</h2></div>
          <Form
            layout="vertical"
            initialValues={{ enabled: protection.ratelimit.enabled, requests: protection.ratelimit.default.requests, burst: protection.ratelimit.default.burst }}
            onSubmit={(values) => rateMutation.mutate({ enabled: values.enabled, default: { ...protection.ratelimit.default, requests: values.requests, burst: values.burst } })}
          >
            <Form.Item label={t('common.online')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('protection.requests')} field="requests"><InputNumber min={1} max={100000} /></Form.Item>
            <Form.Item label={t('protection.burst')} field="burst"><InputNumber min={0} max={10000} /></Form.Item>
            <Button type="primary" htmlType="submit" loading={rateMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ShieldAlert size={16} /> {t('protection.acl')}</h2>
          <Button onClick={() => aclMutation.mutate(protection.acl)} loading={aclMutation.isPending}>{t('common.save')}</Button>
        </div>
        <Table
          rowKey="id"
          pagination={false}
          data={protection.acl.rules}
          columns={[
            { title: t('rules.name'), dataIndex: 'name' },
            { title: 'Method', dataIndex: 'method', render: (method: string) => method || '*' },
            { title: 'Path', dataIndex: 'path_prefix', render: (path: string) => <code>{path || '*'}</code> },
            { title: t('logs.action'), dataIndex: 'action', render: (action: string) => <Tag color={action === 'block' ? 'red' : 'blue'}>{action}</Tag> },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (_: boolean, record: ACLRule) => <Switch checked={record.enabled} size="small" /> },
          ]}
        />
      </section>
    </section>
  );
}

function splitList(value: unknown) {
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}
