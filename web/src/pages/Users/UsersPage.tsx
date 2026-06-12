import { Button, Form, Input, Select, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, UserPlus } from 'lucide-react';
import { createUser, fetchAuditEntries, fetchUsers, updateUser } from '../../api/client';
import type { AuditEntry, User } from '../../types/api';

export default function UsersPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: fetchUsers, retry: false });
  const { data: audit } = useQuery({ queryKey: ['audit'], queryFn: fetchAuditEntries, retry: false });
  const createMutation = useMutation({ mutationFn: createUser, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }) });
  const updateMutation = useMutation({ mutationFn: ({ id, user }: { id: string; user: Partial<User> }) => updateUser(id, user), onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }) });

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('users.title')}</h1>
          <p>{t('users.subtitle')}</p>
        </div>
      </header>

      <div className="users-grid">
        <section className="panel">
          <div className="panel-heading"><h2><UserPlus size={16} /> {t('users.create')}</h2></div>
          <Form layout="vertical" onSubmit={(values) => createMutation.mutate({ username: values.username, password: values.password, role: values.role })}>
            <Form.Item label={t('login.username')} field="username"><Input /></Form.Item>
            <Form.Item label={t('login.password')} field="password"><Input.Password /></Form.Item>
            <Form.Item label={t('users.role')} field="role" initialValue="readonly">
              <Select>
                <Select.Option value="admin">admin</Select.Option>
                <Select.Option value="readonly">readonly</Select.Option>
                <Select.Option value="operator">operator</Select.Option>
              </Select>
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={createMutation.isPending}>{t('common.add')}</Button>
          </Form>
        </section>

        <section className="panel users-audit-panel">
          <div className="panel-heading"><h2><ShieldCheck size={16} /> {t('users.audit')}</h2></div>
          <div className="table-scroll users-audit-table">
            <Table
              rowKey="timestamp"
              pagination={false}
              data={audit ?? []}
              columns={[
                { title: t('logs.time'), dataIndex: 'timestamp', render: (value: string) => <span className="nowrap-cell" title={value}>{value}</span> },
                { title: t('users.user'), dataIndex: 'user', render: (value: string) => <span className="nowrap-cell" title={value}>{value || '-'}</span> },
                { title: 'Path', dataIndex: 'path', render: (value: string) => <code className="table-code" title={value}>{value}</code> },
                { title: t('common.status'), dataIndex: 'status', render: (value: number) => <Tag color={value >= 400 ? 'red' : 'green'}>{value}</Tag> },
              ]}
            />
          </div>
          <div className="mobile-card-list users-audit-cards">
            {(audit ?? []).map((entry) => (
              <AuditEntryCard key={`${entry.timestamp}-${entry.path}`} entry={entry} t={t} />
            ))}
          </div>
        </section>
      </div>

      <section className="table-panel users-table-panel">
        <div className="desktop-table-wrap">
          <Table
            rowKey="id"
            pagination={false}
            className="users-table"
            data={users ?? []}
            columns={[
              { title: t('users.user'), dataIndex: 'username' },
              { title: t('users.role'), dataIndex: 'role', render: (value: string) => <Tag>{value}</Tag> },
              { title: '2FA', dataIndex: 'two_fa_enabled', render: (value: boolean) => <Tag color={value ? 'green' : 'gray'}>{value ? 'on' : 'off'}</Tag> },
              {
                title: t('common.save'),
                dataIndex: 'action',
                render: (_: unknown, record: User) => (
                  <Button size="mini" loading={updateMutation.isPending} onClick={() => updateMutation.mutate({ id: record.id, user: { role: record.role } })}>
                    {t('common.save')}
                  </Button>
                ),
              },
            ]}
          />
        </div>
        <div className="mobile-card-list users-mobile-list">
          {(users ?? []).map((user) => (
            <UserCard
              key={user.id}
              user={user}
              saving={updateMutation.isPending}
              onSave={() => updateMutation.mutate({ id: user.id, user: { role: user.role } })}
              t={t}
            />
          ))}
        </div>
      </section>
    </section>
  );
}

function AuditEntryCard({
  entry,
  t,
}: {
  entry: AuditEntry;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <article className="mobile-data-card">
      <header>
        <strong>{entry.user || '-'}</strong>
        <Tag color={entry.status >= 400 ? 'red' : 'green'}>{entry.status}</Tag>
      </header>
      <dl>
        <div>
          <dt>{t('logs.time')}</dt>
          <dd>{entry.timestamp}</dd>
        </div>
        <div>
          <dt>Path</dt>
          <dd><code className="table-code" title={entry.path}>{entry.path}</code></dd>
        </div>
        <div>
          <dt>IP</dt>
          <dd>{entry.remote_ip || '-'}</dd>
        </div>
      </dl>
    </article>
  );
}

function UserCard({
  user,
  saving,
  onSave,
  t,
}: {
  user: User;
  saving: boolean;
  onSave: () => void;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <article className="mobile-data-card">
      <header>
        <strong>{user.username}</strong>
        <Tag>{user.role}</Tag>
      </header>
      <dl>
        <div>
          <dt>2FA</dt>
          <dd><Tag color={user.two_fa_enabled ? 'green' : 'gray'}>{user.two_fa_enabled ? 'on' : 'off'}</Tag></dd>
        </div>
        {user.created_at && (
          <div>
            <dt>{t('logs.time')}</dt>
            <dd>{user.created_at}</dd>
          </div>
        )}
      </dl>
      <div className="mobile-card-actions">
        <Button type="primary" loading={saving} onClick={onSave}>{t('common.save')}</Button>
      </div>
    </article>
  );
}
