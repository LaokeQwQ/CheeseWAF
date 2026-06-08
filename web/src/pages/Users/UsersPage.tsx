import { Button, Form, Input, Select, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, UserPlus } from 'lucide-react';
import { createUser, fetchAuditEntries, fetchUsers, updateUser } from '../../api/client';
import type { User } from '../../types/api';

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

      <div className="settings-grid">
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

        <section className="panel">
          <div className="panel-heading"><h2><ShieldCheck size={16} /> {t('users.audit')}</h2></div>
          <Table
            rowKey="timestamp"
            pagination={false}
            data={audit ?? []}
            columns={[
              { title: t('logs.time'), dataIndex: 'timestamp' },
              { title: t('users.user'), dataIndex: 'user' },
              { title: 'Path', dataIndex: 'path', render: (value: string) => <code>{value}</code> },
              { title: t('common.status'), dataIndex: 'status', render: (value: number) => <Tag color={value >= 400 ? 'red' : 'green'}>{value}</Tag> },
            ]}
          />
        </section>
      </div>

      <section className="table-panel">
        <Table
          rowKey="id"
          pagination={false}
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
      </section>
    </section>
  );
}
