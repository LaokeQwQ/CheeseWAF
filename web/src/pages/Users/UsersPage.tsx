import { useMemo, useState } from 'react';
import { Button, Form, Input, Message as ArcoMessage, Modal, Pagination, Select, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import QRCode from 'qrcode';
import { Search, ShieldCheck, UserCog, UserPlus, UsersRound } from 'lucide-react';
import { createUser, disableUser2FA, enableUser2FA, fetchAuditEntries, fetchUsers, recoverUser2FA, setupUser2FA, updateUser } from '../../api/client';
import type { AuditEntry, TOTPSetup, User } from '../../types/api';

type UserDraft = {
  username: string;
  role: string;
  password: string;
};

type TwoFAState = {
  user?: User;
  setup?: TOTPSetup;
  qr?: string;
  code: string;
};

type TwoFADisableDraft = {
  password: string;
  code: string;
};

type TwoFARecoveryDraft = {
  password: string;
  confirmUsername: string;
};

type KeyedAuditEntry = AuditEntry & { auditKey: string };

const roleOptions = ['admin', 'operator', 'readonly'];
const userPageSize = 8;
const auditPageSize = 10;

export function pageItems<T>(items: readonly T[], page: number, pageSize: number) {
  const safePage = Math.max(1, page);
  return items.slice((safePage - 1) * pageSize, safePage * pageSize);
}

export function withStableAuditKeys(entries: readonly AuditEntry[]): KeyedAuditEntry[] {
  const occurrences = new Map<string, number>();
  return entries.map((entry) => {
    const fingerprint = JSON.stringify([
      entry.timestamp,
      entry.user,
      entry.role,
      entry.method,
      entry.path,
      entry.status,
      entry.remote_ip,
      entry.latency_ms,
    ]);
    const occurrence = (occurrences.get(fingerprint) ?? 0) + 1;
    occurrences.set(fingerprint, occurrence);
    return { ...entry, auditKey: `${fingerprint}#${occurrence}` };
  });
}

export default function UsersPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [createForm] = Form.useForm();
  const [disableForm] = Form.useForm();
  const [recoveryForm] = Form.useForm();
  const account = currentAccount();
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [disableUser, setDisableUser] = useState<User | null>(null);
  const [recoveryUser, setRecoveryUser] = useState<User | null>(null);
  const [twoFA, setTwoFA] = useState<TwoFAState>({ code: '' });
  const [mobileUserPage, setMobileUserPage] = useState(1);
  const [mobileAuditPage, setMobileAuditPage] = useState(1);
  const { data: users, isLoading: usersLoading } = useQuery({ queryKey: ['users'], queryFn: fetchUsers, retry: false });
  const { data: audit, isLoading: auditLoading } = useQuery({ queryKey: ['audit'], queryFn: fetchAuditEntries, retry: false });
  const displayedAudit = useMemo(() => withStableAuditKeys(audit ?? []).reverse(), [audit]);
  const mobileAuditItems = useMemo(() => pageItems(displayedAudit, mobileAuditPage, auditPageSize), [displayedAudit, mobileAuditPage]);

  const filteredUsers = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (users ?? []).filter((user) => {
      const matchesRole = roleFilter === 'all' || user.role === roleFilter;
      const matchesText = !needle || user.username.toLowerCase().includes(needle) || user.role.toLowerCase().includes(needle);
      return matchesRole && matchesText;
    });
  }, [roleFilter, search, users]);
  const mobileUserItems = useMemo(() => pageItems(filteredUsers, mobileUserPage, userPageSize), [filteredUsers, mobileUserPage]);

  const summary = useMemo(() => {
    const all = users ?? [];
    return {
      total: all.length,
      admins: all.filter((user) => user.role === 'admin').length,
      twoFA: all.filter((user) => user.two_fa_enabled).length,
      recentAudit: audit?.length ?? 0,
    };
  }, [audit?.length, users]);

  const createMutation = useMutation({
    mutationFn: createUser,
    onSuccess: async () => {
      ArcoMessage.success(t('users.created'));
      setCreateOpen(false);
      createForm.resetFields();
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, user }: { id: string; user: Partial<User> & { password?: string } }) => updateUser(id, user),
    onSuccess: async () => {
      ArcoMessage.success(t('users.updated'));
      setEditUser(null);
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const twoFASetupMutation = useMutation({
    mutationFn: ({ userId }: { userId: string }) => setupUser2FA(userId),
    onSuccess: async (setup, variables) => {
      const qr = await QRCode.toDataURL(setup.otpauth_url, { margin: 1, width: 180 });
      setTwoFA((current) => current.user?.id === variables.userId ? { ...current, setup, qr, code: '' } : current);
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const twoFAEnableMutation = useMutation({
    mutationFn: () => enableUser2FA(twoFA.user?.id ?? '', twoFA.setup?.secret ?? '', twoFA.code),
    onSuccess: async () => {
      ArcoMessage.success(t('users.twoFAEnabled'));
      setTwoFA({ code: '' });
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const twoFADisableMutation = useMutation({
    mutationFn: ({ user, values }: { user: User; values: TwoFADisableDraft }) => disableUser2FA(user.id, values.password, values.code),
    onSuccess: async () => {
      ArcoMessage.success(t('users.twoFADisabled'));
      setDisableUser(null);
      disableForm.resetFields();
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  const twoFARecoveryMutation = useMutation({
    mutationFn: ({ user, values }: { user: User; values: TwoFARecoveryDraft }) => recoverUser2FA(user.id, values.password, values.confirmUsername),
    onSuccess: async () => {
      ArcoMessage.success(t('users.twoFARecovered'));
      setRecoveryUser(null);
      recoveryForm.resetFields();
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => ArcoMessage.error(error.message),
  });

  function open2FASetup(user: User) {
    setTwoFA({ user, code: '' });
    twoFASetupMutation.mutate({ userId: user.id });
  }

  function openDisable2FA(user: User) {
    disableForm.resetFields();
    setDisableUser(user);
  }

  function openRecovery2FA(user: User) {
    recoveryForm.resetFields();
    setRecoveryUser(user);
  }

  return (
    <section className="page-surface users-page">
      <header className="page-header">
        <div>
          <h1>{t('users.title')}</h1>
          <p>{t('users.subtitle')}</p>
        </div>
        <Button type="primary" icon={<UserPlus size={15} />} onClick={() => setCreateOpen(true)}>
          {t('users.create')}
        </Button>
      </header>

      <section className="users-summary-grid" aria-label={t('users.summary')}>
        <Metric label={t('users.totalUsers')} value={summary.total} />
        <Metric label={t('users.admins')} value={summary.admins} />
        <Metric label={t('users.twoFAEnabledCount')} value={summary.twoFA} />
        <Metric label={t('users.auditEvents')} value={summary.recentAudit} />
      </section>

      <section className="table-panel users-directory-panel">
        <div className="panel-heading users-directory-heading">
          <h2><UsersRound size={16} /> {t('users.directory')}</h2>
          <div className="users-toolbar">
            <Input allowClear prefix={<Search size={15} />} value={search} placeholder={t('users.searchPlaceholder')} onChange={setSearch} />
            <Select value={roleFilter} onChange={setRoleFilter}>
              <Select.Option value="all">{t('users.allRoles')}</Select.Option>
              {roleOptions.map((role) => <Select.Option key={role} value={role}>{roleLabel(role, t)}</Select.Option>)}
            </Select>
          </div>
        </div>
        <div className="desktop-table-wrap users-table-wrap">
          <Table
            rowKey="id"
            loading={usersLoading}
            pagination={{
              pageSize: 8,
              sizeCanChange: true,
              sizeOptions: [8, 10, 20, 50],
              showTotal: true,
              bufferSize: 1,
              hideOnSinglePage: false,
            }}
            className="users-table"
            data={filteredUsers}
            columns={[
              {
                title: t('users.user'),
                dataIndex: 'username',
                render: (_: string, record: User) => (
                  <div className="user-identity-cell">
                    <span><UserCog size={15} /></span>
                    <div>
                      <strong>{record.username}</strong>
                      <em>{record.id}</em>
                    </div>
                  </div>
                ),
              },
              { title: t('users.role'), dataIndex: 'role', width: 140, render: (value: string) => <Tag>{roleLabel(value, t)}</Tag> },
              {
                title: t('users.twoFA'),
                dataIndex: 'two_fa_enabled',
                width: 150,
                render: (value: boolean) => <Tag color={value ? 'green' : 'gray'}>{value ? t('users.twoFAOn') : t('users.twoFAOff')}</Tag>,
              },
              { title: t('users.createdAt'), dataIndex: 'created_at', width: 190, render: (value: string) => <span className="nowrap-cell">{formatDate(value)}</span> },
              {
                title: t('common.actions'),
                dataIndex: 'action',
                width: 260,
                render: (_: unknown, record: User) => (
                  <div className="table-action-group">
                    <Button size="small" onClick={() => setEditUser(record)}>{t('common.edit')}</Button>
                    {record.two_fa_enabled && record.id === account.subject ? (
                      <Button size="small" status="warning" loading={twoFADisableMutation.isPending} onClick={() => openDisable2FA(record)}>
                        {t('users.disable2FA')}
                      </Button>
                    ) : record.two_fa_enabled && account.role === 'admin' && record.id !== account.subject ? (
                      <Button size="small" status="warning" loading={twoFARecoveryMutation.isPending} onClick={() => openRecovery2FA(record)}>
                        {t('users.recover2FA')}
                      </Button>
                    ) : !record.two_fa_enabled && record.id === account.subject ? (
                      <Button size="small" icon={<ShieldCheck size={14} />} loading={twoFASetupMutation.isPending && twoFA.user?.id === record.id} onClick={() => open2FASetup(record)}>
                        {t('users.setup2FA')}
                      </Button>
                    ) : null}
                  </div>
                ),
              },
            ]}
          />
        </div>
        <div className="mobile-card-list users-mobile-list">
          {usersLoading ? <div className={'empty-state'}>{t('common.loading')}</div> : filteredUsers.length === 0 ? <div className={'empty-state'}>{t('common.noData')}</div> : mobileUserItems.map((user) => (
            <UserCard
              key={user.id}
              user={user}
              t={t}
              onEdit={() => setEditUser(user)}
              onSetup2FA={() => open2FASetup(user)}
              canSetup2FA={!user.two_fa_enabled && user.id === account.subject}
              canDisable2FA={user.two_fa_enabled && user.id === account.subject}
              canRecover2FA={user.two_fa_enabled && account.role === 'admin' && user.id !== account.subject}
              onDisable2FA={() => openDisable2FA(user)}
              onRecover2FA={() => openRecovery2FA(user)}
            />
          ))}
          {filteredUsers.length > userPageSize && <Pagination simple current={mobileUserPage} pageSize={userPageSize} total={filteredUsers.length} onChange={setMobileUserPage} />}
        </div>
      </section>

      <section className="table-panel users-audit-panel">
        <div className="panel-heading">
          <h2><ShieldCheck size={16} /> {t('users.audit')}</h2>
          <span>{t('users.auditHint')}</span>
        </div>
        <div className="table-scroll users-audit-table">
          <Table
            rowKey={(entry) => entry.auditKey}
            loading={auditLoading}
            pagination={{
              pageSize: 10,
              sizeCanChange: true,
              sizeOptions: [10, 20, 50],
              showTotal: true,
              bufferSize: 1,
              hideOnSinglePage: false,
            }}
            data={displayedAudit}
            columns={[
              { title: t('logs.time'), dataIndex: 'timestamp', width: 190, render: (value: string) => <span className="nowrap-cell" title={value}>{formatDate(value)}</span> },
              { title: t('users.user'), dataIndex: 'user', width: 140, render: (value: string) => <span className="nowrap-cell" title={value}>{value || '-'}</span> },
              { title: t('users.method'), dataIndex: 'method', width: 96, render: (value: string) => <Tag>{value}</Tag> },
              { title: t('logs.path'), dataIndex: 'path', render: (value: string) => <code className="table-code" title={value}>{value}</code> },
              { title: t('common.status'), dataIndex: 'status', width: 110, render: (value: number) => <Tag color={value >= 400 ? 'red' : 'green'}>{value}</Tag> },
              { title: 'IP', dataIndex: 'remote_ip', width: 160, render: (value: string) => <span className="nowrap-cell">{stripIpPort(value) || '-'}</span> },
            ]}
          />
        </div>
        <div className="mobile-card-list users-audit-cards">
          {auditLoading ? <div className={'empty-state'}>{t('common.loading')}</div> : displayedAudit.length === 0 ? <div className={'empty-state'}>{t('common.noData')}</div> : mobileAuditItems.map((entry) => (
            <AuditEntryCard key={entry.auditKey} entry={entry} t={t} />
          ))}
          {displayedAudit.length > auditPageSize && <Pagination simple current={mobileAuditPage} pageSize={auditPageSize} total={displayedAudit.length} onChange={setMobileAuditPage} />}
        </div>
      </section>

      <Modal
        title={t('users.create')}
        visible={createOpen}
        onCancel={() => setCreateOpen(false)}
        footer={null}
        className="users-modal"
      >
        <Form
          form={createForm}
          layout="vertical"
          initialValues={{ role: 'operator' }}
          onSubmit={(values: UserDraft) => createMutation.mutate({ username: values.username, password: values.password, role: values.role })}
        >
          <UserFields t={t} includePassword />
          <Button type="primary" htmlType="submit" loading={createMutation.isPending} long>{t('users.create')}</Button>
        </Form>
      </Modal>

      <Modal
        title={editUser ? t('users.editUser', { username: editUser.username }) : t('users.editUserTitle')}
        visible={Boolean(editUser)}
        onCancel={() => setEditUser(null)}
        footer={null}
        className="users-modal"
      >
        {editUser && (
          <Form
            layout="vertical"
            key={editUser.id}
            initialValues={{ username: editUser.username, role: editUser.role, password: '' }}
            onSubmit={(values: UserDraft) => updateMutation.mutate({
              id: editUser.id,
              user: {
                username: values.username,
                role: values.role,
                ...(values.password ? { password: values.password } : {}),
              },
            })}
          >
            <UserFields t={t} includePassword passwordOptional />
            <Button type="primary" htmlType="submit" loading={updateMutation.isPending} long>{t('common.save')}</Button>
          </Form>
        )}
      </Modal>

      <Modal
        title={twoFA.user ? t('users.setup2FAFor', { username: twoFA.user.username }) : t('users.setup2FA')}
        visible={Boolean(twoFA.user)}
        onCancel={() => setTwoFA({ code: '' })}
        footer={null}
        className="users-modal users-twofa-modal"
      >
        {twoFASetupMutation.isPending && <div className="empty-state">{t('common.loading')}</div>}
        {twoFA.user && !twoFASetupMutation.isPending && !twoFA.setup && (
          <div className="empty-state">{t('users.twoFASetupUnavailable')}</div>
        )}
        {twoFA.setup && (
          <div className="twofa-setup users-twofa-setup">
            <div className="users-twofa-status">
              <ShieldCheck size={18} />
              <div>
                <strong>{t('users.verify2FA')}</strong>
                <span>{t('users.twoFAGuide')}</span>
              </div>
            </div>
            <div className="users-twofa-body">
              {twoFA.qr && <img src={twoFA.qr} alt={t('users.twoFAQRCode')} />}
              <div className="users-twofa-steps">
                <div>
                  <span>{t('users.twoFASecret')}</span>
                  <code>{twoFA.setup.secret}</code>
                </div>
                <Input
                  value={twoFA.code}
                  placeholder={t('users.twoFACodePlaceholder')}
                  maxLength={6}
                  onChange={(code) => setTwoFA((current) => ({ ...current, code: code.replace(/\D/g, '').slice(0, 6) }))}
                />
                <Button type="primary" disabled={twoFA.code.length !== 6} loading={twoFAEnableMutation.isPending} onClick={() => twoFAEnableMutation.mutate()} long>
                  {t('users.enable2FA')}
                </Button>
              </div>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        title={disableUser ? t('users.disable2FAFor', { username: disableUser.username }) : t('users.disable2FA')}
        visible={Boolean(disableUser)}
        onCancel={() => setDisableUser(null)}
        footer={null}
        className="users-modal"
      >
        {disableUser && (
          <Form
            form={disableForm}
            layout="vertical"
            onSubmit={(values: TwoFADisableDraft) => twoFADisableMutation.mutate({ user: disableUser, values })}
          >
            <Form.Item label={t('users.currentPassword')} field="password" rules={[{ required: true, message: t('users.currentPasswordRequired') }]}>
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Form.Item label={t('users.twoFACode')} field="code" rules={[{ required: true, message: t('users.twoFACodeRequired') }]}>
              <Input maxLength={6} inputMode="numeric" />
            </Form.Item>
            <Button type="primary" status="danger" htmlType="submit" loading={twoFADisableMutation.isPending} long>{t('users.disable2FA')}</Button>
          </Form>
        )}
      </Modal>

      <Modal
        title={recoveryUser ? t('users.recover2FAFor', { username: recoveryUser.username }) : t('users.recover2FA')}
        visible={Boolean(recoveryUser)}
        onCancel={() => setRecoveryUser(null)}
        footer={null}
        className="users-modal"
      >
        {recoveryUser && (
          <Form
            form={recoveryForm}
            layout="vertical"
            onSubmit={(values: TwoFARecoveryDraft) => twoFARecoveryMutation.mutate({ user: recoveryUser, values })}
          >
            <p>{t('users.recover2FAHint', { username: recoveryUser.username })}</p>
            <Form.Item label={t('users.currentPassword')} field="password" rules={[{ required: true, message: t('users.currentPasswordRequired') }]}>
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            <Form.Item label={t('users.confirmTargetUsername')} field="confirmUsername" rules={[{ required: true, message: t('users.confirmTargetUsernameRequired') }]}>
              <Input placeholder={recoveryUser.username} autoComplete="off" />
            </Form.Item>
            <Button type="primary" status="danger" htmlType="submit" loading={twoFARecoveryMutation.isPending} long>{t('users.recover2FA')}</Button>
          </Form>
        )}
      </Modal>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="users-summary-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function UserFields({
  t,
  includePassword,
  passwordOptional = false,
}: {
  t: (key: string, options?: Record<string, unknown>) => string;
  includePassword?: boolean;
  passwordOptional?: boolean;
}) {
  return (
    <>
      <Form.Item label={t('login.username')} field="username" rules={[{ required: true, message: t('users.usernameRequired') }]}>
        <Input placeholder={t('users.usernamePlaceholder')} />
      </Form.Item>
      <Form.Item label={t('users.role')} field="role" rules={[{ required: true }]}>
        <Select>
          {roleOptions.map((role) => <Select.Option key={role} value={role}>{roleLabel(role, t)}</Select.Option>)}
        </Select>
      </Form.Item>
      {includePassword && (
        <Form.Item
          label={passwordOptional ? t('users.newPassword') : t('login.password')}
          field="password"
          extra={passwordOptional ? t('users.passwordOptionalHint') : t('users.passwordHint')}
          rules={passwordOptional ? [] : [{ required: true, message: t('users.passwordRequired') }]}
        >
          <Input.Password placeholder={passwordOptional ? t('users.passwordKeepPlaceholder') : t('users.passwordPlaceholder')} />
        </Form.Item>
      )}
    </>
  );
}

function UserCard({
  user,
  t,
  onEdit,
  onSetup2FA,
  onDisable2FA,
  onRecover2FA,
  canSetup2FA,
  canDisable2FA,
  canRecover2FA,
}: {
  user: User;
  t: (key: string, options?: Record<string, unknown>) => string;
  onEdit: () => void;
  onSetup2FA: () => void;
  onDisable2FA: () => void;
  onRecover2FA: () => void;
  canSetup2FA: boolean;
  canDisable2FA: boolean;
  canRecover2FA: boolean;
}) {
  return (
    <article className="mobile-data-card user-mobile-card">
      <header>
        <strong>{user.username}</strong>
        <Tag>{roleLabel(user.role, t)}</Tag>
      </header>
      <dl>
        <div><dt>{t('users.twoFA')}</dt><dd><Tag color={user.two_fa_enabled ? 'green' : 'gray'}>{user.two_fa_enabled ? t('users.twoFAOn') : t('users.twoFAOff')}</Tag></dd></div>
        <div><dt>{t('users.createdAt')}</dt><dd>{formatDate(user.created_at)}</dd></div>
      </dl>
      <div className="mobile-card-actions">
        <Button onClick={onEdit}>{t('common.edit')}</Button>
        {canDisable2FA && <Button status="warning" onClick={onDisable2FA}>{t('users.disable2FA')}</Button>}
        {canRecover2FA && <Button status="warning" onClick={onRecover2FA}>{t('users.recover2FA')}</Button>}
        {canSetup2FA && <Button onClick={onSetup2FA}>{t('users.setup2FA')}</Button>}
      </div>
    </article>
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
        <div><dt>{t('logs.time')}</dt><dd>{formatDate(entry.timestamp)}</dd></div>
        <div><dt>{t('users.method')}</dt><dd>{entry.method || '-'}</dd></div>
        <div><dt>{t('logs.path')}</dt><dd><code className="table-code" title={entry.path}>{entry.path}</code></dd></div>
        <div><dt>IP</dt><dd>{stripIpPort(entry.remote_ip) || '-'}</dd></div>
      </dl>
    </article>
  );
}

// Audit remote addresses arrive as host:port (Go http.Request.RemoteAddr); display the IP only.
function stripIpPort(value: string): string {
  if (!value) {
    return value;
  }
  const bracketedV6 = /^\[([^\]]+)\]:\d+$/.exec(value);
  if (bracketedV6) {
    return bracketedV6[1];
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) {
    return value.slice(0, value.lastIndexOf(':'));
  }
  return value;
}

function roleLabel(role: string, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (role) {
    case 'admin':
      return t('users.adminRole');
    case 'operator':
      return t('users.operatorRole');
    case 'readonly':
      return t('users.readonlyRole');
    default:
      return role || t('common.unknown');
  }
}

function formatDate(value?: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function currentAccount() {
  const fallback = { subject: '', username: '', role: '' };
  const payload = (localStorage.getItem('cheesewaf-token') ?? '').split('.')[1];
  if (!payload) {
    return fallback;
  }
  try {
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='))) as { sub?: string; username?: string; role?: string };
    return { subject: decoded.sub ?? '', username: decoded.username ?? '', role: decoded.role ?? '' };
  } catch {
    return fallback;
  }
}
