import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  toast,
} from '@/components/ui';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import QRCode from 'qrcode';
import { ChevronLeft, ChevronRight, Search, ShieldCheck, UserCog, UserPlus, UsersRound } from 'lucide-react';
import { createUser, disableUser2FA, enableUser2FA, fetchAuditEntries, fetchUsers, recoverUser2FA, setupUser2FA, updateUser } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import type { AuditEntry, TOTPSetup, User } from '../../types/api';
import { passwordPolicyErrorKey } from '../../utils/passwordPolicy';

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
const userPageSizeOptions = [8, 10, 20, 50];
const auditPageSizeOptions = [10, 20, 50];

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

const emptyUserDraft = (): UserDraft => ({ username: '', role: 'operator', password: '' });
const emptyDisableDraft = (): TwoFADisableDraft => ({ password: '', code: '' });
const emptyRecoveryDraft = (): TwoFARecoveryDraft => ({ password: '', confirmUsername: '' });

export default function UsersPage() {
  const { t, i18n } = useTranslation();
  const locale = i18n?.resolvedLanguage;
  const queryClient = useQueryClient();
  const account = useMemo(() => currentAccount(), []);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [createOpen, setCreateOpen] = useState(false);
  const [createDraft, setCreateDraft] = useState<UserDraft>(emptyUserDraft);
  const [createErrors, setCreateErrors] = useState<Partial<Record<keyof UserDraft, string>>>({});
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editDraft, setEditDraft] = useState<UserDraft>(emptyUserDraft);
  const [editErrors, setEditErrors] = useState<Partial<Record<keyof UserDraft, string>>>({});
  const [disableUser, setDisableUser] = useState<User | null>(null);
  const [disableDraft, setDisableDraft] = useState<TwoFADisableDraft>(emptyDisableDraft);
  const [disableErrors, setDisableErrors] = useState<Partial<Record<keyof TwoFADisableDraft, string>>>({});
  const [recoveryUser, setRecoveryUser] = useState<User | null>(null);
  const [recoveryDraft, setRecoveryDraft] = useState<TwoFARecoveryDraft>(emptyRecoveryDraft);
  const [recoveryErrors, setRecoveryErrors] = useState<Partial<Record<keyof TwoFARecoveryDraft, string>>>({});
  const [twoFA, setTwoFA] = useState<TwoFAState>({ code: '' });
  const [userPage, setUserPage] = useState(1);
  const [userTablePageSize, setUserTablePageSize] = useState(userPageSize);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTablePageSize, setAuditTablePageSize] = useState(auditPageSize);
  const [mobileUserPage, setMobileUserPage] = useState(1);
  const [mobileAuditPage, setMobileAuditPage] = useState(1);
  const { data: users, isLoading: usersLoading, isError: usersError, isFetching: usersFetching, refetch: refetchUsers } = useQuery({
    queryKey: ['users'],
    queryFn: fetchUsers,
    retry: false,
  });
  const { data: audit, isLoading: auditLoading, isError: auditError, isFetching: auditFetching, refetch: refetchAudit } = useQuery({
    queryKey: ['audit'],
    queryFn: fetchAuditEntries,
    retry: false,
  });
  const displayedAudit = useMemo(() => withStableAuditKeys(audit ?? []).reverse(), [audit]);
  const mobileAuditItems = useMemo(() => pageItems(displayedAudit, mobileAuditPage, auditPageSize), [displayedAudit, mobileAuditPage]);
  const desktopAuditItems = useMemo(() => pageItems(displayedAudit, auditPage, auditTablePageSize), [auditPage, auditTablePageSize, displayedAudit]);

  const filteredUsers = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (users ?? []).filter((user) => {
      const matchesRole = roleFilter === 'all' || user.role === roleFilter;
      const matchesText = !needle || user.username.toLowerCase().includes(needle) || user.role.toLowerCase().includes(needle);
      return matchesRole && matchesText;
    });
  }, [roleFilter, search, users]);
  const mobileUserItems = useMemo(() => pageItems(filteredUsers, mobileUserPage, userPageSize), [filteredUsers, mobileUserPage]);
  const desktopUserItems = useMemo(() => pageItems(filteredUsers, userPage, userTablePageSize), [filteredUsers, userPage, userTablePageSize]);

  useEffect(() => {
    setMobileUserPage(1);
    setUserPage(1);
  }, [search, roleFilter]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredUsers.length / userPageSize) || 1);
    if (mobileUserPage > totalPages) {
      setMobileUserPage(totalPages);
    }
  }, [filteredUsers.length, mobileUserPage]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(filteredUsers.length / userTablePageSize) || 1);
    if (userPage > totalPages) {
      setUserPage(totalPages);
    }
  }, [filteredUsers.length, userPage, userTablePageSize]);

  useEffect(() => {
    const totalPages = Math.max(1, Math.ceil(displayedAudit.length / auditTablePageSize) || 1);
    if (auditPage > totalPages) {
      setAuditPage(totalPages);
    }
  }, [auditPage, auditTablePageSize, displayedAudit.length]);

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
      toast.success(t('users.created'));
      setCreateOpen(false);
      setCreateDraft(emptyUserDraft());
      setCreateErrors({});
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => toast.error(error.message),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, user }: { id: string; user: Partial<User> & { password?: string } }) => updateUser(id, user),
    onSuccess: async () => {
      toast.success(t('users.updated'));
      setEditUser(null);
      setEditDraft(emptyUserDraft());
      setEditErrors({});
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => toast.error(error.message),
  });

  const twoFASetupMutation = useMutation({
    mutationFn: ({ userId }: { userId: string }) => setupUser2FA(userId),
    onSuccess: async (setup, variables) => {
      const qr = await QRCode.toDataURL(setup.otpauth_url, { margin: 1, width: 180 });
      setTwoFA((current) => current.user?.id === variables.userId ? { ...current, setup, qr, code: '' } : current);
    },
    onError: (error) => toast.error(error.message),
  });

  const twoFAEnableMutation = useMutation({
    mutationFn: () => enableUser2FA(twoFA.user?.id ?? '', twoFA.setup?.secret ?? '', twoFA.code),
    onSuccess: async () => {
      toast.success(t('users.twoFAEnabled'));
      setTwoFA({ code: '' });
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => toast.error(error.message),
  });

  const twoFADisableMutation = useMutation({
    mutationFn: ({ user, values }: { user: User; values: TwoFADisableDraft }) => disableUser2FA(user.id, values.password, values.code),
    onSuccess: async () => {
      toast.success(t('users.twoFADisabled'));
      setDisableUser(null);
      setDisableDraft(emptyDisableDraft());
      setDisableErrors({});
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => toast.error(error.message),
  });

  const twoFARecoveryMutation = useMutation({
    mutationFn: ({ user, values }: { user: User; values: TwoFARecoveryDraft }) => recoverUser2FA(user.id, values.password, values.confirmUsername),
    onSuccess: async () => {
      toast.success(t('users.twoFARecovered'));
      setRecoveryUser(null);
      setRecoveryDraft(emptyRecoveryDraft());
      setRecoveryErrors({});
      await queryClient.invalidateQueries({ queryKey: ['users'] });
      await queryClient.invalidateQueries({ queryKey: ['shell-users'] });
    },
    onError: (error) => toast.error(error.message),
  });

  function open2FASetup(user: User) {
    setTwoFA({ user, code: '' });
    twoFASetupMutation.mutate({ userId: user.id });
  }

  function openDisable2FA(user: User) {
    setDisableDraft(emptyDisableDraft());
    setDisableErrors({});
    setDisableUser(user);
  }

  function openRecovery2FA(user: User) {
    setRecoveryDraft(emptyRecoveryDraft());
    setRecoveryErrors({});
    setRecoveryUser(user);
  }

  function openEditUser(user: User) {
    setEditDraft({ username: user.username, role: user.role, password: '' });
    setEditErrors({});
    setEditUser(user);
  }

  function validateUserDraft(values: UserDraft, passwordOptional: boolean) {
    const errors: Partial<Record<keyof UserDraft, string>> = {};
    if (!values.username.trim()) {
      errors.username = t('users.usernameRequired');
    }
    if (!values.role) {
      errors.role = t('users.role');
    }
    if (!passwordOptional && !values.password) {
      errors.password = t('users.passwordRequired');
    } else if (values.password) {
      const key = passwordPolicyErrorKey(values.password, '');
      if (key) {
        errors.password = t(`passwordPolicy.${key}`);
      }
    }
    return errors;
  }

  function submitCreate(event: FormEvent) {
    event.preventDefault();
    const errors = validateUserDraft(createDraft, false);
    setCreateErrors(errors);
    if (Object.keys(errors).length) {
      return;
    }
    createMutation.mutate({ username: createDraft.username, password: createDraft.password, role: createDraft.role });
  }

  function submitEdit(event: FormEvent) {
    event.preventDefault();
    if (!editUser) {
      return;
    }
    const errors = validateUserDraft(editDraft, true);
    setEditErrors(errors);
    if (Object.keys(errors).length) {
      return;
    }
    updateMutation.mutate({
      id: editUser.id,
      user: {
        username: editDraft.username,
        role: editDraft.role,
        ...(editDraft.password ? { password: editDraft.password } : {}),
      },
    });
  }

  function submitDisable(event: FormEvent) {
    event.preventDefault();
    if (!disableUser) {
      return;
    }
    const errors: Partial<Record<keyof TwoFADisableDraft, string>> = {};
    if (!disableDraft.password) {
      errors.password = t('users.currentPasswordRequired');
    }
    if (!disableDraft.code) {
      errors.code = t('users.twoFACodeRequired');
    }
    setDisableErrors(errors);
    if (Object.keys(errors).length) {
      return;
    }
    twoFADisableMutation.mutate({ user: disableUser, values: disableDraft });
  }

  function submitRecovery(event: FormEvent) {
    event.preventDefault();
    if (!recoveryUser) {
      return;
    }
    const errors: Partial<Record<keyof TwoFARecoveryDraft, string>> = {};
    if (!recoveryDraft.password) {
      errors.password = t('users.currentPasswordRequired');
    }
    if (!recoveryDraft.confirmUsername) {
      errors.confirmUsername = t('users.confirmTargetUsernameRequired');
    }
    setRecoveryErrors(errors);
    if (Object.keys(errors).length) {
      return;
    }
    twoFARecoveryMutation.mutate({ user: recoveryUser, values: recoveryDraft });
  }

  return (
    <section className="page-surface users-page">
      <header className="page-header">
        <div>
          <h1>{t('users.title')}</h1>
          <p>{t('users.subtitle')}</p>
        </div>
        <Button onClick={() => { setCreateDraft(emptyUserDraft()); setCreateErrors({}); setCreateOpen(true); }}>
          <UserPlus size={15} />
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
            <div className="relative">
              <Search size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="pl-8"
                value={search}
                placeholder={t('users.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-[160px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t('users.allRoles')}</SelectItem>
                {roleOptions.map((role) => <SelectItem key={role} value={role}>{roleLabel(role, t)}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>
        {usersError && !users ? (
          <QueryErrorState onRetry={() => void refetchUsers()} retrying={usersFetching} />
        ) : (
          <>
            <div className="desktop-table-wrap users-table-wrap">
              {usersLoading ? (
                <div className="empty-state">{t('common.loading')}</div>
              ) : filteredUsers.length === 0 ? (
                <div className="empty-state">{t('common.noData')}</div>
              ) : (
                <>
                  <Table className="users-table">
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t('users.user')}</TableHead>
                        <TableHead className="w-[140px]">{t('users.role')}</TableHead>
                        <TableHead className="w-[150px]">{t('users.twoFA')}</TableHead>
                        <TableHead className="w-[190px]">{t('users.createdAt')}</TableHead>
                        <TableHead className="w-[260px]">{t('common.actions')}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {desktopUserItems.map((record) => (
                        <TableRow key={record.id}>
                          <TableCell>
                            <div className="user-identity-cell">
                              <span><UserCog size={15} /></span>
                              <div>
                                <strong>{record.username}</strong>
                                <em>{record.id}</em>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell><Badge variant="outline">{roleLabel(record.role, t)}</Badge></TableCell>
                          <TableCell>
                            <Badge variant={record.two_fa_enabled ? 'success' : 'secondary'}>
                              {record.two_fa_enabled ? t('users.twoFAOn') : t('users.twoFAOff')}
                            </Badge>
                          </TableCell>
                          <TableCell><span className="nowrap-cell">{formatDate(record.created_at, locale)}</span></TableCell>
                          <TableCell>
                            <div className="table-action-group">
                              <Button size="sm" variant="outline" onClick={() => openEditUser(record)}>{t('common.edit')}</Button>
                              {record.two_fa_enabled && record.id === account.subject ? (
                                <Button size="sm" variant="secondary" loading={twoFADisableMutation.isPending} onClick={() => openDisable2FA(record)}>
                                  {t('users.disable2FA')}
                                </Button>
                              ) : record.two_fa_enabled && account.role === 'admin' && record.id !== account.subject ? (
                                <Button size="sm" variant="secondary" loading={twoFARecoveryMutation.isPending} onClick={() => openRecovery2FA(record)}>
                                  {t('users.recover2FA')}
                                </Button>
                              ) : !record.two_fa_enabled && record.id === account.subject ? (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  loading={twoFASetupMutation.isPending && twoFA.user?.id === record.id}
                                  onClick={() => open2FASetup(record)}
                                >
                                  <ShieldCheck size={14} />
                                  {t('users.setup2FA')}
                                </Button>
                              ) : null}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  <SimplePagination
                    page={userPage}
                    pageSize={userTablePageSize}
                    total={filteredUsers.length}
                    pageSizeOptions={userPageSizeOptions}
                    onPageChange={setUserPage}
                    onPageSizeChange={(size) => { setUserTablePageSize(size); setUserPage(1); }}
                    t={t}
                  />
                </>
              )}
            </div>
            <div className="mobile-card-list users-mobile-list">
              {usersLoading ? <div className={'empty-state'}>{t('common.loading')}</div> : filteredUsers.length === 0 ? <div className={'empty-state'}>{t('common.noData')}</div> : mobileUserItems.map((user) => (
                <UserCard
                  key={user.id}
                  user={user}
                  t={t}
                  locale={locale}
                  onEdit={() => openEditUser(user)}
                  onSetup2FA={() => open2FASetup(user)}
                  canSetup2FA={!user.two_fa_enabled && user.id === account.subject}
                  canDisable2FA={user.two_fa_enabled && user.id === account.subject}
                  canRecover2FA={user.two_fa_enabled && account.role === 'admin' && user.id !== account.subject}
                  onDisable2FA={() => openDisable2FA(user)}
                  onRecover2FA={() => openRecovery2FA(user)}
                />
              ))}
              {filteredUsers.length > userPageSize && (
                <SimplePagination
                  page={mobileUserPage}
                  pageSize={userPageSize}
                  total={filteredUsers.length}
                  onPageChange={setMobileUserPage}
                  t={t}
                  simple
                />
              )}
            </div>
          </>
        )}
      </section>

      <section className="table-panel users-audit-panel">
        <div className="panel-heading">
          <h2><ShieldCheck size={16} /> {t('users.audit')}</h2>
          <span>{t('users.auditHint')}</span>
        </div>
        {auditError && !audit ? (
          <QueryErrorState onRetry={() => void refetchAudit()} retrying={auditFetching} />
        ) : (
          <>
            <div className="table-scroll users-audit-table">
              {auditLoading ? (
                <div className="empty-state">{t('common.loading')}</div>
              ) : displayedAudit.length === 0 ? (
                <div className="empty-state">{t('common.noData')}</div>
              ) : (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-[190px]">{t('logs.time')}</TableHead>
                        <TableHead className="w-[140px]">{t('users.user')}</TableHead>
                        <TableHead className="w-[96px]">{t('users.method')}</TableHead>
                        <TableHead>{t('logs.path')}</TableHead>
                        <TableHead className="w-[110px]">{t('common.status')}</TableHead>
                        <TableHead className="w-[160px]">IP</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {desktopAuditItems.map((entry) => (
                        <TableRow key={entry.auditKey}>
                          <TableCell><span className="nowrap-cell" title={entry.timestamp}>{formatDate(entry.timestamp, locale)}</span></TableCell>
                          <TableCell><span className="nowrap-cell" title={entry.user}>{entry.user || '-'}</span></TableCell>
                          <TableCell><Badge variant="outline">{entry.method}</Badge></TableCell>
                          <TableCell><code className="table-code" title={entry.path}>{entry.path}</code></TableCell>
                          <TableCell>
                            <Badge variant={entry.status >= 400 ? 'destructive' : 'success'}>{entry.status}</Badge>
                          </TableCell>
                          <TableCell><span className="nowrap-cell">{stripIpPort(entry.remote_ip) || '-'}</span></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  <SimplePagination
                    page={auditPage}
                    pageSize={auditTablePageSize}
                    total={displayedAudit.length}
                    pageSizeOptions={auditPageSizeOptions}
                    onPageChange={setAuditPage}
                    onPageSizeChange={(size) => { setAuditTablePageSize(size); setAuditPage(1); }}
                    t={t}
                  />
                </>
              )}
            </div>
            <div className="mobile-card-list users-audit-cards">
              {auditLoading ? <div className={'empty-state'}>{t('common.loading')}</div> : displayedAudit.length === 0 ? <div className={'empty-state'}>{t('common.noData')}</div> : mobileAuditItems.map((entry) => (
                <AuditEntryCard key={entry.auditKey} entry={entry} t={t} locale={locale} />
              ))}
              {displayedAudit.length > auditPageSize && (
                <SimplePagination
                  page={mobileAuditPage}
                  pageSize={auditPageSize}
                  total={displayedAudit.length}
                  onPageChange={setMobileAuditPage}
                  t={t}
                  simple
                />
              )}
            </div>
          </>
        )}
      </section>

      <Dialog open={createOpen} onOpenChange={(open) => {
        setCreateOpen(open);
        if (!open) {
          setCreateDraft(emptyUserDraft());
          setCreateErrors({});
        }
      }}>
        <DialogContent className="users-modal">
          <DialogHeader>
            <DialogTitle>{t('users.create')}</DialogTitle>
          </DialogHeader>
          <form className="space-y-4" onSubmit={submitCreate}>
            <UserFields
              t={t}
              includePassword
              values={createDraft}
              errors={createErrors}
              onChange={(patch) => setCreateDraft((current) => ({ ...current, ...patch }))}
            />
            <Button type="submit" className="w-full" loading={createMutation.isPending}>{t('users.create')}</Button>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(editUser)} onOpenChange={(open) => {
        if (!open) {
          setEditUser(null);
          setEditDraft(emptyUserDraft());
          setEditErrors({});
        }
      }}>
        <DialogContent className="users-modal">
          <DialogHeader>
            <DialogTitle>{editUser ? t('users.editUser', { username: editUser.username }) : t('users.editUserTitle')}</DialogTitle>
          </DialogHeader>
          {editUser && (
            <form className="space-y-4" onSubmit={submitEdit}>
              <UserFields
                t={t}
                includePassword
                passwordOptional
                values={editDraft}
                errors={editErrors}
                onChange={(patch) => setEditDraft((current) => ({ ...current, ...patch }))}
              />
              <Button type="submit" className="w-full" loading={updateMutation.isPending}>{t('common.save')}</Button>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(twoFA.user)} onOpenChange={(open) => { if (!open) setTwoFA({ code: '' }); }}>
        <DialogContent className="users-modal users-twofa-modal">
          <DialogHeader>
            <DialogTitle>{twoFA.user ? t('users.setup2FAFor', { username: twoFA.user.username }) : t('users.setup2FA')}</DialogTitle>
          </DialogHeader>
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
                  <TwoFASecretReveal secret={twoFA.setup.secret} label={t('users.twoFASecret')} revealLabel={t('users.showSecret', { defaultValue: 'Show secret key' })} />
                  <Input
                    value={twoFA.code}
                    placeholder={t('users.twoFACodePlaceholder')}
                    maxLength={6}
                    onChange={(e) => setTwoFA((current) => ({ ...current, code: e.target.value.replace(/\D/g, '').slice(0, 6) }))}
                  />
                  <Button className="w-full" disabled={twoFA.code.length !== 6} loading={twoFAEnableMutation.isPending} onClick={() => twoFAEnableMutation.mutate()}>
                    {t('users.enable2FA')}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(disableUser)} onOpenChange={(open) => {
        if (!open) {
          setDisableUser(null);
          setDisableDraft(emptyDisableDraft());
          setDisableErrors({});
        }
      }}>
        <DialogContent className="users-modal">
          <DialogHeader>
            <DialogTitle>{disableUser ? t('users.disable2FAFor', { username: disableUser.username }) : t('users.disable2FA')}</DialogTitle>
          </DialogHeader>
          {disableUser && (
            <form className="space-y-4" onSubmit={submitDisable}>
              <div className="space-y-2">
                <Label>{t('users.currentPassword')}</Label>
                <Input
                  type="password"
                  autoComplete="current-password"
                  value={disableDraft.password}
                  onChange={(e) => setDisableDraft((current) => ({ ...current, password: e.target.value }))}
                />
                {disableErrors.password && <p className="text-sm text-destructive">{disableErrors.password}</p>}
              </div>
              <div className="space-y-2">
                <Label>{t('users.twoFACode')}</Label>
                <Input
                  maxLength={6}
                  inputMode="numeric"
                  value={disableDraft.code}
                  onChange={(e) => setDisableDraft((current) => ({ ...current, code: e.target.value.replace(/\D/g, '').slice(0, 6) }))}
                />
                {disableErrors.code && <p className="text-sm text-destructive">{disableErrors.code}</p>}
              </div>
              <Button type="submit" variant="destructive" className="w-full" loading={twoFADisableMutation.isPending}>{t('users.disable2FA')}</Button>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(recoveryUser)} onOpenChange={(open) => {
        if (!open) {
          setRecoveryUser(null);
          setRecoveryDraft(emptyRecoveryDraft());
          setRecoveryErrors({});
        }
      }}>
        <DialogContent className="users-modal">
          <DialogHeader>
            <DialogTitle>{recoveryUser ? t('users.recover2FAFor', { username: recoveryUser.username }) : t('users.recover2FA')}</DialogTitle>
          </DialogHeader>
          {recoveryUser && (
            <form className="space-y-4" onSubmit={submitRecovery}>
              <p>{t('users.recover2FAHint', { username: recoveryUser.username })}</p>
              <div className="space-y-2">
                <Label>{t('users.currentPassword')}</Label>
                <Input
                  type="password"
                  autoComplete="current-password"
                  value={recoveryDraft.password}
                  onChange={(e) => setRecoveryDraft((current) => ({ ...current, password: e.target.value }))}
                />
                {recoveryErrors.password && <p className="text-sm text-destructive">{recoveryErrors.password}</p>}
              </div>
              <div className="space-y-2">
                <Label>{t('users.confirmTargetUsername')}</Label>
                <Input
                  placeholder={recoveryUser.username}
                  autoComplete="off"
                  value={recoveryDraft.confirmUsername}
                  onChange={(e) => setRecoveryDraft((current) => ({ ...current, confirmUsername: e.target.value }))}
                />
                {recoveryErrors.confirmUsername && <p className="text-sm text-destructive">{recoveryErrors.confirmUsername}</p>}
              </div>
              <Button type="submit" variant="destructive" className="w-full" loading={twoFARecoveryMutation.isPending}>{t('users.recover2FA')}</Button>
            </form>
          )}
        </DialogContent>
      </Dialog>
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
  values,
  errors,
  onChange,
}: {
  t: (key: string, options?: Record<string, unknown>) => string;
  includePassword?: boolean;
  passwordOptional?: boolean;
  values: UserDraft;
  errors: Partial<Record<keyof UserDraft, string>>;
  onChange: (patch: Partial<UserDraft>) => void;
}) {
  return (
    <>
      <div className="space-y-2">
        <Label>{t('login.username')}</Label>
        <Input
          placeholder={t('users.usernamePlaceholder')}
          value={values.username}
          onChange={(e) => onChange({ username: e.target.value })}
        />
        {errors.username && <p className="text-sm text-destructive">{errors.username}</p>}
      </div>
      <div className="space-y-2">
        <Label>{t('users.role')}</Label>
        <Select value={values.role} onValueChange={(role) => onChange({ role })}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            {roleOptions.map((role) => <SelectItem key={role} value={role}>{roleLabel(role, t)}</SelectItem>)}
          </SelectContent>
        </Select>
        {errors.role && <p className="text-sm text-destructive">{errors.role}</p>}
      </div>
      {includePassword && (
        <div className="space-y-2">
          <Label>{passwordOptional ? t('users.newPassword') : t('login.password')}</Label>
          <Input
            type="password"
            placeholder={passwordOptional ? t('users.passwordKeepPlaceholder') : t('users.passwordPlaceholder')}
            value={values.password}
            onChange={(e) => onChange({ password: e.target.value })}
          />
          <p className="text-xs text-muted-foreground">{passwordOptional ? t('users.passwordOptionalHint') : t('users.passwordHint')}</p>
          {errors.password && <p className="text-sm text-destructive">{errors.password}</p>}
        </div>
      )}
    </>
  );
}

function UserCard({
  user,
  t,
  locale,
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
  locale?: string;
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
        <Badge variant="outline">{roleLabel(user.role, t)}</Badge>
      </header>
      <dl>
        <div>
          <dt>{t('users.twoFA')}</dt>
          <dd>
            <Badge variant={user.two_fa_enabled ? 'success' : 'secondary'}>
              {user.two_fa_enabled ? t('users.twoFAOn') : t('users.twoFAOff')}
            </Badge>
          </dd>
        </div>
        <div><dt>{t('users.createdAt')}</dt><dd>{formatDate(user.created_at, locale)}</dd></div>
      </dl>
      <div className="mobile-card-actions">
        <Button variant="outline" onClick={onEdit}>{t('common.edit')}</Button>
        {canDisable2FA && <Button variant="secondary" onClick={onDisable2FA}>{t('users.disable2FA')}</Button>}
        {canRecover2FA && <Button variant="secondary" onClick={onRecover2FA}>{t('users.recover2FA')}</Button>}
        {canSetup2FA && <Button variant="outline" onClick={onSetup2FA}>{t('users.setup2FA')}</Button>}
      </div>
    </article>
  );
}

function AuditEntryCard({
  entry,
  t,
  locale,
}: {
  entry: AuditEntry;
  t: (key: string, options?: Record<string, unknown>) => string;
  locale?: string;
}) {
  return (
    <article className="mobile-data-card">
      <header>
        <strong>{entry.user || '-'}</strong>
        <Badge variant={entry.status >= 400 ? 'destructive' : 'success'}>{entry.status}</Badge>
      </header>
      <dl>
        <div><dt>{t('logs.time')}</dt><dd>{formatDate(entry.timestamp, locale)}</dd></div>
        <div><dt>{t('users.method')}</dt><dd>{entry.method || '-'}</dd></div>
        <div><dt>{t('logs.path')}</dt><dd><code className="table-code" title={entry.path}>{entry.path}</code></dd></div>
        <div><dt>IP</dt><dd>{stripIpPort(entry.remote_ip) || '-'}</dd></div>
      </dl>
    </article>
  );
}

function SimplePagination({
  page,
  pageSize,
  total,
  pageSizeOptions,
  onPageChange,
  onPageSizeChange,
  t,
  simple = false,
}: {
  page: number;
  pageSize: number;
  total: number;
  pageSizeOptions?: number[];
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  t: (key: string, options?: Record<string, unknown>) => string;
  simple?: boolean;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1);
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 py-3">
      {!simple && (
        <span className="text-sm text-muted-foreground">
          {total}
        </span>
      )}
      <div className="flex items-center gap-2 ml-auto">
        {!simple && pageSizeOptions && onPageSizeChange && (
          <Select value={String(pageSize)} onValueChange={(value) => onPageSizeChange(Number(value))}>
            <SelectTrigger className="w-[90px]"><SelectValue /></SelectTrigger>
            <SelectContent>
              {pageSizeOptions.map((size) => (
                <SelectItem key={size} value={String(size)}>{size}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => onPageChange(page - 1)} aria-label={t('common.back')}>
          <ChevronLeft size={14} />
        </Button>
        <span className="text-sm tabular-nums">{page} / {totalPages}</span>
        <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} aria-label={t('common.next')}>
          <ChevronRight size={14} />
        </Button>
      </div>
    </div>
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

function formatDate(value?: string, locale?: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString(locale);
}

function currentAccount() {
  const fallback = { subject: '', username: '', role: '' };
  try {
    const cached = sessionStorage.getItem('cheesewaf-account');
    if (cached) {
      const parsed = JSON.parse(cached) as { subject?: string; username?: string; role?: string };
      return {
        subject: parsed.subject ?? '',
        username: parsed.username ?? '',
        role: parsed.role ?? '',
      };
    }
  } catch {
    /* fall through */
  }
  return fallback;
}

function TwoFASecretReveal({ secret, label, revealLabel }: { secret: string; label: string; revealLabel: string }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    if (!visible) return;
    const timer = window.setTimeout(() => setVisible(false), 30_000);
    return () => window.clearTimeout(timer);
  }, [visible]);
  return (
    <div className="users-twofa-secret">
      <span>{label}</span>
      {!visible ? (
        <Button type="button" variant="outline" size="sm" onClick={() => setVisible(true)}>{revealLabel}</Button>
      ) : (
        <code className="users-twofa-secret-value" style={{ userSelect: 'none' }}>{secret}</code>
      )}
    </div>
  );
}
