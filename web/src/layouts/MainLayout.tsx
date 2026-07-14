import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Button, Dropdown, Input, Menu, Message as ArcoMessage, Modal, Pagination, Select, Space, Tag, Tooltip } from '@arco-design/web-react';
import '../styles/arco-components';
import {
  BrainCircuit,
  Bot,
  FileCode2,
  Bell,
  Clock3,
  LogOut,
  Gauge,
  LineChart,
  Map,
  Globe2,
  LockKeyhole,
  Languages,
  LayoutDashboard,
  ListFilter,
  ListChecks,
  Menu as MenuIcon,
  Network,
  Radar,
  Pin,
  PinOff,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  CloudDownload,
  UserCog,
  UserRound,
  SunMoon,
  type LucideIcon,
} from 'lucide-react';
import i18n from '../i18n';
import { clearNotifications, fetchAuditEntries, fetchHealth, fetchLogs, fetchNotifications, fetchUsers, fetchVersion, logout, markAllNotificationsRead as markAllNotificationsReadAPI, sanitizeInternalReturnPath, updateNotification } from '../api/client';
import AIAssistantEntry from '../components/AIAssistant/AIAssistantEntry';
import BrandLogo from '../components/BrandLogo';
import { useAppStore, type Language } from '../stores';
import { themeOptions, type ThemeName } from '../themes/tokens';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { AuditEntry, LogEntry, Notification, NotificationFilter, User } from '../types/api';
import { displayAction } from '../utils/display';
import { preloadRoute } from '../routes/preload';

type NavItem = { key: string; labelKey: string; icon: LucideIcon };
type NavGroup = { labelKey: string; items: NavItem[] };

const navGroups: NavGroup[] = [
  {
    labelKey: 'navGroup.posture',
    items: [
      { key: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard },
      { key: '/monitor', labelKey: 'nav.monitor', icon: LineChart },
      { key: '/attack-map', labelKey: 'nav.attackMap', icon: Map },
    ],
  },
  {
    labelKey: 'navGroup.security',
    items: [
      { key: '/sites', labelKey: 'nav.sites', icon: Globe2 },
      { key: '/ssl', labelKey: 'nav.ssl', icon: LockKeyhole },
      { key: '/rules', labelKey: 'nav.rules', icon: ListChecks },
      { key: '/logs', labelKey: 'nav.logs', icon: ListFilter },
      { key: '/ip', labelKey: 'nav.ip', icon: Shield },
      { key: '/protection', labelKey: 'nav.protection', icon: ShieldAlert },
      { key: '/bot-challenge', labelKey: 'nav.botChallenge', icon: Bot },
      { key: '/apisec', labelKey: 'nav.apisec', icon: Radar },
      { key: '/ai', labelKey: 'nav.ai', icon: BrainCircuit },
    ],
  },
  {
    labelKey: 'navGroup.platform',
    items: [
      { key: '/edge', labelKey: 'nav.edge', icon: Gauge },
      { key: '/block-pages', labelKey: 'nav.blockPages', icon: FileCode2 },
      { key: '/users', labelKey: 'nav.users', icon: UserCog },
      { key: '/ops', labelKey: 'nav.ops', icon: Radar },
      { key: '/updates', labelKey: 'nav.updates', icon: CloudDownload },
      { key: '/cluster', labelKey: 'nav.cluster', icon: Network },
      { key: '/system', labelKey: 'nav.system', icon: Settings },
    ],
  },
];

const allNavItems = navGroups.flatMap((group) => group.items);
export default function MainLayout() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const sidebarCollapsed = useAppStore((state) => state.sidebarCollapsed);
  const setTheme = useAppStore((state) => state.setTheme);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const setSidebarCollapsed = useAppStore((state) => state.setSidebarCollapsed);
  const queryClient = useQueryClient();
  const { data: version } = useQuery({ queryKey: ['version'], queryFn: fetchVersion, staleTime: 5 * 60_000, retry: false });
  const { data: recentLogs } = useQuery({ queryKey: ['recent-security-logs', 12], queryFn: () => fetchLogs({ limit: 12 }), refetchInterval: 30_000, staleTime: 20_000, retry: false });
  const { data: auditEntries } = useQuery({ queryKey: ['shell-audit'], queryFn: fetchAuditEntries, staleTime: 30_000, refetchInterval: 60_000, retry: false });
  const { data: users } = useQuery({ queryKey: ['shell-users'], queryFn: fetchUsers, staleTime: 60_000, retry: false });
  const [healthFailures, setHealthFailures] = useState(0);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState(Date.now());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const heartbeatRefetching = useRef(false);
  const healthQuery = useQuery({
    queryKey: ['shell-health'],
    queryFn: fetchHealth,
    // Healthy consoles do not need 1s polling — keep light contact and back off on failures.
    refetchInterval: healthFailures >= 5 ? false : healthFailures > 0 ? 10_000 : 15_000,
    retry: false,
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationFilter, setNotificationFilter] = useState<NotificationFilter>('all');
  const [notificationPage, setNotificationPage] = useState(1);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const notificationShellRef = useRef<HTMLDivElement | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});
  const account = currentAccount();
  const shellClassName = [
    sidebarCollapsed ? 'app-shell app-shell-collapsed' : 'app-shell',
    mobileNavOpen ? 'app-mobile-nav-open' : '',
  ].filter(Boolean).join(' ');

  useEffect(() => {
    setNotificationsOpen(false);
    setMobileNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!notificationsOpen) {
      return undefined;
    }
    const closeFromOutside = (event: PointerEvent) => {
      const target = event.target;
      if (target instanceof Node && notificationShellRef.current?.contains(target)) {
        return;
      }
      setNotificationsOpen(false);
    };
    const closeFromEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setNotificationsOpen(false);
      }
    };
    window.addEventListener('pointerdown', closeFromOutside, { capture: true });
    window.addEventListener('keydown', closeFromEscape);
    return () => {
      window.removeEventListener('pointerdown', closeFromOutside, { capture: true });
      window.removeEventListener('keydown', closeFromEscape);
    };
  }, [notificationsOpen]);

  useEffect(() => {
    if (!mobileNavOpen) {
      return undefined;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMobileNavOpen(false);
      }
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [mobileNavOpen]);

  useEffect(() => {
    if (healthQuery.isSuccess) {
      setHealthFailures(0);
      setLastHeartbeatAt(Date.now());
    }
    if (healthQuery.isError) {
      setHealthFailures((value) => Math.min(5, value + 1));
    }
  }, [healthQuery.isError, healthQuery.isSuccess, healthQuery.dataUpdatedAt, healthQuery.errorUpdatedAt]);

  const healthRefetch = healthQuery.refetch;
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (healthFailures >= 5 || heartbeatRefetching.current) {
        return;
      }
      // Stale heartbeat only after well beyond the healthy poll interval.
      if (Date.now() - lastHeartbeatAt <= 20_000) {
        return;
      }
      setHealthFailures((value) => Math.max(1, Math.min(5, value + 1)));
      heartbeatRefetching.current = true;
      void healthRefetch().finally(() => {
        heartbeatRefetching.current = false;
      });
    }, 5_000);
    return () => window.clearInterval(timer);
  }, [healthFailures, healthRefetch, lastHeartbeatAt]);

  const currentKey = allNavItems.find((item) => (
    item.key === '/'
      ? location.pathname === '/'
      : location.pathname === item.key || location.pathname.startsWith(`${item.key}/`)
  ))?.key ?? '/';
  const connection = connectionState(healthFailures, healthQuery.data?.status, healthQuery.isFetching, lastHeartbeatAt);
  const showGlobalAssistant = !location.pathname.startsWith('/ai');
  const recentLogItems = useMemo(() => safeArray<LogEntry>(recentLogs?.items), [recentLogs?.items]);
  const auditItems = useMemo(() => safeArray<AuditEntry>(auditEntries), [auditEntries]);
  const userItems = useMemo(() => safeArray<User>(users), [users]);
  const notificationLimit = 8;
  const notificationQuery = useQuery({
    queryKey: ['notifications', notificationFilter, notificationPage],
    queryFn: () => fetchNotifications({ page: notificationPage, limit: notificationLimit, filter: notificationFilter }),
    refetchInterval: 15_000,
    staleTime: 10_000,
    retry: false,
    placeholderData: (previous) => previous,
  });
  const notificationItems = safeArray<Notification>(notificationQuery.data?.items);
  const unreadNotifications = notificationQuery.data?.unread ?? 0;
  const refreshNotifications = () => queryClient.invalidateQueries({ queryKey: ['notifications'] });
  const notificationMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: { read?: boolean; pinned?: boolean } }) => updateNotification(id, patch),
    onSuccess: () => {
      setNotificationPage(1);
      void refreshNotifications();
    },
    onError: (error) => ArcoMessage.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const markAllReadMutation = useMutation({
    mutationFn: markAllNotificationsReadAPI,
    onSuccess: () => {
      setNotificationPage(1);
      void refreshNotifications();
    },
    onError: (error) => ArcoMessage.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const clearNotificationsMutation = useMutation({
    mutationFn: clearNotifications,
    onSuccess: () => {
      setNotificationPage(1);
      void refreshNotifications();
    },
    onError: (error) => ArcoMessage.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const searchResults = useMemo(
    () => buildSearchResults(searchValue, recentLogItems, auditItems, userItems, t),
    [auditItems, recentLogItems, searchValue, t, userItems],
  );

  function reconnectHealth() {
    setHealthFailures(0);
    void healthQuery.refetch();
  }

  function markNotificationRead(id: string) {
    notificationMutation.mutate({ id, patch: { read: true } });
  }

  function toggleNotificationRead(item: Notification) {
    notificationMutation.mutate({ id: item.id, patch: { read: !item.read } });
  }

  function markAllNotificationsRead() {
    markAllReadMutation.mutate();
  }

  function clearAllNotifications() {
    Modal.confirm({
      title: t('shell.clearNotificationsConfirmTitle'),
      content: t('shell.clearNotificationsConfirmContent'),
      okButtonProps: { status: 'danger' },
      onOk: () => clearNotificationsMutation.mutateAsync(),
    });
  }

  function toggleNotificationPin(item: Notification) {
    notificationMutation.mutate({ id: item.id, patch: { pinned: !item.pinned } });
  }

  async function handleLogout() {
    try {
      await logout();
    } catch {
      // Local logout must still work if the session is already expired or the API is unreachable.
    } finally {
      localStorage.removeItem('cheesewaf-token');
      queryClient.clear();
      navigate('/login', { replace: true });
    }
  }

  return (
    <div className={shellClassName}>
      <aside className="app-sidebar">
        <div className="brand-row">
          <button className="brand-mark" type="button" aria-label={t('common.home')} onClick={() => navigate('/')}>
            <BrandLogo />
          </button>
          <div className="brand-copy">
            <strong>CheeseWAF</strong>
            <span>{t('shell.status')}</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Primary">
          {navGroups.map((group) => {
            const collapsed = Boolean(collapsedGroups[group.labelKey]);
            return (
              <section key={group.labelKey} className="nav-group">
                <button
                  type="button"
                  className="nav-group-heading"
                  aria-expanded={!collapsed}
                  onClick={() =>
                    setCollapsedGroups((prev) => ({
                      ...prev,
                      [group.labelKey]: !prev[group.labelKey],
                    }))
                  }
                >
                  <span>{t(group.labelKey)}</span>
                </button>
                <div className={collapsed ? 'nav-group-items nav-group-collapsed' : 'nav-group-items'}>
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    const active = currentKey === item.key;
                    return (
                      <Link
                        key={item.key}
                        to={item.key}
                        className={active ? 'nav-item nav-item-active' : 'nav-item'}
                        onClick={() => setMobileNavOpen(false)}
                        onMouseEnter={() => preloadRoute(item.key)}
                        onFocus={() => preloadRoute(item.key)}
                      >
                        <Icon size={18} />
                        <span>{t(item.labelKey)}</span>
                      </Link>
                    );
                  })}
                </div>
              </section>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <button className={`sidebar-status sidebar-status-${connection.state}`} type="button" onClick={reconnectHealth}>
            <span className="status-dot" />
            <div className="sidebar-status-copy">
              <strong>{t(connection.titleKey)}</strong>
              <span>{connectionDetail(connection.state, healthFailures, t)}</span>
            </div>
          </button>
          <Tooltip content={versionTooltip(version, t)}>
            <button className="sidebar-version" type="button" onClick={() => navigate('/updates')}>
              <span>CheeseWAF</span>
              <strong>{versionLabel(version, t)}</strong>
            </button>
          </Tooltip>
        </div>
      </aside>
      <button className="mobile-nav-backdrop" type="button" aria-label={t('common.close')} onClick={() => setMobileNavOpen(false)} />

      <div className="app-main">
        <header className="topbar">
          <Space className="topbar-left" size={10}>
            <Tooltip content={mobileNavOpen ? t('shell.closeSidebar') : sidebarCollapsed ? t('shell.expandSidebar') : t('shell.collapseSidebar')}>
              <Button
                className="icon-button"
                icon={<MenuIcon size={18} />}
                aria-expanded={mobileNavOpen}
                aria-label={mobileNavOpen ? t('shell.closeSidebar') : sidebarCollapsed ? t('shell.expandSidebar') : t('shell.collapseSidebar')}
                onClick={() => {
                  if (window.matchMedia('(max-width: 1024px)').matches) {
                    setMobileNavOpen((open) => !open);
                    return;
                  }
                  setSidebarCollapsed(!sidebarCollapsed);
                }}
              />
            </Tooltip>
            <button className="topbar-mobile-brand" type="button" aria-label={t('common.home')} onClick={() => navigate('/')}>
              <BrandLogo />
            </button>
            <Input
              className="topbar-search"
              prefix={<Search size={16} />}
              placeholder={t('common.search')}
              aria-label={t('common.search')}
              allowClear
              value={searchValue}
              onChange={(value) => {
                setSearchValue(value);
                setSearchOpen(Boolean(String(value).trim()));
              }}
              onFocus={() => setSearchOpen(Boolean(searchValue.trim()))}
              onBlur={() => window.setTimeout(() => setSearchOpen(false), 120)}
              onPressEnter={() => {
                const first = searchResults[0];
                if (first) {
                  navigate(first.to);
                  setSearchOpen(false);
                  setSearchValue('');
                }
              }}
            />
            {searchOpen && (
              <div className="topbar-search-panel" role="listbox">
                {searchResults.length === 0 ? (
                  <div className="topbar-search-empty">{t('shell.searchEmpty')}</div>
                ) : searchResults.map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    className="topbar-search-result"
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => {
                      navigate(item.to);
                      setSearchOpen(false);
                      setSearchValue('');
                    }}
                  >
                    <span>{item.type}</span>
                    <strong>{item.title}</strong>
                    <em>{item.subtitle}</em>
                  </button>
                ))}
              </div>
            )}
          </Space>

          <div className="topbar-right">
            <div className="topbar-actions">
              <div className="notification-shell" ref={notificationShellRef}>
                <span className="notification-trigger">
                  <Button
                    className={notificationsOpen ? 'icon-button notification-button notification-button-active' : 'icon-button notification-button'}
                    icon={<Bell size={18} />}
                    aria-label={t('shell.notifications')}
                    aria-expanded={notificationsOpen}
                    aria-haspopup="dialog"
                    aria-controls="cheesewaf-notification-panel"
                    onClick={() => {
                      setSearchOpen(false);
                      setNotificationsOpen((open) => !open);
                    }}
                  />
                  {unreadNotifications > 0 && <span className="notification-dot">{unreadNotifications > 9 ? '9+' : unreadNotifications}</span>}
                </span>
                {notificationsOpen && (
                  <NotificationPanel
                    items={notificationItems}
                    total={notificationQuery.data?.total ?? 0}
                    filteredTotal={notificationQuery.data?.filtered_total ?? 0}
                    unread={unreadNotifications}
                    page={notificationPage}
                    pageSize={notificationLimit}
                    filter={notificationFilter}
                    loading={notificationQuery.isLoading}
                    error={notificationQuery.isError}
                    busy={notificationMutation.isPending || markAllReadMutation.isPending || clearNotificationsMutation.isPending}
                    onRetry={() => void notificationQuery.refetch()}
                    onPageChange={setNotificationPage}
                    onFilterChange={(filter) => {
                      setNotificationFilter(filter);
                      setNotificationPage(1);
                    }}
                    onMarkAllRead={markAllNotificationsRead}
                    onClearAll={clearAllNotifications}
                    onToggleRead={toggleNotificationRead}
                    onTogglePin={toggleNotificationPin}
                    onOpen={(item) => {
                      if (!item.read) {
                        markNotificationRead(item.id);
                      }
                      navigate(sanitizeInternalReturnPath(item.target || '/'));
                      setNotificationsOpen(false);
                    }}
                  />
                )}
              </div>
              <Select
                aria-label={t('system.theme')}
                className="topbar-select"
                value={theme}
                prefix={<SunMoon size={15} />}
                onChange={(value) => setTheme(value as ThemeName)}
              >
                {themeOptions.map((option) => (
                  <Select.Option key={option.value} value={option.value}>
                    {t(option.labelKey)}
                  </Select.Option>
                ))}
              </Select>
              <Select
                aria-label={t('system.language')}
                className="language-select"
                value={language}
                prefix={<Languages size={15} />}
                onChange={(value) => setLanguage(value as Language)}
              >
                <Select.Option value="zh-CN">中文</Select.Option>
                <Select.Option value="en-US">English</Select.Option>
              </Select>
            </div>
            <Dropdown
              droplist={
                <Menu
                  onClickMenuItem={(key) => {
                    if (key === 'users') {
                      navigate('/users');
                    }
                    if (key === 'logout') {
                      handleLogout();
                    }
                  }}
                >
                  <Menu.Item key="users">
                    <span className="menu-inline"><UserCog size={14} /> {t('shell.admin')}</span>
                  </Menu.Item>
                  <Menu.Item key="logout">
                    <span className="menu-inline"><LogOut size={14} /> {t('common.logout')}</span>
                  </Menu.Item>
                </Menu>
              }
            >
              <button className="account-button" type="button">
                <UserRound size={16} />
                <span>{account.username}</span>
              </button>
            </Dropdown>
          </div>
        </header>

        <main className="workspace">
          <Outlet />
        </main>
        {showGlobalAssistant && <AIAssistantEntry />}
      </div>
    </div>
  );
}

export function NotificationPanel({
  items,
  total,
  filteredTotal,
  unread,
  page,
  pageSize,
  filter,
  loading,
  error,
  busy,
  onRetry,
  onPageChange,
  onFilterChange,
  onOpen,
  onMarkAllRead,
  onClearAll,
  onToggleRead,
  onTogglePin,
}: {
  items: Notification[];
  total: number;
  filteredTotal: number;
  unread: number;
  page: number;
  pageSize: number;
  filter: NotificationFilter;
  loading: boolean;
  error: boolean;
  busy: boolean;
  onRetry: () => void;
  onPageChange: (page: number) => void;
  onFilterChange: (filter: NotificationFilter) => void;
  onOpen: (item: Notification) => void;
  onMarkAllRead: () => void;
  onClearAll: () => void;
  onToggleRead: (item: Notification) => void;
  onTogglePin: (item: Notification) => void;
}) {
  const { t } = useTranslation();
  const filterOptions: Array<{ key: NotificationFilter; label: string }> = [
    { key: 'all', label: t('shell.notificationFilterAll') },
    { key: 'unread', label: t('shell.notificationFilterUnread') },
    { key: 'read', label: t('shell.notificationFilterRead') },
    { key: 'pinned', label: t('shell.notificationFilterPinned') },
  ];
  const keyedItems = withStableNotificationKeys(items);
  return (
    <section
      id="cheesewaf-notification-panel"
      className="notification-panel"
      role="dialog"
      aria-label={t('shell.notifications')}
    >
      <header>
        <strong>{t('shell.notifications')}</strong>
        <Tag color={unread > 0 ? 'orange' : 'green'}>
          {total ? t('shell.notificationPanelSummary', { unread, total }) : t('common.healthy')}
        </Tag>
      </header>
      {total > 0 && (
        <div className="notification-filter-tabs" role="tablist" aria-label={t('shell.notifications')}>
          {filterOptions.map((option) => (
            <button
              key={option.key}
              type="button"
              role="tab"
              className={filter === option.key ? 'notification-filter-active' : ''}
              aria-selected={filter === option.key}
              onClick={() => onFilterChange(option.key)}
            >
              {option.label}
            </button>
          ))}
        </div>
      )}
      {total > 0 && (
        <div className="notification-actions">
          <Button size="mini" loading={busy} disabled={unread === 0 || busy} onClick={onMarkAllRead}>{t('shell.markAllRead')}</Button>
          <Button size="mini" status="warning" loading={busy} disabled={total === 0 || busy} onClick={onClearAll}>{t('shell.clearAllNotifications')}</Button>
        </div>
      )}
      <div className="notification-list">
        {error ? (
          <div className="notification-empty"><span>{t('shell.notificationLoadFailed')}</span><Button size="mini" onClick={onRetry}>{t('common.retry')}</Button></div>
        ) : loading && items.length === 0 ? (
          <div className="notification-empty">{t('common.loading')}</div>
        ) : items.length === 0 ? (
          <div className="notification-empty">{total ? t('shell.noFilteredNotifications') : t('shell.noNotifications')}</div>
        ) : keyedItems.map(({ item, notificationKey }) => (
          <article
            key={notificationKey}
            className={`notification-item notification-item-${item.type}${item.read ? ' notification-item-read' : ''}${item.pinned ? ' notification-item-pinned' : ''}`}
          >
            <button type="button" className="notification-open" onClick={() => onOpen(item)}>
              <span className="notification-item-title">
                {!item.read && <i aria-hidden="true" />}
                {item.title}
                {item.pinned && <Tag size="small" color="arcoblue">{t('shell.pinnedNotification')}</Tag>}
              </span>
              <strong>{item.message}</strong>
              <em><Clock3 size={12} /> {formatRelativeTime(item.created_at)}</em>
            </button>
            <div className="notification-item-actions">
              <button
                type="button"
                className="notification-read-toggle"
                aria-label={item.read ? t('shell.markUnread') : t('shell.markRead')}
                title={item.read ? t('shell.markUnread') : t('shell.markRead')}
                disabled={busy}
                onClick={() => onToggleRead(item)}
              >
                {item.read ? t('shell.readState') : t('shell.unreadState')}
              </button>
              <button
                type="button"
                className="notification-pin"
                aria-label={item.pinned ? t('shell.unpinNotification') : t('shell.pinNotification')}
                title={item.pinned ? t('shell.unpinNotification') : t('shell.pinNotification')}
                disabled={busy}
                onClick={() => onTogglePin(item)}
              >
                {item.pinned ? <PinOff size={13} /> : <Pin size={13} />}
              </button>
            </div>
          </article>
        ))}
      </div>
      {filteredTotal > pageSize && (
        <Pagination simple size="mini" current={page} pageSize={pageSize} total={filteredTotal} onChange={onPageChange} />
      )}
    </section>
  );
}

type KeyedNotification = { item: Notification; notificationKey: string };

export function withStableNotificationKeys(items: readonly Notification[]): KeyedNotification[] {
  const occurrences = new globalThis.Map<string, number>();
  return items.map((item) => {
    const fingerprint = JSON.stringify([item.id, item.type, item.title, item.message, item.target, item.read, item.pinned, item.created_at, item.updated_at]);
    const occurrence = (occurrences.get(fingerprint) ?? 0) + 1;
    occurrences.set(fingerprint, occurrence);
    return { item, notificationKey: `${fingerprint}#${occurrence}` };
  });
}

type SearchResult = {
  key: string;
  type: string;
  title: string;
  subtitle: string;
  to: string;
};

export function buildSearchResults(query: string, logs: LogEntry[], audits: AuditEntry[], users: User[], t: (key: string, options?: Record<string, unknown>) => string): SearchResult[] {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return [];
  }
  const results: SearchResult[] = [];
  for (const item of allNavItems) {
    const label = t(item.labelKey);
    if (matchesSearch(needle, label, item.key)) {
      results.push({ key: `nav:${item.key}`, type: t('shell.searchSection'), title: label, subtitle: item.key, to: item.key });
    }
  }
  for (const log of logs) {
    const ref = log.trace_id || log.id;
    if (ref && matchesSearch(needle, ref, log.client_ip, log.uri, log.category, log.action)) {
      results.push({
        key: `log:${log.id || ref}`,
        type: t('shell.searchEvent'),
        title: ref,
        subtitle: `${log.client_ip || '-'} · ${displayAction(log.action, t)} · ${log.uri || '/'}`,
        to: `/logs/${encodeURIComponent(ref)}`,
      });
    }
  }
  for (const user of users) {
    if (matchesSearch(needle, user.username, user.role)) {
      results.push({
        key: `user:${user.id || user.username}`,
        type: t('shell.searchUser'),
        title: user.username,
        subtitle: user.role,
        to: '/users',
      });
    }
  }
  for (const audit of audits.slice(-40).reverse()) {
    if (matchesSearch(needle, audit.user, audit.path, audit.method, String(audit.status))) {
      results.push({
        key: `audit:${audit.timestamp}:${audit.user}:${audit.method}:${audit.path}:${audit.status}:${audit.remote_ip}:${audit.latency_ms}`,
        type: t('shell.searchAudit'),
        title: audit.user || audit.path,
        subtitle: `${audit.method} ${audit.path} · ${audit.status}`,
        to: '/users',
      });
    }
  }
  const occurrences = new globalThis.Map<string, number>();
  return results.slice(0, 8).map((result) => {
    const occurrence = occurrences.get(result.key) ?? 0;
    occurrences.set(result.key, occurrence + 1);
    return occurrence === 0 ? result : { ...result, key: `${result.key}:duplicate:${occurrence}` };
  });
}

function matchesSearch(needle: string, ...values: Array<string | undefined>) {
  return values.some((value) => String(value ?? '').toLowerCase().includes(needle));
}

function safeArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? value as T[] : [];
}

function formatRelativeTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value || '-';
  }
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) {
    return `${Math.max(1, seconds)}s`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)}m`;
  }
  if (seconds < 86400) {
    return `${Math.round(seconds / 3600)}h`;
  }
  return date.toLocaleString();
}

function connectionState(failures: number, status: string | undefined, fetching: boolean, lastHeartbeatAt: number) {
  if (failures >= 5) {
    return { state: 'offline', titleKey: 'shell.connectionOffline' };
  }
  if (failures > 0 || (fetching && Date.now() - lastHeartbeatAt > 3_000)) {
    return { state: 'reconnecting', titleKey: 'shell.connectionReconnecting' };
  }
  if (status === 'ok') {
    return { state: 'online', titleKey: 'shell.connectionOnline' };
  }
  return { state: 'reconnecting', titleKey: 'shell.connectionReconnecting' };
}

function connectionDetail(state: string, failures: number, t: (key: string, options?: Record<string, unknown>) => string) {
  if (state === 'offline') {
    return t('shell.connectionFailed');
  }
  if (state === 'reconnecting') {
    return t('shell.connectionRetrying', { count: Math.max(1, failures), total: 5 });
  }
  return t('shell.connectionReady');
}

function channelLabel(channel: string | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  switch (channel) {
    case 'stable':
      return t('updates.channelStable');
    case 'canary':
      return t('updates.channelCanary');
    case 'dev':
    case 'dev-local':
      return t('updates.channelDev');
    default:
      return channel || t('common.unknown');
  }
}

function versionTooltip(version: { version: string; channel: string; commit: string; build_time: string; platform: string } | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  if (!version?.version) {
    return fallbackText(t, 'shell.versionUnavailable', 'Version unavailable');
  }
  return [
    version.version,
    channelLabel(version.channel, t),
    version.commit,
    version.platform,
    version.build_time,
  ].filter(Boolean).join(' · ');
}

function versionLabel(version: { version: string; channel: string } | undefined, t: (key: string, options?: Record<string, unknown>) => string) {
  if (!version?.version) {
    return fallbackText(t, 'shell.versionUnavailable', 'Version unavailable');
  }
  return `${version.version} · ${channelLabel(version.channel, t)}`;
}

function fallbackText(t: (key: string, options?: Record<string, unknown>) => string, key: string, fallback: string) {
  const value = t(key);
  return value === key ? fallback : value;
}

function currentAccount() {
  const token = localStorage.getItem('cheesewaf-token') ?? '';
  const fallback = { username: '', role: '' };
  const payload = token.split('.')[1];
  if (!payload) {
    return fallback;
  }
  try {
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='))) as { username?: string; role?: string };
    return {
      username: decoded.username || fallback.username,
      role: decoded.role || fallback.role,
    };
  } catch {
    return fallback;
  }
}
