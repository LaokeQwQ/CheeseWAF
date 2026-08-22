import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  toast,
} from '@/components/ui';
import '../styles/console-layout-hardening.css';
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
  ClipboardList,
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
  X,
  ChevronLeft,
  ChevronRight,
  type LucideIcon,
} from 'lucide-react';
import i18n from '../i18n';
import { clearNotifications, fetchAuditEntries, fetchHealth, fetchLogs, fetchNotifications, fetchUsers, fetchVersion, isSessionInvalidAuthFailure, logout, markAllNotificationsRead as markAllNotificationsReadAPI, sanitizeInternalReturnPath, updateNotification } from '../api/client';
import AIAssistantEntry from '../components/AIAssistant/AIAssistantEntry';
import BrandLogo from '../components/BrandLogo';
import { useAppStore, type Language } from '../stores';
import { themeOptions, type ThemeName } from '../themes/tokens';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePageVisibility, usePollingVisibility } from '../hooks/usePollingVisibility';
import type { AuditEntry, LogEntry, Notification, NotificationFilter, User } from '../types/api';
import { displayAction } from '../utils/display';
import { preloadRoute } from '../routes/preload';
import { currentAccount, filterNavigation, hasScope, type AccountProfile } from '../authProfile';
import { subscribeRealtimeEvents } from '../api/realtime';

type NavItem = { key: string; labelKey: string; icon: LucideIcon; requiredScopes: string[] };
type NavGroup = { labelKey: string; items: NavItem[] };

const navGroups: NavGroup[] = [
  {
    labelKey: 'navGroup.posture',
    items: [
      { key: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard, requiredScopes: ['read:monitor'] },
      { key: '/monitor', labelKey: 'nav.monitor', icon: LineChart, requiredScopes: ['read:monitor'] },
      { key: '/attack-map', labelKey: 'nav.attackMap', icon: Map, requiredScopes: ['read:logs'] },
    ],
  },
  {
    labelKey: 'navGroup.security',
    items: [
      { key: '/sites', labelKey: 'nav.sites', icon: Globe2, requiredScopes: ['read:sites'] },
      { key: '/ssl', labelKey: 'nav.ssl', icon: LockKeyhole, requiredScopes: ['read:system'] },
      { key: '/rules', labelKey: 'nav.rules', icon: ListChecks, requiredScopes: ['read:rules'] },
      { key: '/review', labelKey: 'nav.review', icon: ClipboardList, requiredScopes: ['read:logs'] },
      { key: '/logs', labelKey: 'nav.logs', icon: ListFilter, requiredScopes: ['read:logs'] },
      { key: '/ip', labelKey: 'nav.ip', icon: Shield, requiredScopes: ['read:protection'] },
      { key: '/protection', labelKey: 'nav.protection', icon: ShieldAlert, requiredScopes: ['read:protection'] },
      { key: '/bot-challenge', labelKey: 'nav.botChallenge', icon: Bot, requiredScopes: ['read:protection'] },
      { key: '/apisec', labelKey: 'nav.apisec', icon: Radar, requiredScopes: ['read:apisec'] },
      { key: '/ai', labelKey: 'nav.ai', icon: BrainCircuit, requiredScopes: ['read:ai', 'use:ai', 'write:ai', 'approve:ai'] },
    ],
  },
  {
    labelKey: 'navGroup.platform',
    items: [
      { key: '/edge', labelKey: 'nav.edge', icon: Gauge, requiredScopes: ['read:edge'] },
      { key: '/block-pages', labelKey: 'nav.blockPages', icon: FileCode2, requiredScopes: ['read:system'] },
      { key: '/users', labelKey: 'nav.users', icon: UserCog, requiredScopes: ['read:users'] },
      { key: '/ops', labelKey: 'nav.ops', icon: Radar, requiredScopes: ['read:ops'] },
      { key: '/updates', labelKey: 'nav.updates', icon: CloudDownload, requiredScopes: ['read:system'] },
      { key: '/cluster', labelKey: 'nav.cluster', icon: Network, requiredScopes: ['read:cluster'] },
      { key: '/system', labelKey: 'nav.system', icon: Settings, requiredScopes: ['read:system'] },
    ],
  },
];

const allNavItems = navGroups.flatMap((group) => group.items);

export function navigationForAccount(account: AccountProfile) {
  return filterNavigation(navGroups, account);
}

export function shellCapabilities(account: AccountProfile) {
  return {
    version: hasScope(account, 'read:system'),
    recentLogs: hasScope(account, 'read:logs'),
    audit: hasScope(account, 'read:audit'),
    users: hasScope(account, 'read:users'),
    notifications: hasScope(account, 'read:monitor'),
    realtime: hasScope(account, 'read:realtime'),
  };
}

export function realtimeQueryKeys(messageType: string): ReadonlyArray<readonly unknown[]> {
  switch (messageType) {
    case 'stats':
      return [['monitor-summary'], ['monitor'], ['attack-screen-monitor']];
    case 'alert':
      return [['notifications']];
    case 'approval':
      return [['assistant-approvals']];
    case 'ai_stream':
      return [['ai-events'], ['assistant-approvals']];
    case 'log':
      return [
        ['recent-security-logs'],
        ['dashboard-period-logs'],
        ['dashboard-live-logs'],
        ['logs'],
        ['attack-map-logs'],
        ['attack-screen-logs'],
      ];
    default:
      return [];
  }
}

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
  const account = useMemo(() => currentAccount(), []);
  const shellAccess = useMemo(() => shellCapabilities(account), [account]);
  const [realtimeConnected, setRealtimeConnected] = useState(false);
  const recentLogsRefetchInterval = usePollingVisibility(realtimeConnected ? 2 * 60_000 : 30_000);
  const auditEntriesRefetchInterval = usePollingVisibility(60_000);
  const { data: version } = useQuery({ queryKey: ['version'], queryFn: fetchVersion, staleTime: 5 * 60_000, retry: false, enabled: shellAccess.version });
  const { data: recentLogs } = useQuery({ queryKey: ['recent-security-logs', 12], queryFn: () => fetchLogs({ limit: 12 }), refetchInterval: recentLogsRefetchInterval, staleTime: 20_000, retry: false, enabled: shellAccess.recentLogs });
  const { data: auditEntries } = useQuery({ queryKey: ['shell-audit'], queryFn: fetchAuditEntries, staleTime: 30_000, refetchInterval: auditEntriesRefetchInterval, retry: false, enabled: shellAccess.audit });
  const { data: users } = useQuery({ queryKey: ['shell-users'], queryFn: fetchUsers, staleTime: 60_000, retry: false, enabled: shellAccess.users });
  const [healthFailures, setHealthFailures] = useState(0);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState(Date.now());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const heartbeatRefetching = useRef(false);
  const healthRefetchInterval = usePollingVisibility(healthFailures >= 5 ? false : healthFailures > 0 ? 10_000 : 15_000);
  const healthQuery = useQuery({
    queryKey: ['shell-health'],
    queryFn: fetchHealth,
    // Healthy consoles do not need 1s polling — keep light contact and back off on failures.
    refetchInterval: healthRefetchInterval,
    retry: false,
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationFilter, setNotificationFilter] = useState<NotificationFilter>('all');
  const [notificationPage, setNotificationPage] = useState(1);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const [searchHighlight, setSearchHighlight] = useState(0);
  const [clearConfirmOpen, setClearConfirmOpen] = useState(false);
  const notificationShellRef = useRef<HTMLDivElement | null>(null);
  const notificationTriggerRef = useRef<HTMLSpanElement | null>(null);
  const searchBlurTimerRef = useRef<number | null>(null);
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({});
  const shellClassName = [
    sidebarCollapsed ? 'app-shell app-shell-collapsed' : 'app-shell',
    mobileNavOpen ? 'app-mobile-nav-open' : '',
  ].filter(Boolean).join(' ');
  const allowedNavGroups = useMemo(() => navigationForAccount(account), [account]);
  const allowedNavItems = useMemo(() => allowedNavGroups.flatMap((group) => group.items), [allowedNavGroups]);

  useEffect(() => {
    if (!shellAccess.realtime) {
      setRealtimeConnected(false);
      return undefined;
    }
    return subscribeRealtimeEvents({
      onConnectionChange: setRealtimeConnected,
      onEvent: (message) => {
        for (const queryKey of realtimeQueryKeys(message.type)) {
          void queryClient.invalidateQueries({ queryKey });
        }
      },
    }).close;
  }, [queryClient, shellAccess.realtime]);

  useEffect(() => {
    setNotificationsOpen(false);
    setMobileNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!notificationsOpen) {
      return undefined;
    }
    const panel = notificationShellRef.current?.querySelector<HTMLElement>('#cheesewaf-notification-panel');
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusable = panel?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    focusable?.[0]?.focus();
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
    const trapFocus = (event: KeyboardEvent) => {
      if (event.key !== 'Tab' || !panel || !focusable || focusable.length === 0) {
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('pointerdown', closeFromOutside, { capture: true });
    window.addEventListener('keydown', closeFromEscape);
    window.addEventListener('keydown', trapFocus);
    return () => {
      window.removeEventListener('pointerdown', closeFromOutside, { capture: true });
      window.removeEventListener('keydown', closeFromEscape);
      window.removeEventListener('keydown', trapFocus);
      if (previousFocus && document.contains(previousFocus)) {
        previousFocus.focus();
      } else {
        notificationTriggerRef.current?.querySelector<HTMLElement>('button')?.focus();
      }
    };
  }, [notificationsOpen]);

  useEffect(() => () => {
    if (searchBlurTimerRef.current != null) {
      window.clearTimeout(searchBlurTimerRef.current);
      searchBlurTimerRef.current = null;
    }
  }, []);

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
  const pageVisible = usePageVisibility();
  useEffect(() => {
    if (!pageVisible) {
      return undefined;
    }
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
  }, [healthFailures, healthRefetch, lastHeartbeatAt, pageVisible]);

  const currentKey = allowedNavItems.find((item) => (
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
  const notificationsRefreshInterval = usePollingVisibility(realtimeConnected ? 60_000 : 15_000);
  const notificationQuery = useQuery({
    queryKey: ['notifications', notificationFilter, notificationPage],
    queryFn: () => fetchNotifications({ page: notificationPage, limit: notificationLimit, filter: notificationFilter }),
    refetchInterval: notificationsRefreshInterval,
    staleTime: 10_000,
    retry: false,
    placeholderData: (previous) => previous,
    enabled: shellAccess.notifications,
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
    onError: (error) => toast.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const markAllReadMutation = useMutation({
    mutationFn: markAllNotificationsReadAPI,
    onSuccess: () => {
      setNotificationPage(1);
      void refreshNotifications();
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const clearNotificationsMutation = useMutation({
    mutationFn: clearNotifications,
    onSuccess: () => {
      setNotificationPage(1);
      void refreshNotifications();
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : t('shell.notificationUpdateFailed')),
  });
  const searchResults = useMemo(
    () => buildSearchResults(searchValue, recentLogItems, auditItems, userItems, t, allowedNavItems),
    [allowedNavItems, auditItems, recentLogItems, searchValue, t, userItems],
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
    setClearConfirmOpen(true);
  }

  async function confirmClearNotifications() {
    try {
      await clearNotificationsMutation.mutateAsync();
      setClearConfirmOpen(false);
    } catch {
      // Error already toasted via mutation onError.
    }
  }

  function toggleNotificationPin(item: Notification) {
    notificationMutation.mutate({ id: item.id, patch: { pinned: !item.pinned } });
  }

  async function handleLogout() {
    try {
      await logout();
      queryClient.clear();
      navigate('/login', { replace: true });
    } catch (err) {
      if (isSessionInvalidAuthFailure(err)) {
        queryClient.clear();
        navigate('/login', { replace: true });
      } else {
        toast.error(err instanceof Error ? err.message : t('common.requestFailed'));
      }
    }
  }

  const sidebarToggleLabel = mobileNavOpen
    ? t('shell.closeSidebar')
    : sidebarCollapsed
      ? t('shell.expandSidebar')
      : t('shell.collapseSidebar');

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

        <nav className="nav-list" aria-label={t('common.primaryNav')}>
          {allowedNavGroups.map((group) => {
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
          <Tooltip>
            <TooltipTrigger asChild>
              <button className="sidebar-version" type="button" onClick={() => navigate('/updates')}>
                <span>CheeseWAF</span>
                <strong>{versionLabel(version, t)}</strong>
              </button>
            </TooltipTrigger>
            <TooltipContent>{versionTooltip(version, t)}</TooltipContent>
          </Tooltip>
        </div>
      </aside>
      <button
        className="mobile-nav-backdrop"
        type="button"
        aria-label={t('common.close')}
        aria-hidden={!mobileNavOpen}
        tabIndex={mobileNavOpen ? 0 : -1}
        onClick={() => setMobileNavOpen(false)}
      />

      <div className="app-main">
        <header className="topbar">
          <div className="topbar-left gap-2.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  className="icon-button"
                  size="icon"
                  variant="outline"
                  aria-expanded={mobileNavOpen}
                  aria-label={sidebarToggleLabel}
                  onClick={() => {
                    if (window.matchMedia('(max-width: 1024px)').matches) {
                      setMobileNavOpen((open) => !open);
                      return;
                    }
                    setSidebarCollapsed(!sidebarCollapsed);
                  }}
                >
                  <MenuIcon size={18} />
                </Button>
              </TooltipTrigger>
              <TooltipContent>{sidebarToggleLabel}</TooltipContent>
            </Tooltip>
            <button className="topbar-mobile-brand" type="button" aria-label={t('common.home')} onClick={() => navigate('/')}>
              <BrandLogo />
            </button>
            <div className="topbar-search relative">
              <Search
                size={16}
                className="pointer-events-none absolute left-3 top-1/2 z-[1] -translate-y-1/2 text-muted-foreground"
                aria-hidden
              />
              <Input
                className="pl-9 pr-8"
                placeholder={t('common.search')}
                aria-label={t('common.search')}
                aria-controls={searchOpen ? 'cheesewaf-search-results' : undefined}
                aria-expanded={searchOpen}
                value={searchValue}
                onChange={(event) => {
                  const value = event.target.value;
                  setSearchValue(value);
                  setSearchHighlight(0);
                  setSearchOpen(Boolean(String(value).trim()));
                }}
                onFocus={() => {
                  if (searchBlurTimerRef.current != null) {
                    window.clearTimeout(searchBlurTimerRef.current);
                    searchBlurTimerRef.current = null;
                  }
                  setSearchOpen(Boolean(searchValue.trim()));
                }}
                onBlur={() => {
                  if (searchBlurTimerRef.current != null) {
                    window.clearTimeout(searchBlurTimerRef.current);
                  }
                  searchBlurTimerRef.current = window.setTimeout(() => {
                    searchBlurTimerRef.current = null;
                    setSearchOpen(false);
                  }, 120);
                }}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    const target = searchResults[searchHighlight] ?? searchResults[0];
                    if (target) {
                      event.preventDefault();
                      navigate(target.to);
                      setSearchOpen(false);
                      setSearchValue('');
                    }
                    return;
                  }
                  if (!searchOpen || searchResults.length === 0) {
                    return;
                  }
                  if (event.key === 'ArrowDown') {
                    event.preventDefault();
                    setSearchHighlight((current) => (current + 1) % searchResults.length);
                  } else if (event.key === 'ArrowUp') {
                    event.preventDefault();
                    setSearchHighlight((current) => (current - 1 + searchResults.length) % searchResults.length);
                  }
                }}
              />
              {searchValue ? (
                <button
                  type="button"
                  className="absolute right-2 top-1/2 z-[1] inline-flex size-5 -translate-y-1/2 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground"
                  aria-label={t('common.reset')}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => {
                    setSearchValue('');
                    setSearchHighlight(0);
                    setSearchOpen(false);
                  }}
                >
                  <X size={14} />
                </button>
              ) : null}
            </div>
            {searchOpen && (
              <div className="topbar-search-panel" role="listbox" id="cheesewaf-search-results">
                {searchResults.length === 0 ? (
                  <div className="topbar-search-empty">{t('shell.searchEmpty')}</div>
                ) : searchResults.map((item, index) => (
                  <button
                    key={item.key}
                    type="button"
                    role="option"
                    aria-selected={index === searchHighlight}
                    className={index === searchHighlight ? 'topbar-search-result topbar-search-result-active' : 'topbar-search-result'}
                    onMouseDown={(event) => event.preventDefault()}
                    onMouseEnter={() => setSearchHighlight(index)}
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
          </div>

          <div className="topbar-right">
            <div className="topbar-actions">
              <div className="notification-shell" ref={notificationShellRef}>
                <span className="notification-trigger" ref={notificationTriggerRef}>
                  <Button
                    className={notificationsOpen ? 'icon-button notification-button notification-button-active' : 'icon-button notification-button'}
                    size="icon"
                    variant="outline"
                    aria-label={t('shell.notifications')}
                    aria-expanded={notificationsOpen}
                    aria-haspopup="dialog"
                    aria-controls="cheesewaf-notification-panel"
                    onClick={() => {
                      setSearchOpen(false);
                      setNotificationsOpen((open) => !open);
                    }}
                  >
                    <Bell size={18} />
                  </Button>
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
                    busy={notificationMutation.isPending}
                    markAllBusy={markAllReadMutation.isPending}
                    clearBusy={clearNotificationsMutation.isPending}
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
              <Select value={theme} onValueChange={(value) => setTheme(value as ThemeName)}>
                <SelectTrigger className="topbar-select" aria-label={t('system.theme')}>
                  <span className="flex min-w-0 items-center gap-1.5">
                    <SunMoon size={15} className="shrink-0" />
                    <SelectValue />
                  </span>
                </SelectTrigger>
                <SelectContent>
                  {themeOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {t(option.labelKey)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
                <SelectTrigger className="language-select" aria-label={t('system.language')}>
                  <span className="flex min-w-0 items-center gap-1.5">
                    <Languages size={15} className="shrink-0" />
                    <SelectValue />
                  </span>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="zh-CN">中文</SelectItem>
                  <SelectItem value="en-US">English</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="account-button" type="button">
                  <UserRound size={16} />
                  <span>{account.username}</span>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigate('/users')}>
                  <UserCog size={14} />
                  {t('shell.admin')}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => void handleLogout()}>
                  <LogOut size={14} />
                  {t('common.logout')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="workspace">
          <Outlet />
        </main>
        {showGlobalAssistant && <AIAssistantEntry />}
      </div>

      <Dialog open={clearConfirmOpen} onOpenChange={setClearConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('shell.clearNotificationsConfirmTitle')}</DialogTitle>
            <DialogDescription>{t('shell.clearNotificationsConfirmContent')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setClearConfirmOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="destructive"
              loading={clearNotificationsMutation.isPending}
              onClick={() => void confirmClearNotifications()}
            >
              {t('common.confirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
  markAllBusy = false,
  clearBusy = false,
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
  markAllBusy?: boolean;
  clearBusy?: boolean;
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
  const anyBusy = busy || markAllBusy || clearBusy;
  const pageCount = Math.max(1, Math.ceil(filteredTotal / pageSize));
  return (
    <section
      id="cheesewaf-notification-panel"
      className="notification-panel"
      role="dialog"
      aria-modal="true"
      aria-label={t('shell.notifications')}
    >
      <header>
        <strong>{t('shell.notifications')}</strong>
        <Badge variant={unread > 0 ? 'warning' : 'success'}>
          {total ? t('shell.notificationPanelSummary', { unread, total }) : t('common.healthy')}
        </Badge>
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
          <Button size="sm" loading={markAllBusy} disabled={unread === 0 || anyBusy} onClick={onMarkAllRead}>
            {t('shell.markAllRead')}
          </Button>
          <Button size="sm" variant="outline" loading={clearBusy} disabled={total === 0 || anyBusy} onClick={onClearAll}>
            {t('shell.clearAllNotifications')}
          </Button>
        </div>
      )}
      <div className="notification-list">
        {error ? (
          <div className="notification-empty">
            <span>{t('shell.notificationLoadFailed')}</span>
            <Button size="sm" onClick={onRetry}>{t('common.retry')}</Button>
          </div>
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
                {item.pinned && <Badge variant="default" className="ml-1">{t('shell.pinnedNotification')}</Badge>}
              </span>
              <strong>{item.message}</strong>
              <em><Clock3 size={12} /> {formatRelativeTime(item.created_at, i18n.resolvedLanguage || undefined)}</em>
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
        <div className="flex items-center justify-end gap-2">
          <Button
            size="sm"
            variant="outline"
            disabled={page <= 1}
            aria-label={t('common.back')}
            onClick={() => onPageChange(page - 1)}
          >
            <ChevronLeft size={14} />
          </Button>
          <span className="text-xs text-muted-foreground">
            {page} / {pageCount}
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={page >= pageCount}
            aria-label={t('common.next')}
            onClick={() => onPageChange(page + 1)}
          >
            <ChevronRight size={14} />
          </Button>
        </div>
      )}
    </section>
  );
}

type KeyedNotification = { item: Notification; notificationKey: string };

export function withStableNotificationKeys(items: readonly Notification[]): KeyedNotification[] {
  const occurrences = new globalThis.Map<string, number>();
  return items.map((item) => {
    const base = String(item.id || `${item.created_at}:${item.title}:${item.message}`).trim() || 'notification';
    const occurrence = (occurrences.get(base) ?? 0) + 1;
    occurrences.set(base, occurrence);
    return { item, notificationKey: occurrence === 1 ? base : `${base}#${occurrence}` };
  });
}

type SearchResult = {
  key: string;
  type: string;
  title: string;
  subtitle: string;
  to: string;
};

export function buildSearchResults(query: string, logs: LogEntry[], audits: AuditEntry[], users: User[], t: (key: string, options?: Record<string, unknown>) => string, navigation: readonly NavItem[] = allNavItems): SearchResult[] {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return [];
  }
  const results: SearchResult[] = [];
  for (const item of navigation) {
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

function formatRelativeTime(value: string, locale?: string) {
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
  return date.toLocaleString(locale);
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
