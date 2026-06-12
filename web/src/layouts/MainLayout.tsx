import { useEffect, useRef, useState } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Button, Dropdown, Input, Menu, Popover, Select, Space, Tag, Tooltip } from '@arco-design/web-react';
import { motion } from 'framer-motion';
import {
  BrainCircuit,
  FileCode2,
  Bell,
  LogOut,
  Gauge,
  LineChart,
  Map,
  Globe2,
  Languages,
  LayoutDashboard,
  ListFilter,
  ListChecks,
  Menu as MenuIcon,
  Radar,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  CloudDownload,
  UserCog,
  UserRound,
  SunMoon,
} from 'lucide-react';
import i18n from '../i18n';
import { navItemMotion } from '../animations/micro';
import { fetchHealth, fetchMonitorSummary, logout } from '../api/client';
import AIAssistant from '../components/AIAssistant/AIAssistant';
import BrandLogo from '../components/BrandLogo';
import { useAppStore, type Language } from '../stores';
import { themeOptions, type ThemeName } from '../themes/tokens';
import { useQuery } from '@tanstack/react-query';

const navItems = [
  { key: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard },
  { key: '/sites', labelKey: 'nav.sites', icon: Globe2 },
  { key: '/rules', labelKey: 'nav.rules', icon: ListChecks },
  { key: '/logs', labelKey: 'nav.logs', icon: ListFilter },
  { key: '/ip', labelKey: 'nav.ip', icon: Shield },
  { key: '/protection', labelKey: 'nav.protection', icon: ShieldAlert },
  { key: '/edge', labelKey: 'nav.edge', icon: Gauge },
  { key: '/ai', labelKey: 'nav.ai', icon: BrainCircuit },
  { key: '/monitor', labelKey: 'nav.monitor', icon: LineChart },
  { key: '/apisec', labelKey: 'nav.apisec', icon: Radar },
  { key: '/users', labelKey: 'nav.users', icon: UserCog },
  { key: '/ops', labelKey: 'nav.ops', icon: Radar },
  { key: '/updates', labelKey: 'nav.updates', icon: CloudDownload },
  { key: '/block-pages', labelKey: 'nav.blockPages', icon: FileCode2 },
  { key: '/attack-map', labelKey: 'nav.attackMap', icon: Map },
  { key: '/system', labelKey: 'nav.system', icon: Settings },
];

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
  const { data: monitor } = useQuery({ queryKey: ['shell-monitor'], queryFn: fetchMonitorSummary, refetchInterval: 15_000, retry: false });
  const [healthFailures, setHealthFailures] = useState(0);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState(Date.now());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const heartbeatRefetching = useRef(false);
  const healthQuery = useQuery({
    queryKey: ['shell-health'],
    queryFn: fetchHealth,
    refetchInterval: healthFailures >= 5 ? false : healthFailures > 0 ? 10_000 : 1_000,
    retry: false,
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const account = currentAccount();
  const shellClassName = [
    sidebarCollapsed ? 'app-shell app-shell-collapsed' : 'app-shell',
    mobileNavOpen ? 'app-mobile-nav-open' : '',
  ].filter(Boolean).join(' ');

  useEffect(() => {
    i18n.changeLanguage(language);
  }, [language]);

  useEffect(() => {
    setNotificationsOpen(false);
    setMobileNavOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (healthQuery.isSuccess) {
      setHealthFailures(0);
      setLastHeartbeatAt(Date.now());
    }
    if (healthQuery.isError) {
      setHealthFailures((value) => Math.min(5, value + 1));
    }
  }, [healthQuery.isError, healthQuery.isSuccess, healthQuery.dataUpdatedAt, healthQuery.errorUpdatedAt]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (healthFailures >= 5 || heartbeatRefetching.current) {
        return;
      }
      if (Date.now() - lastHeartbeatAt <= 3_000) {
        return;
      }
      setHealthFailures((value) => Math.max(1, Math.min(5, value + 1)));
      heartbeatRefetching.current = true;
      void healthQuery.refetch().finally(() => {
        heartbeatRefetching.current = false;
      });
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [healthFailures, healthQuery, lastHeartbeatAt]);

  const currentKey = navItems.find((item) => (
    item.key === '/'
      ? location.pathname === '/'
      : location.pathname === item.key || location.pathname.startsWith(`${item.key}/`)
  ))?.key ?? '/';
  const snapshot = monitor?.snapshot;
  const connection = connectionState(healthFailures, healthQuery.data?.status, healthQuery.isFetching, lastHeartbeatAt);

  function reconnectHealth() {
    setHealthFailures(0);
    void healthQuery.refetch();
  }

  async function handleLogout() {
    try {
      await logout();
    } catch {
      // Local logout must still work if the session is already expired or the API is unreachable.
    } finally {
      localStorage.removeItem('cheesewaf-token');
      navigate('/login', { replace: true });
    }
  }

  return (
    <div className={shellClassName}>
      <aside className="app-sidebar">
        <div className="brand-row">
          <button className="brand-mark" type="button" onClick={() => navigate('/')}>
            <BrandLogo />
          </button>
          <div className="brand-copy">
            <strong>CheeseWAF</strong>
            <span>{t('shell.status')}</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="Primary">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentKey === item.key;
            return (
              <motion.button
                {...navItemMotion}
                key={item.key}
                type="button"
                className={active ? 'nav-item nav-item-active' : 'nav-item'}
                onClick={() => {
                  navigate(item.key);
                  setMobileNavOpen(false);
                }}
              >
                <Icon size={18} />
                <span>{t(item.labelKey)}</span>
              </motion.button>
            );
          })}
        </nav>

        <button className={`sidebar-status sidebar-status-${connection.state}`} type="button" onClick={reconnectHealth}>
          <span className="status-dot" />
          <div className="sidebar-status-copy">
            <strong>{t(connection.titleKey)}</strong>
            <span>{connectionDetail(connection.state, healthFailures, t)}</span>
          </div>
        </button>
      </aside>
      <button className="mobile-nav-backdrop" type="button" aria-label={t('common.close')} onClick={() => setMobileNavOpen(false)} />

      <div className="app-main">
        <header className="topbar">
          <Space className="topbar-left" size={10}>
            <Tooltip content="Menu">
              <Button
                className="icon-button"
                icon={<MenuIcon size={18} />}
                aria-expanded={mobileNavOpen}
                onClick={() => {
                  setSidebarCollapsed(!sidebarCollapsed);
                  setMobileNavOpen((open) => !open);
                }}
              />
            </Tooltip>
            <button className="topbar-mobile-brand" type="button" onClick={() => navigate('/')}>
              <BrandLogo />
            </button>
            <Input
              className="topbar-search"
              prefix={<Search size={16} />}
              placeholder={t('common.search')}
              allowClear
            />
            <Popover
              popupVisible={notificationsOpen}
              onVisibleChange={setNotificationsOpen}
              trigger="click"
              position="bottom"
              content={<NotificationPanel blocked={snapshot?.blocked ?? 0} requests={snapshot?.requests ?? 0} />}
            >
              <Button
                className={notificationsOpen ? 'icon-button notification-button notification-button-active' : 'icon-button notification-button'}
                icon={<Bell size={18} />}
                aria-label={t('shell.notifications')}
              />
            </Popover>
          </Space>

          <div className="topbar-right">
            <div className="topbar-actions">
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
        <AIAssistant />
      </div>
    </div>
  );
}

function NotificationPanel({ blocked, requests }: { blocked: number; requests: number }) {
  const { t } = useTranslation();
  return (
    <section className="notification-panel">
      <header>
        <strong>{t('shell.notifications')}</strong>
        <Tag color={blocked > 0 ? 'red' : 'green'}>{blocked > 0 ? t('common.blocked') : t('common.healthy')}</Tag>
      </header>
      <div>
        <span>{t('shell.attacks')}</span>
        <strong>{blocked}</strong>
      </div>
      <div>
        <span>{t('shell.requests')}</span>
        <strong>{requests}</strong>
      </div>
    </section>
  );
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

function currentAccount() {
  const token = localStorage.getItem('cheesewaf-token') ?? '';
  const fallback = { username: 'admin', role: 'admin' };
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
