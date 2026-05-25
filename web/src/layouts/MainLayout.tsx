import { useEffect } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Button, Dropdown, Input, Menu, Select, Space, Tag, Tooltip } from '@arco-design/web-react';
import { motion } from 'framer-motion';
import {
  Activity,
  BrainCircuit,
  FileCode2,
  Bell,
  Gauge,
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
  SlidersHorizontal,
  SunMoon,
} from 'lucide-react';
import i18n from '../i18n';
import { navItemMotion } from '../animations/micro';
import AIAssistant from '../components/AIAssistant/AIAssistant';
import { useAppStore, type Language } from '../stores';
import { themeOptions, type ThemeName } from '../themes/tokens';

const navItems = [
  { key: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard },
  { key: '/sites', labelKey: 'nav.sites', icon: Globe2 },
  { key: '/rules', labelKey: 'nav.rules', icon: ListChecks },
  { key: '/logs', labelKey: 'nav.logs', icon: ListFilter },
  { key: '/ip', labelKey: 'nav.ip', icon: Shield },
  { key: '/protection', labelKey: 'nav.protection', icon: ShieldAlert },
  { key: '/edge', labelKey: 'nav.edge', icon: Gauge },
  { key: '/ai', labelKey: 'nav.ai', icon: BrainCircuit },
  { key: '/ops', labelKey: 'nav.ops', icon: Radar },
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

  useEffect(() => {
    i18n.changeLanguage(language);
  }, [language]);

  const currentKey = navItems.find((item) => item.key === location.pathname)?.key ?? '/';

  return (
    <div className={sidebarCollapsed ? 'app-shell app-shell-collapsed' : 'app-shell'}>
      <aside className="app-sidebar">
        <div className="brand-row">
          <button className="brand-mark" type="button" onClick={() => navigate('/')}>
            CW
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
                onClick={() => navigate(item.key)}
              >
                <Icon size={18} />
                <span>{t(item.labelKey)}</span>
              </motion.button>
            );
          })}
        </nav>

        <div className="sidebar-status">
          <span className="status-dot" />
          <div>
            <strong>{t('common.healthy')}</strong>
            <span>127.0.0.1:9443</span>
          </div>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <Space size={10}>
            <Tooltip content="Menu">
              <Button
                className="icon-button"
                icon={<MenuIcon size={18} />}
                onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              />
            </Tooltip>
            <Input
              className="topbar-search"
              prefix={<Search size={16} />}
              placeholder={t('common.search')}
              allowClear
            />
          </Space>

          <Space size={10}>
            <Tag className="metric-chip" icon={<Activity size={14} />}>
              {t('shell.latency')} 3.8ms
            </Tag>
            <Tag className="metric-chip" icon={<SlidersHorizontal size={14} />}>
              {t('shell.requests')} 18.4k
            </Tag>
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
            <Dropdown
              droplist={
                <Menu>
                  <Menu.Item key="1">{t('shell.notifications')}</Menu.Item>
                  <Menu.Item key="2">{t('shell.admin')}</Menu.Item>
                </Menu>
              }
            >
              <Button className="icon-button" icon={<Bell size={18} />} />
            </Dropdown>
          </Space>
        </header>

        <main className="workspace">
          <Outlet />
        </main>
        <AIAssistant />
      </div>
    </div>
  );
}
