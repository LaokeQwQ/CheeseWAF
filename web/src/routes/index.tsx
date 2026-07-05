import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppErrorBoundary } from '../components/AppErrorBoundary';
import MainLayout from '../layouts/MainLayout';
import { preloadAIPage, preloadAPISecurityPage } from './preload';

const AIPage = lazy(preloadAIPage);
const APISecurityPage = lazy(preloadAPISecurityPage);
const AttackMapPage = lazy(() => import('../pages/AttackMap/AttackMapPage'));
const AttackScreenPage = lazy(() => import('../pages/AttackMap/AttackScreenPage'));
const BlockPagesPage = lazy(() => import('../pages/BlockPages/BlockPagesPage'));
const BlockPagePreviewWindow = lazy(() => import('../pages/BlockPages/BlockPagesPage').then((module) => ({ default: module.BlockPagePreviewWindow })));
const DashboardPage = lazy(() => import('../pages/Dashboard/DashboardPage'));
const EdgePage = lazy(() => import('../pages/Edge/EdgePage'));
const IPManagePage = lazy(() => import('../pages/IPManage/IPManagePage'));
const LogDetailPage = lazy(() => import('../pages/Logs/LogDetailPage'));
const LogsPage = lazy(() => import('../pages/Logs/LogsPage'));
const LoginPage = lazy(() => import('../pages/Login/LoginPage'));
const MonitorPage = lazy(() => import('../pages/Monitor/MonitorPage'));
const OperationsPage = lazy(() => import('../pages/Operations/OperationsPage'));
const ProtectionPage = lazy(() => import('../pages/Protection/ProtectionPage'));
const RulesPage = lazy(() => import('../pages/Rules/RulesPage'));
const SetupPage = lazy(() => import('../pages/Setup/SetupPage'));
const SiteDetailPage = lazy(() => import('../pages/Sites/SiteDetailPage'));
const SitesPage = lazy(() => import('../pages/Sites/SitesPage'));
const SSLPage = lazy(() => import('../pages/SSL/SSLPage'));
const SystemPage = lazy(() => import('../pages/System/SystemPage'));
const UpdatesPage = lazy(() => import('../pages/Updates/UpdatesPage'));
const UsersPage = lazy(() => import('../pages/Users/UsersPage'));

function Page({ children }: { children: ReactNode }) {
  return (
    <div className="page-motion">
      {children}
    </div>
  );
}

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<div className="page-spinner" aria-label="Loading" aria-busy="true" />}>{children}</Suspense>;
}

function ProtectedLayout() {
  const location = useLocation();
  const token = localStorage.getItem('cheesewaf-token');
  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <MainLayout />;
}

function ProtectedStandalone({ children }: { children: ReactNode }) {
  const location = useLocation();
  const token = localStorage.getItem('cheesewaf-token');
  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

export default function AppRoutes() {
  const location = useLocation();

  return (
    <AppErrorBoundary resetKey={location.pathname}>
      <Routes location={location}>
        <Route path="/login" element={<LazyPage><LoginPage /></LazyPage>} />
        <Route path="/setup" element={<LazyPage><SetupPage /></LazyPage>} />
        <Route path="/attack-map/screen" element={<ProtectedStandalone><LazyPage><AttackScreenPage /></LazyPage></ProtectedStandalone>} />
        <Route path="/block-pages/preview" element={<ProtectedStandalone><LazyPage><BlockPagePreviewWindow /></LazyPage></ProtectedStandalone>} />
        <Route element={<ProtectedLayout />}>
          <Route index element={<Page><LazyPage><DashboardPage /></LazyPage></Page>} />
          <Route path="sites" element={<Page><LazyPage><SitesPage /></LazyPage></Page>} />
          <Route path="sites/:id" element={<Page><LazyPage><SiteDetailPage /></LazyPage></Page>} />
          <Route path="ssl" element={<Page><LazyPage><SSLPage /></LazyPage></Page>} />
          <Route path="rules" element={<Page><LazyPage><RulesPage /></LazyPage></Page>} />
          <Route path="logs" element={<Page><LazyPage><LogsPage /></LazyPage></Page>} />
          <Route path="logs/:traceId" element={<Page><LazyPage><LogDetailPage /></LazyPage></Page>} />
          <Route path="ip" element={<Page><LazyPage><IPManagePage /></LazyPage></Page>} />
          <Route path="protection" element={<Page><LazyPage><ProtectionPage /></LazyPage></Page>} />
          <Route path="edge" element={<Page><LazyPage><EdgePage /></LazyPage></Page>} />
          <Route path="ai" element={<Page><LazyPage><AIPage /></LazyPage></Page>} />
          <Route path="monitor" element={<Page><LazyPage><MonitorPage /></LazyPage></Page>} />
          <Route path="apisec" element={<Page><LazyPage><APISecurityPage /></LazyPage></Page>} />
          <Route path="users" element={<Page><LazyPage><UsersPage /></LazyPage></Page>} />
          <Route path="ops" element={<Page><LazyPage><OperationsPage /></LazyPage></Page>} />
          <Route path="updates" element={<Page><LazyPage><UpdatesPage /></LazyPage></Page>} />
          <Route path="block-pages" element={<Page><LazyPage><BlockPagesPage /></LazyPage></Page>} />
          <Route path="attack-map" element={<Page><LazyPage><AttackMapPage /></LazyPage></Page>} />
          <Route path="system" element={<Page><LazyPage><SystemPage /></LazyPage></Page>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppErrorBoundary>
  );
}
