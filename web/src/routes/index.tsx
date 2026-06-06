import { AnimatePresence, motion } from 'framer-motion';
import { lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { pageVariants } from '../animations/variants';
import MainLayout from '../layouts/MainLayout';
import AIPage from '../pages/AI/AIPage';
import APISecurityPage from '../pages/APISecurity/APISecurityPage';
import BlockPagesPage from '../pages/BlockPages/BlockPagesPage';
import DashboardPage from '../pages/Dashboard/DashboardPage';
import EdgePage from '../pages/Edge/EdgePage';
import IPManagePage from '../pages/IPManage/IPManagePage';
import LogsPage from '../pages/Logs/LogsPage';
import MonitorPage from '../pages/Monitor/MonitorPage';
import OperationsPage from '../pages/Operations/OperationsPage';
import ProtectionPage from '../pages/Protection/ProtectionPage';
import RulesPage from '../pages/Rules/RulesPage';
import LoginPage from '../pages/Login/LoginPage';
import SetupPage from '../pages/Setup/SetupPage';
import SiteDetailPage from '../pages/Sites/SiteDetailPage';
import SitesPage from '../pages/Sites/SitesPage';
import SystemPage from '../pages/System/SystemPage';
import UsersPage from '../pages/Users/UsersPage';
import UpdatesPage from '../pages/Updates/UpdatesPage';

const AttackMapPage = lazy(() => import('../pages/AttackMap/AttackMapPage'));

function Page({ children }: { children: ReactNode }) {
  return (
    <motion.div
      variants={pageVariants}
      initial="initial"
      animate="enter"
      exit="exit"
      className="page-motion"
    >
      {children}
    </motion.div>
  );
}

function LazyPage({ children }: { children: ReactNode }) {
  return <Suspense fallback={<div className="page-spinner">Loading</div>}>{children}</Suspense>;
}

function ProtectedLayout() {
  const location = useLocation();
  const token = localStorage.getItem('cheesewaf-token');
  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <MainLayout />;
}

export default function AppRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route element={<ProtectedLayout />}>
          <Route index element={<Page><DashboardPage /></Page>} />
          <Route path="sites" element={<Page><SitesPage /></Page>} />
          <Route path="sites/:id" element={<Page><SiteDetailPage /></Page>} />
          <Route path="rules" element={<Page><RulesPage /></Page>} />
          <Route path="logs" element={<Page><LogsPage /></Page>} />
          <Route path="ip" element={<Page><IPManagePage /></Page>} />
          <Route path="protection" element={<Page><ProtectionPage /></Page>} />
          <Route path="edge" element={<Page><EdgePage /></Page>} />
          <Route path="ai" element={<Page><AIPage /></Page>} />
          <Route path="monitor" element={<Page><MonitorPage /></Page>} />
          <Route path="apisec" element={<Page><APISecurityPage /></Page>} />
          <Route path="users" element={<Page><UsersPage /></Page>} />
          <Route path="ops" element={<Page><OperationsPage /></Page>} />
          <Route path="updates" element={<Page><UpdatesPage /></Page>} />
          <Route path="block-pages" element={<Page><BlockPagesPage /></Page>} />
          <Route path="attack-map" element={<Page><LazyPage><AttackMapPage /></LazyPage></Page>} />
          <Route path="system" element={<Page><SystemPage /></Page>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AnimatePresence>
  );
}
