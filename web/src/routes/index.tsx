import { AnimatePresence, motion } from 'framer-motion';
import type { ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { pageVariants } from '../animations/variants';
import MainLayout from '../layouts/MainLayout';
import AIPage from '../pages/AI/AIPage';
import AttackMapPage from '../pages/AttackMap/AttackMapPage';
import BlockPagesPage from '../pages/BlockPages/BlockPagesPage';
import DashboardPage from '../pages/Dashboard/DashboardPage';
import EdgePage from '../pages/Edge/EdgePage';
import IPManagePage from '../pages/IPManage/IPManagePage';
import LogsPage from '../pages/Logs/LogsPage';
import OperationsPage from '../pages/Operations/OperationsPage';
import ProtectionPage from '../pages/Protection/ProtectionPage';
import RulesPage from '../pages/Rules/RulesPage';
import LoginPage from '../pages/Login/LoginPage';
import SetupPage from '../pages/Setup/SetupPage';
import SitesPage from '../pages/Sites/SitesPage';
import SystemPage from '../pages/System/SystemPage';

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

export default function AppRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route element={<MainLayout />}>
          <Route index element={<Page><DashboardPage /></Page>} />
          <Route path="sites" element={<Page><SitesPage /></Page>} />
          <Route path="rules" element={<Page><RulesPage /></Page>} />
          <Route path="logs" element={<Page><LogsPage /></Page>} />
          <Route path="ip" element={<Page><IPManagePage /></Page>} />
          <Route path="protection" element={<Page><ProtectionPage /></Page>} />
          <Route path="edge" element={<Page><EdgePage /></Page>} />
          <Route path="ai" element={<Page><AIPage /></Page>} />
          <Route path="ops" element={<Page><OperationsPage /></Page>} />
          <Route path="block-pages" element={<Page><BlockPagesPage /></Page>} />
          <Route path="attack-map" element={<Page><AttackMapPage /></Page>} />
          <Route path="system" element={<Page><SystemPage /></Page>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AnimatePresence>
  );
}
