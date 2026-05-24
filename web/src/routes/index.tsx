import { AnimatePresence, motion } from 'framer-motion';
import type { ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { pageVariants } from '../animations/variants';
import MainLayout from '../layouts/MainLayout';
import DashboardPage from '../pages/Dashboard/DashboardPage';
import IPManagePage from '../pages/IPManage/IPManagePage';
import LogsPage from '../pages/Logs/LogsPage';
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
          <Route path="logs" element={<Page><LogsPage /></Page>} />
          <Route path="ip" element={<Page><IPManagePage /></Page>} />
          <Route path="system" element={<Page><SystemPage /></Page>} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AnimatePresence>
  );
}
