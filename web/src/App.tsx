import { useEffect } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider, Toaster } from '@/components/ui';
import AppRoutes from './routes';
import i18n from './i18n';
import { applyTheme, loadThemeStyles } from './themes';
import { useAppStore } from './stores';
import { queryClient } from './queryClient';

export default function App() {
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);

  useEffect(() => {
    applyTheme(theme);
    void loadThemeStyles(theme);
  }, [theme]);

  useEffect(() => {
    void i18n.changeLanguage(language);
    document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
  }, [language]);

  return (
    <TooltipProvider delayDuration={200}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
        <Toaster richColors position="top-right" />
      </QueryClientProvider>
    </TooltipProvider>
  );
}
