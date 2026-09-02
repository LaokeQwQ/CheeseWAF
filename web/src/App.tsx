import { useEffect } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider, Toaster } from '@/components/ui';
import AppRoutes from './routes';
import i18n, { ensureLanguage } from './i18n';
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
    // Only the default locale ships in the entry chunk, so a non-default
    // language has to be fetched before switching. Without this await i18next
    // renders raw keys (e.g. "common.save") for a bundle that has not arrived.
    let cancelled = false;
    void (async () => {
      await ensureLanguage(language);
      if (cancelled) {
        return;
      }
      await i18n.changeLanguage(language);
      document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
    })();
    return () => {
      cancelled = true;
    };
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
