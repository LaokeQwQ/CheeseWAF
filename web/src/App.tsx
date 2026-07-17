import { useEffect, useMemo } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ConfigProvider from '@arco-design/web-react/es/ConfigProvider';
import enUS from '@arco-design/web-react/es/locale/en-US';
import zhCN from '@arco-design/web-react/es/locale/zh-CN';
import AppRoutes from './routes';
import { applyTheme } from './themes';
import { useAppStore } from './stores';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      refetchIntervalInBackground: false,
      staleTime: 30_000,
      gcTime: 10 * 60_000,
      placeholderData: (previousData: unknown) => previousData,
    },
  },
});

export default function App() {
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
  }, [language]);

  const locale = useMemo(() => (language === 'zh-CN' ? zhCN : enUS), [language]);

  return (
    <ConfigProvider locale={locale} getPopupContainer={() => document.body}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </QueryClientProvider>
    </ConfigProvider>
  );
}
