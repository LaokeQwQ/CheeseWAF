import { useEffect, useMemo } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import ConfigProvider from '@arco-design/web-react/es/ConfigProvider';
import enUS from '@arco-design/web-react/es/locale/en-US';
import zhCN from '@arco-design/web-react/es/locale/zh-CN';
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
