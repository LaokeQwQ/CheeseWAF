import { useEffect } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@appica/ui-react/providers/theme-provider';
import AppRoutes from './routes';
import i18n from './i18n';
import { applyTheme, loadThemeStyles } from './themes';
import { useAppStore } from './stores';
import { queryClient } from './queryClient';
import { ToastHost } from './ui';

function themeToMode(theme: string): 'light' | 'dark' | 'system' {
  const value = theme.toLowerCase();
  if (value.includes('dark') || value.includes('night') || value === 'obsidian') {
    return 'dark';
  }
  if (value === 'system' || value === 'auto') {
    return 'system';
  }
  return 'light';
}

export default function App() {
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const mode = themeToMode(theme);

  useEffect(() => {
    applyTheme(theme);
    void loadThemeStyles(theme);
  }, [theme]);

  useEffect(() => {
    void i18n.changeLanguage(language);
    document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
  }, [language]);

  return (
    <ThemeProvider defaultTheme={mode} enableSystem disableTransitionOnChange storageKey="cheesewaf-appica-theme">
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AppRoutes />
          <ToastHost />
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
