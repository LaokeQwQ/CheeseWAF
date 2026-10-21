import { useEffect, useRef } from 'react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider, Toaster } from '@/components/ui';
import AppRoutes from './routes';
import i18n, { ensureLanguage } from './i18n';
import { applyTheme, loadThemeStyles } from './themes';
import { useAppStore } from './stores';
import { queryClient } from './queryClient';

const LANGUAGE_TRANSITION_DURATION_MS = 320;
const LANGUAGE_TRANSITION_EXIT_MS = 90;

export default function App() {
  const theme = useAppStore((state) => state.theme);
  const language = useAppStore((state) => state.language);
  const hasAppliedThemeRef = useRef(false);
  const hasAppliedLanguageRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    let requestSequence = 0;
    const applyWhenLoaded = async (nextTheme: typeof theme) => {
      const sequence = ++requestSequence;
      try {
        await loadThemeStyles(nextTheme);
      } catch {
        return;
      }
      if (cancelled || sequence !== requestSequence) return;
      applyTheme(nextTheme, hasAppliedThemeRef.current);
      hasAppliedThemeRef.current = true;
    };

    void applyWhenLoaded(theme);

    if (theme !== 'system' || typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return () => { cancelled = true; };
    }
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => { void applyWhenLoaded('system'); };
    media.addEventListener?.('change', handleChange);
    return () => {
      cancelled = true;
      media.removeEventListener?.('change', handleChange);
    };
  }, [theme]);

  useEffect(() => {
    // Only the default locale ships in the entry chunk, so a non-default
    // language has to be fetched before switching. Without this await i18next
    // renders raw keys (e.g. "common.save") for a bundle that has not arrived.
    let cancelled = false;
    let timer: number | undefined;
    void (async () => {
      await ensureLanguage(language);
      if (cancelled) {
        return;
      }

      const reducedMotion = typeof window.matchMedia === 'function'
        && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const animateLanguage = hasAppliedLanguageRef.current && !reducedMotion;
      const root = document.documentElement;
      if (animateLanguage && document.querySelector('.auth-screen')) {
        root.classList.add('language-transition-out');
        await new Promise<void>((resolve) => {
          timer = window.setTimeout(() => {
            timer = undefined;
            resolve();
          }, LANGUAGE_TRANSITION_EXIT_MS);
        });
        if (cancelled) return;
        root.classList.remove('language-transition-out');
      }

      const languageChange = i18n.changeLanguage(language);
      if (animateLanguage) root.classList.add('language-transition-in');
      await languageChange;
      if (cancelled) return;
      document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
      hasAppliedLanguageRef.current = true;

      if (animateLanguage) {
        timer = window.setTimeout(() => {
          root.classList.remove('language-transition-in');
          timer = undefined;
        }, LANGUAGE_TRANSITION_DURATION_MS);
      }
    })();
    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
        timer = undefined;
      }
      document.documentElement.classList.remove('language-transition-out', 'language-transition-in');
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
