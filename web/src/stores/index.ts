import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { ThemeName } from '../themes/tokens';

export type Language = 'zh-CN' | 'en-US';

type AppState = {
  theme: ThemeName;
  language: Language;
  sidebarCollapsed: boolean;
  setTheme: (theme: ThemeName) => void;
  setLanguage: (language: Language) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
};

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      theme: 'light',
      language: 'zh-CN',
      sidebarCollapsed: false,
      setTheme: (theme) => set({ theme }),
      setLanguage: (language) => set({ language }),
      setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
    }),
    {
      name: 'cheesewaf-ui',
      partialize: (state) => ({
        theme: state.theme,
        language: state.language,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    },
  ),
);
