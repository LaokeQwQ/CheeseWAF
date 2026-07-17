import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { ThemeName } from '../themes/tokens';

export type Language = 'zh-CN' | 'en-US';

type AppState = {
  theme: ThemeName;
  language: Language;
  sidebarCollapsed: boolean;
  /** Floating AI assistant button on every page (except dedicated AI page). */
  aiAssistantFabVisible: boolean;
  setTheme: (theme: ThemeName) => void;
  setLanguage: (language: Language) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setAiAssistantFabVisible: (visible: boolean) => void;
};

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      theme: 'light',
      language: 'zh-CN',
      sidebarCollapsed: false,
      aiAssistantFabVisible: true,
      setTheme: (theme) => set({ theme }),
      setLanguage: (language) => set({ language }),
      setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
      setAiAssistantFabVisible: (aiAssistantFabVisible) => set({ aiAssistantFabVisible }),
    }),
    {
      name: 'cheesewaf-ui',
      partialize: (state) => ({
        theme: state.theme,
        language: state.language,
        sidebarCollapsed: state.sidebarCollapsed,
        aiAssistantFabVisible: state.aiAssistantFabVisible,
      }),
    },
  ),
);
