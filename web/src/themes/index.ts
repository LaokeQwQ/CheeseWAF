import { themeAttribute, themeMeta, type ThemeName } from './tokens';

const themeStyleLoaders: Record<ThemeName, () => Promise<unknown>> = {
  light: () => import('./light.css'),
  dark: () => import('./dark.css'),
  blackGold: () => import('./black-gold.css'),
  blueWhite: () => import('./blue-white.css'),
};

const loadedThemes = new Set<ThemeName>();

export function readInitialTheme(): ThemeName {
  try {
    const persisted = JSON.parse(localStorage.getItem('cheesewaf-ui') ?? '{}') as {
      state?: { theme?: unknown };
    };
    const theme = persisted.state?.theme;
    if (theme === 'light' || theme === 'dark' || theme === 'blackGold' || theme === 'blueWhite') {
      return theme;
    }
  } catch {
    // Invalid local preferences must not prevent the login screen from loading.
  }
  return 'light';
}

export async function loadThemeStyles(theme: ThemeName) {
  if (loadedThemes.has(theme)) {
    return;
  }
  await themeStyleLoaders[theme]();
  loadedThemes.add(theme);
}

export function applyTheme(theme: ThemeName) {
  const root = document.documentElement;
  root.dataset.theme = themeAttribute[theme];
  root.style.colorScheme = themeMeta[theme].colorScheme;

  if (theme === 'dark' || theme === 'blackGold') {
    document.body.setAttribute('arco-theme', 'dark');
  } else {
    document.body.removeAttribute('arco-theme');
  }

  let meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
  if (!meta) {
    meta = document.createElement('meta');
    meta.name = 'theme-color';
    document.head.appendChild(meta);
  }
  meta.content = themeMeta[theme].themeColor;
}
