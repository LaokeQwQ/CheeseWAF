import { themeAttribute, themeMeta, themeOptions, type ResolvedThemeName, type ThemeName } from './tokens';

const themeStyleLoaders: Record<ResolvedThemeName, () => Promise<unknown>> = {
  light: () => import('./light.css'),
  dark: () => import('./dark.css'),
  blackGold: () => import('./black-gold.css'),
  blueWhite: () => import('./blue-white.css'),
  pinkWhite: () => import('./pink-white.css'),
  mikuGreen: () => import('./miku-green.css'),
};

const loadedThemes = new Set<ResolvedThemeName>();

function isThemeName(value: unknown): value is ThemeName {
  return themeOptions.some((option) => option.value === value);
}
function prefersDarkScheme(): boolean {
  return typeof window !== 'undefined'
    && typeof window.matchMedia === 'function'
    && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

export function resolveTheme(theme: ThemeName): ResolvedThemeName {
  return theme === 'system' ? (prefersDarkScheme() ? 'dark' : 'light') : theme;
}

export function readInitialTheme(): ThemeName {
  try {
    const persisted = JSON.parse(localStorage.getItem('cheesewaf-ui') ?? '{}') as {
      state?: { theme?: unknown };
    };
    const theme = persisted.state?.theme;
    if (isThemeName(theme)) {
      return theme;
    }
  } catch {
    // Invalid local preferences must not prevent the login screen from loading.
  }
  // No valid persisted choice yet: follow the OS color scheme. Once the user
  // picks a theme it is persisted and takes precedence on later loads.
  return prefersDarkScheme() ? 'dark' : 'light';
}

export async function loadThemeStyles(theme: ThemeName) {
  const resolvedTheme = resolveTheme(theme);
  if (loadedThemes.has(resolvedTheme)) {
    return;
  }
  await themeStyleLoaders[resolvedTheme]();
  loadedThemes.add(resolvedTheme);
}

export function applyTheme(theme: ThemeName) {
  const resolvedTheme = resolveTheme(theme);
  const root = document.documentElement;
  root.dataset.theme = themeAttribute[resolvedTheme];
  root.style.colorScheme = themeMeta[resolvedTheme].colorScheme;

  const dark = resolvedTheme === 'dark' || resolvedTheme === 'blackGold';
  root.classList.toggle('dark', dark);

  let meta = document.querySelector('meta[name="theme-color"]') as HTMLMetaElement | null;
  if (!meta) {
    meta = document.createElement('meta');
    meta.name = 'theme-color';
    document.head.appendChild(meta);
  }
  meta.content = themeMeta[resolvedTheme].themeColor;
}
