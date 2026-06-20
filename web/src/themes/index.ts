import { themeAttribute, themeMeta, type ThemeName } from './tokens';

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
