import { themeAttribute, type ThemeName } from './tokens';

export function applyTheme(theme: ThemeName) {
  const root = document.documentElement;
  root.dataset.theme = themeAttribute[theme];

  if (theme === 'dark' || theme === 'blackGold') {
    document.body.setAttribute('arco-theme', 'dark');
  } else {
    document.body.removeAttribute('arco-theme');
  }
}
