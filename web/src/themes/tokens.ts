export type ThemeName = 'light' | 'dark' | 'blackGold' | 'blueWhite';

export const themeOptions: Array<{ labelKey: string; value: ThemeName }> = [
  { labelKey: 'themes.light', value: 'light' },
  { labelKey: 'themes.dark', value: 'dark' },
  { labelKey: 'themes.blackGold', value: 'blackGold' },
  { labelKey: 'themes.blueWhite', value: 'blueWhite' },
];

export const themeAttribute: Record<ThemeName, string> = {
  light: 'light',
  dark: 'dark',
  blackGold: 'black-gold',
  blueWhite: 'blue-white',
};
