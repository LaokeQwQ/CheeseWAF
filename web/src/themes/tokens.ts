export type ThemeName = 'light' | 'dark' | 'blackGold' | 'blueWhite' | 'pinkWhite' | 'mikuGreen';

export const themeOptions: Array<{ labelKey: string; value: ThemeName }> = [
  { labelKey: 'themes.light', value: 'light' },
  { labelKey: 'themes.dark', value: 'dark' },
  { labelKey: 'themes.blackGold', value: 'blackGold' },
  { labelKey: 'themes.blueWhite', value: 'blueWhite' },
  { labelKey: 'themes.pinkWhite', value: 'pinkWhite' },
  { labelKey: 'themes.mikuGreen', value: 'mikuGreen' },
];

export const themeAttribute: Record<ThemeName, string> = {
  light: 'light',
  dark: 'dark',
  blackGold: 'black-gold',
  blueWhite: 'blue-white',
  pinkWhite: 'pink-white',
  mikuGreen: 'miku-green',
};

export const themeMeta: Record<
  ThemeName,
  { themeColor: string; colorScheme: 'light' | 'dark' }
> = {
  light: { themeColor: '#f6f8fb', colorScheme: 'light' },
  dark: { themeColor: '#0d1117', colorScheme: 'dark' },
  blackGold: { themeColor: '#0a0a08', colorScheme: 'dark' },
  blueWhite: { themeColor: '#eef6ff', colorScheme: 'light' },
  pinkWhite: { themeColor: '#fdf6f9', colorScheme: 'light' },
  mikuGreen: { themeColor: '#f1faf9', colorScheme: 'light' },
};
