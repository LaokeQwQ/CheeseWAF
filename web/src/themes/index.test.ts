import { beforeEach, describe, expect, it } from 'vitest';
import { applyTheme, loadThemeStyles, readInitialTheme } from './index';

describe('theme bootstrap', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    document.body.removeAttribute('arco-theme');
  });

  it('reads a valid persisted theme before React mounts', () => {
    localStorage.setItem('cheesewaf-ui', JSON.stringify({ state: { theme: 'blackGold' } }));
    expect(readInitialTheme()).toBe('blackGold');

    localStorage.setItem('cheesewaf-ui', JSON.stringify({ state: { theme: 'mikuGreen' } }));
    expect(readInitialTheme()).toBe('mikuGreen');
  });

  it('falls back safely when persisted preferences are invalid', () => {
    localStorage.setItem('cheesewaf-ui', '{invalid');
    expect(readInitialTheme()).toBe('light');
  });

  it('applies matching document and Arco color schemes', () => {
    applyTheme('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(document.documentElement.style.colorScheme).toBe('dark');
    expect(document.body.getAttribute('arco-theme')).toBe('dark');

    applyTheme('blueWhite');
    expect(document.documentElement.dataset.theme).toBe('blue-white');
    expect(document.body.hasAttribute('arco-theme')).toBe(false);

    applyTheme('pinkWhite');
    expect(document.documentElement.dataset.theme).toBe('pink-white');
    expect(document.documentElement.style.colorScheme).toBe('light');
    expect(document.body.hasAttribute('arco-theme')).toBe(false);
  });

  it('loads every theme stylesheet before it is activated', async () => {
    await expect(loadThemeStyles('light')).resolves.toBeUndefined();
    await expect(loadThemeStyles('dark')).resolves.toBeUndefined();
    await expect(loadThemeStyles('blackGold')).resolves.toBeUndefined();
    await expect(loadThemeStyles('blueWhite')).resolves.toBeUndefined();
    await expect(loadThemeStyles('pinkWhite')).resolves.toBeUndefined();
    await expect(loadThemeStyles('mikuGreen')).resolves.toBeUndefined();
  });
});
