import { beforeEach, describe, expect, it } from 'vitest';
import { applyTheme, loadThemeStyles, readInitialTheme } from './index';

describe('theme bootstrap', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    document.documentElement.classList.remove('dark');
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

  it('applies document theme and color scheme', () => {
    applyTheme('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(document.documentElement.style.colorScheme).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    applyTheme('blackGold');
    expect(document.documentElement.dataset.theme).toBe('black-gold');
    expect(document.documentElement.style.colorScheme).toBe('dark');
    expect(document.documentElement.classList.contains('dark')).toBe(true);

    applyTheme('blueWhite');
    expect(document.documentElement.dataset.theme).toBe('blue-white');
    expect(document.documentElement.classList.contains('dark')).toBe(false);

    applyTheme('pinkWhite');
    expect(document.documentElement.dataset.theme).toBe('pink-white');
    expect(document.documentElement.style.colorScheme).toBe('light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
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
