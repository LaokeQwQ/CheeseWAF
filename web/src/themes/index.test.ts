import { beforeEach, describe, expect, it, vi } from 'vitest';
import { applyTheme, loadThemeStyles, readInitialTheme } from './index';

function stubMatchMedia(scheme: 'light' | 'dark') {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: scheme === 'dark' ? query.includes('dark') : !query.includes('dark'),
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

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

  it('follows prefers-color-scheme when nothing is persisted', () => {
    stubMatchMedia('dark');
    expect(readInitialTheme()).toBe('dark');

    stubMatchMedia('light');
    expect(readInitialTheme()).toBe('light');
  });

  it('lets a valid persisted choice win over the system scheme', () => {
    stubMatchMedia('dark');
    localStorage.setItem('cheesewaf-ui', JSON.stringify({ state: { theme: 'light' } }));
    expect(readInitialTheme()).toBe('light');
  });

  it('falls back safely when persisted preferences are invalid', () => {
    stubMatchMedia('dark');
    localStorage.setItem('cheesewaf-ui', '{invalid');
    expect(readInitialTheme()).toBe('dark');
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
