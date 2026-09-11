import { describe, expect, it } from 'vitest';
import { isCanonicalUsername, usernameErrorKey } from './username';
import enUS from '../i18n/locales/en-US';
import zhCN from '../i18n/locales/zh-CN';

describe('canonical username validation', () => {
  it('accepts the canonical admin username without changing its case', () => {
    expect(isCanonicalUsername('admin')).toBe(true);
    expect(usernameErrorKey('admin')).toBeNull();
  });

  it.each([' admin', 'admin ', 'admin\t', 'admin\u200b', 'ad\nmin'])('reports whitespace or invisible input for %j', (value) => {
    expect(usernameErrorKey(value)).toBe('setup.usernameWhitespace');
    expect(usernameErrorKey(value, 'login')).toBe('login.usernameWhitespace');
    expect(isCanonicalUsername(value)).toBe(false);
  });

  it('rejects non-ASCII symbols even when the visible shape looks like a name', () => {
    expect(usernameErrorKey('admin@ops')).toBe('setup.usernameInvalidChars');
    expect(usernameErrorKey('admin😀x')).toBe('setup.usernameInvalidChars');
  });

  it('keeps length, start, and end diagnostics separate', () => {
    expect(usernameErrorKey('ad')).toBe('setup.usernameTooShort');
    expect(usernameErrorKey('1admin')).toBe('setup.usernameMustStartWithLetter');
    expect(usernameErrorKey('admin-')).toBe('setup.usernameMustEndAlnum');
    expect(usernameErrorKey(`a${'b'.repeat(32)}`)).toBe('setup.usernameTooLong');
  });

  it.each([enUS, zhCN])('provides translated whitespace guidance for every account entry point', (locale) => {
    for (const namespace of ['setup', 'users', 'login'] as const) {
      const messages = locale[namespace] as Record<string, unknown>;
      expect(messages.usernameWhitespace).toEqual(expect.any(String));
      expect(messages.usernameWhitespace).not.toBe('');
    }
  });
});
