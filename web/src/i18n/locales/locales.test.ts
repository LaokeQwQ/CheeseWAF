import { describe, expect, it } from 'vitest';
import enUS from './en-US';
import zhCN from './zh-CN';

function leafKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [prefix];
  return Object.entries(value as Record<string, unknown>)
    .flatMap(([key, child]) => leafKeys(child, prefix ? `${prefix}.${key}` : key))
    .sort();
}

describe('locale dictionaries', () => {
  it('keep English and Simplified Chinese key sets identical', () => {
    expect(leafKeys(zhCN)).toEqual(leafKeys(enUS));
  });

  it('do not contain blank user-facing strings', () => {
    for (const locale of [enUS, zhCN]) {
      const blanks = leafKeys(locale).filter((key) => {
        const value = key.split('.').reduce<unknown>((current, part) => (
          current && typeof current === 'object' ? (current as Record<string, unknown>)[part] : undefined
        ), locale);
        return typeof value === 'string' && value.trim() === '';
      });
      expect(blanks).toEqual([]);
    }
  });
});
