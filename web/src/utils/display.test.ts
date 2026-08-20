import { describe, expect, it } from 'vitest';
import { displayCategory } from './display';

const t = (key: string) => key;

describe('displayCategory', () => {
  it('maps semantic and edge categories to i18n keys', () => {
    expect(displayCategory('xxe', t)).toBe('securityCategories.xxe');
    expect(displayCategory('protocol_enforcement', t)).toBe('securityCategories.protocolEnforcement');
    expect(displayCategory('ip_access', t)).toBe('securityCategories.ipAccess');
    expect(displayCategory('fingerprint', t)).toBe('securityCategories.fingerprint');
    expect(displayCategory('api_security', t)).toBe('securityCategories.apiSecurity');
    expect(displayCategory('request_too_large', t)).toBe('securityCategories.requestTooLarge');
    expect(displayCategory('sqli', t)).toBe('securityCategories.sqli');
  });

  it('falls back to unknown instead of custom rule', () => {
    expect(displayCategory('not-a-real-category', t)).toBe('securityCategories.unknown');
    expect(displayCategory('', t)).toBe('securityCategories.unknown');
  });
});
