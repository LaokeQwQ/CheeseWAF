import { describe, expect, it } from 'vitest';
import {
  compileRulePattern,
  isDangerouslyBroadPattern,
  ruleTemplates,
  testPattern,
  validateRuleDraft,
} from './rulesLogic';

const t = (key: string, options?: Record<string, unknown>) =>
  options ? `${key}:${JSON.stringify(options)}` : key;

describe('rulesLogic', () => {
  it('ships attack templates with real patterns', () => {
    const templates = ruleTemplates(t);
    expect(templates.length).toBeGreaterThanOrEqual(10);
    const sqli = templates.find((item) => item.key === 'sql-union');
    expect(sqli?.pattern).toMatch(/union/i);
    expect(testPattern(sqli!.pattern, "1' UNION SELECT 1 FROM users").matched).toBe(true);
    expect(testPattern(sqli!.pattern, '/health').matched).toBe(false);
  });

  it('compiles inline case-insensitive flags', () => {
    const re = compileRulePattern('(?i)admin');
    expect(re.test('ADMIN')).toBe(true);
    expect(re.test('user')).toBe(false);
  });

  it('rejects empty, invalid priority, invalid regex, and overly broad patterns', () => {
    expect(validateRuleDraft('', 100, t).ok).toBe(false);
    expect(validateRuleDraft('^/admin$', 0, t).ok).toBe(false);
    expect(validateRuleDraft('^/admin$', 1000, t).ok).toBe(false);
    expect(validateRuleDraft('[unterminated', 100, t).ok).toBe(false);
    expect(validateRuleDraft('.*', 100, t).ok).toBe(false);
    expect(validateRuleDraft('^/admin$', 100, t).ok).toBe(true);
  });

  it('flags dangerously broad patterns including flag-prefixed wildcards', () => {
    expect(isDangerouslyBroadPattern('.*')).toBe(true);
    expect(isDangerouslyBroadPattern('(?i).*')).toBe(true);
    expect(isDangerouslyBroadPattern('^[\\s\\S]*$')).toBe(true);
    expect(isDangerouslyBroadPattern('^/api/')).toBe(false);
  });

  it('treats empty test input as non-match without error', () => {
    expect(testPattern('^/admin$', '')).toEqual({ ok: true, matched: false });
    expect(testPattern('', 'payload')).toEqual({ ok: true, matched: false });
  });
});
