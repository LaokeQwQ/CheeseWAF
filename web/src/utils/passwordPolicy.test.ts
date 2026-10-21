import { describe, expect, it } from 'vitest';
import { classifyPassword, passwordClassCount, passwordPolicyErrorKey } from './passwordPolicy';

describe('passwordPolicy', () => {
  it.each(['Qzqjvbnm密码', 'Qzqjvbnméé'])('does not count Unicode letters as special: %s', (password) => {
    expect(classifyPassword(password).special).toBe(false);
    expect(passwordPolicyErrorKey(password)).toBe('needClasses');
  });

  it('counts Unicode decimal digits the same as the server', () => {
    expect(classifyPassword('Qzqjvbnm١٩').nonRepeatingDigit).toBe(true);
    expect(classifyPassword('Qzqjvbnm١٢٣٤').nonRepeatingDigit).toBe(false);
    expect(passwordPolicyErrorKey('Qzqjvbnm١٩')).toBeNull();
  });

  it.each([
    ['Qzqjvbnm密码', { upper: true, lower: true, nonRepeatingDigit: false, special: false }, 'needClasses'],
    ['ÉÉÉÉéééé9!', { upper: false, lower: false, nonRepeatingDigit: true, special: true }, 'needClasses'],
    ['Qzqjvbnm密码9!', { upper: true, lower: true, nonRepeatingDigit: true, special: true }, null],
    ['Qzqjvbnm١١!', { upper: true, lower: true, nonRepeatingDigit: false, special: true }, null],
  ] as const)('matches the server golden vector for %s', (password, expected, errorKey) => {
    expect(classifyPassword(password)).toEqual(expected);
    expect(passwordPolicyErrorKey(password)).toBe(errorKey);
  });
  it('rejects Admin123456', () => {
    expect(passwordPolicyErrorKey('Admin123456')).not.toBeNull();
    expect(passwordPolicyErrorKey('Admin123456', 'admin')).not.toBeNull();
  });

  it('accepts strong three-class passwords', () => {
    expect(passwordPolicyErrorKey('Correct-Horse!')).toBeNull();
    expect(passwordPolicyErrorKey('N7v!mKq2PxR')).toBeNull();
  });

  it('requires min length 10', () => {
    expect(passwordPolicyErrorKey('Ab1!xYz')).toBe('tooShort');
  });

  it('classifies non-repeating digits', () => {
    const ok = classifyPassword('Abcdefg19!');
    expect(ok.nonRepeatingDigit).toBe(true);
    expect(passwordClassCount(ok)).toBeGreaterThanOrEqual(3);

    const seq = classifyPassword('Abcde1234!');
    expect(seq.nonRepeatingDigit).toBe(false);
  });
});
