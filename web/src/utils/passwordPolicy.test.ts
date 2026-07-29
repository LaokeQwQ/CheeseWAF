import { describe, expect, it } from 'vitest';
import { classifyPassword, passwordClassCount, passwordPolicyErrorKey } from './passwordPolicy';

describe('passwordPolicy', () => {
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
