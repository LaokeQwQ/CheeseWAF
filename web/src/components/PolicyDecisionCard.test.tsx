import { describe, expect, it } from 'vitest';
import { getWAFPolicyDecision } from './PolicyDecisionCard';

describe('getWAFPolicyDecision', () => {
  it('reads the policy ladder and route override fields, and leaves absent ones undefined', () => {
    const decision = getWAFPolicyDecision({
      waf_policy_decision: {
        block_threshold: 0.9,
        challenge_threshold: '0.6',
        log_threshold: 0.3,
        action_override: 'challenge',
        route_override: '/api/admin',
      },
    });

    expect(decision).not.toBeNull();
    expect(decision?.blockThreshold).toBe(0.9);
    expect(decision?.challengeThreshold).toBe(0.6);
    expect(decision?.logThreshold).toBe(0.3);
    expect(decision?.actionOverride).toBe('challenge');
    expect(decision?.routeOverride).toBe('/api/admin');

    const sparse = getWAFPolicyDecision({ waf_policy_decision: { action: 'block' } });
    expect(sparse?.action).toBe('block');
    expect(sparse?.blockThreshold).toBeUndefined();
    expect(sparse?.challengeThreshold).toBeUndefined();
    expect(sparse?.logThreshold).toBeUndefined();
    expect(sparse?.actionOverride).toBeUndefined();
    expect(sparse?.routeOverride).toBeUndefined();
  });
});
