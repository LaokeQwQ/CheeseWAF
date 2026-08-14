import { describe, expect, it } from 'vitest';
import { parseReviewVerdict, reviewSearchMatch, shapeLabelKey, statusLabelKey } from './reviewLogic';

describe('reviewLogic', () => {
  it('parses compact model verdict json', () => {
    expect(parseReviewVerdict('{"risk":"high","summary":"php gadget","ai_used":true}')).toEqual({
      risk: 'high',
      summary: 'php gadget',
      aiUsed: true,
    });
  });

  it('keeps plain text verdicts', () => {
    expect(parseReviewVerdict('looks like a webshell')).toEqual({ summary: 'looks like a webshell' });
  });

  it('maps shape and status keys', () => {
    expect(shapeLabelKey('embedded')).toBe('review.embedded');
    expect(statusLabelKey('pending')).toBe('review.pending');
  });

  it('matches search across payload and path', () => {
    const item = {
      id: '1',
      trace_id: 't1',
      site_id: 'site-a',
      client_ip: '203.0.113.1',
      method: 'GET',
      uri: '/search',
      category: 'webshell',
      severity: 'high',
      payload: 'eval($_GET[cmd])',
      protection_level: 3,
      shape: 'embedded',
      status: 'pending',
      created_at: '2026-08-14T00:00:00Z',
    };
    expect(reviewSearchMatch(item, 'eval')).toBe(true);
    expect(reviewSearchMatch(item, 'nope')).toBe(false);
  });
});
