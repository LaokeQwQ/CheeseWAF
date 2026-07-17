import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from './client';
import { buildBotChallengeOverview, fetchBotChallengeMetrics } from './botChallenge';
import type { LogEntry } from '../types/api';

const start = new Date('2026-07-10T00:00:00Z');
const end = new Date('2026-07-11T00:00:00Z');
function log(patch: Partial<LogEntry>): LogEntry { return { id:'1',timestamp:'2026-07-10T12:00:00Z',trace_id:'cw-1',site_id:'site-a',client_ip:'203.0.113.7',method:'GET',uri:'/',status_code:403,action:'challenge',detector_id:'bot',category:'bot',severity:'medium',message:'automation suspected',payload:'',user_agent:'test',country:'CN',latency:1,...patch }; }

describe('bot challenge overview', () => {
  afterEach(() => vi.restoreAllMocks());

  it('loads server-side metrics with the selected range', async () => {
    const get = vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { data: { range: '7d', totals: {}, trend: [] } } } as never);
    await expect(fetchBotChallengeMetrics('7d')).resolves.toMatchObject({ range: '7d' });
    expect(get).toHaveBeenCalledWith('/protection/bot/metrics', { params: { range: '7d' } });
  });

  it('aggregates only actual bot challenge logs and keeps unavailable outcomes undefined', () => {
    const overview = buildBotChallengeOverview([log({}), log({ id:'2', action:'pass', category:'normal', detector_id:'', client_ip:'198.51.100.2' })], start, end);
    expect(overview.totalChallenges).toBe(1); expect(overview.challengedClients).toBe(1); expect(overview.passRate).toBeUndefined();
  });
  it('uses explicit captcha metadata for type and pass rate', () => {
    const overview = buildBotChallengeOverview([log({metadata:{captcha_type:'text_click',captcha_outcome:'passed'}}),log({id:'2',trace_id:'cw-2',metadata:{captcha_type:'text_click',captcha_outcome:'failed'}})],start,end);
    expect(overview.passRate).toBe(.5); expect(overview.typeEffects[0]).toMatchObject({type:'text_click',issued:2,passed:1,failed:1,passRate:.5});
  });
});
