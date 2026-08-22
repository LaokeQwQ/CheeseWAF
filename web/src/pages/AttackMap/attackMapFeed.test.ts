import { describe, expect, it } from 'vitest';
import type { AttackMapAggregateResponse } from '../../types/api';
import { mergeAttackMapAggregates, mergeAttackMapFeed, nextAttackMapCursor, regionsFromAttackMapAggregates } from './attackMapFeed';

function response(id: string, timestamp: string): AttackMapAggregateResponse {
  return {
    items: [{
      key: 'CN|Shanghai', country_code: 'CN', country: 'CN', location_name: 'Shanghai',
      lat: 31.2, lon: 121.5, mappable: true, attacks: 1, blocked: 1,
      severity: 'high', severity_rank: 3, top_category: 'sqli', categories: { sqli: 1 },
    }],
    events: [{
      id,
      trace_id: id,
      timestamp,
      client_ip: '203.0.113.8',
      method: 'GET',
      uri: '/login',
      action: 'block',
      category: 'sqli',
      severity: 'high',
      status_code: 403,
      country: 'CN',
      metadata: { lat: 31.2, lon: 121.5 },
    }],
    total: 1,
    has_more: false,
    next: { time: timestamp, id },
    generated_at: timestamp,
  };
}

describe('attackMapFeed', () => {
  it('merges incremental projections without duplicates and keeps geo metadata', () => {
    const first = mergeAttackMapFeed([], response('a', '2026-08-22T10:00:00Z'));
    const duplicate = mergeAttackMapFeed(first, response('a', '2026-08-22T10:00:00Z'));
    const second = mergeAttackMapFeed(duplicate, response('b', '2026-08-22T10:00:01Z'));
    expect(second.map((entry) => entry.id)).toEqual(['a', 'b']);
    expect(second[0]?.country).toBe('CN');
    expect(second[0]?.metadata).toEqual({ lat: 31.2, lon: 121.5 });
  });

  it('never moves the cursor backwards', () => {
    const current = { time: '2026-08-22T10:00:01Z', id: 'b' };
    expect(nextAttackMapCursor(current, response('a', '2026-08-22T10:00:00Z'))).toEqual(current);
    expect(nextAttackMapCursor(current, response('c', '2026-08-22T10:00:02Z'))).toEqual({ time: '2026-08-22T10:00:02Z', id: 'c' });
  });

  it('merges server aggregates and converts them to map regions', () => {
    const first = mergeAttackMapAggregates([], response('a', '2026-08-22T10:00:00Z'));
    const merged = mergeAttackMapAggregates(first, response('b', '2026-08-22T10:00:01Z'));
    expect(merged).toHaveLength(1);
    expect(merged[0]?.attacks).toBe(2);
    expect(merged[0]?.categories).toEqual({ sqli: 2 });
    const regions = regionsFromAttackMapAggregates(merged);
    expect(regions[0]).toMatchObject({ attacks: 2, countryCode: 'CN', locationName: 'Shanghai', mappable: true });
  });

  it('keeps country-only aggregates visible on the map', () => {
    const countryOnly = response('a', '2026-08-22T10:00:00Z');
    countryOnly.items = [{
      key: 'US|||', country_code: 'US', country: 'US', mappable: false,
      attacks: 1, blocked: 0, severity: 'medium', severity_rank: 2,
    }];
    expect(regionsFromAttackMapAggregates(countryOnly.items)[0]).toMatchObject({
      countryCode: 'US', mappable: true, lon: -95.7, lat: 37.1, locationSource: 'country-fallback',
    });
  });

  it('normalizes optional fields in compact regional events', () => {
    const compact = response('a', '2026-08-22T10:00:00Z');
    compact.items[0]!.events = [{ id: 'minimal', timestamp: '2026-08-22T10:00:00Z' }];

    const event = regionsFromAttackMapAggregates(compact.items)[0]?.events[0];

    expect(event).toMatchObject({
      id: 'minimal',
      trace_id: '',
      client_ip: '',
      method: '',
      uri: '',
      action: '',
      status_code: 0,
    });
  });

  it('bounds retained aggregate buckets for long-running screens', () => {
    const current = Array.from({ length: 1000 }, (_, index) => ({
      ...response(`event-${index}`, '2026-08-22T10:00:00Z').items[0]!,
      key: `bucket-${index}`,
      attacks: 1,
    }));
    const delta = response('new', '2026-08-22T10:00:01Z');
    delta.items[0]!.key = 'bucket-new';
    delta.items[0]!.attacks = 2;

    const merged = mergeAttackMapAggregates(current, delta);

    expect(merged).toHaveLength(1000);
    expect(merged.some((item) => item.key === 'bucket-new')).toBe(true);
  });
});
