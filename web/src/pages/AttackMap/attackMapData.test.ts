import { describe, expect, it } from 'vitest';
import type { LogEntry } from '../../types/api';
import {
  aggregateRegions,
  projectMapPoint,
  severityRank,
  threatLevelFor,
  worldMapPaths,
} from './attackMapData';

function entry(partial: Partial<LogEntry>): LogEntry {
  return {
    id: partial.id ?? crypto.randomUUID?.() ?? String(Math.random()),
    timestamp: partial.timestamp ?? '2026-07-17T12:00:00Z',
    client_ip: partial.client_ip ?? '203.0.113.10',
    method: 'GET',
    uri: partial.uri ?? '/admin',
    action: partial.action ?? 'block',
    category: partial.category ?? 'sqli',
    severity: partial.severity ?? 'high',
    status_code: partial.status_code ?? 403,
    message: '',
    country: partial.country ?? 'CN',
    metadata: partial.metadata ?? {},
    ...partial,
  } as LogEntry;
}

describe('attackMapData business aggregation', () => {
  it('exports projected world paths for the basemap', () => {
    expect(worldMapPaths.length).toBeGreaterThan(50);
    expect(worldMapPaths.every((item) => item.d.length > 0)).toBe(true);
  });

  it('aggregates security events by country and ranks threat level', () => {
    const regions = aggregateRegions([
      entry({ country: 'CN', severity: 'critical', category: 'sqli', client_ip: '1.1.1.1' }),
      entry({ country: 'CN', severity: 'high', category: 'xss', client_ip: '1.1.1.2' }),
      entry({ country: 'US', severity: 'low', category: 'bot', client_ip: '8.8.8.8' }),
      entry({ action: 'pass', category: '', severity: '', status_code: 200, country: 'JP' }), // ignored
    ]);
    expect(regions.some((r) => r.countryCode === 'CN' && r.attacks >= 2)).toBe(true);
    expect(regions.some((r) => r.countryCode === 'US' && r.attacks === 1)).toBe(true);
    expect(regions.some((r) => r.countryCode === 'JP')).toBe(false);
    const cn = regions.find((r) => r.countryCode === 'CN')!;
    expect(severityRank(cn.severity)).toBeGreaterThanOrEqual(3);
    expect(['low', 'medium', 'high', 'critical']).toContain(cn.level);
  });

  it('uses precise metadata coordinates when present', () => {
    const regions = aggregateRegions([
      entry({
        country: 'CN',
        metadata: { lat: 31.23, lon: 121.47, city: 'Shanghai', province: 'Shanghai' },
      }),
    ]);
    expect(regions).toHaveLength(1);
    expect(regions[0].lat).toBeCloseTo(31.23, 2);
    expect(regions[0].lon).toBeCloseTo(121.47, 2);
    expect(regions[0].mappable).toBe(true);
    const projected = projectMapPoint(regions[0].lon, regions[0].lat);
    expect(projected).not.toBeNull();
    expect(projected!.x).toBeGreaterThan(0);
    expect(projected!.x).toBeLessThan(100);
  });

  it('computes threat levels from volume and severity', () => {
    expect(threatLevelFor(1, 1, 100)).toBe('low');
    expect(threatLevelFor(10, 2, 20)).toBe('medium');
    // attacks>=20 && volume>=0.6 escalates to critical even when severity is high
    expect(threatLevelFor(15, 3, 40)).toBe('high');
    expect(threatLevelFor(25, 3, 40)).toBe('critical');
    expect(threatLevelFor(60, 4, 80)).toBe('critical');
  });
});
