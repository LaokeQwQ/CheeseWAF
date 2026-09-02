import type { AttackMapAggregate, AttackMapAggregateResponse, AttackMapEvent, LogEntry } from '../../types/api';
import { countryCoordinates, projectMapPoint, threatLevelFor, type AttackRegion, type LocationPrecision } from './attackMapData';

const maxAttackMapFeedEntries = 1000;
const maxAttackMapAggregateBuckets = 1000;

export type AttackMapCursor = { time: string; id: string };

export function mergeAttackMapFeed(current: LogEntry[], response: AttackMapAggregateResponse): LogEntry[] {
  const merged = new Map<string, LogEntry>();
  for (const entry of current) {
    merged.set(feedKey(entry), entry);
  }
  for (const event of response.events ?? []) {
    const entry = eventToLogEntry(event);
    merged.set(feedKey(entry), entry);
  }
  return Array.from(merged.values())
    .sort((left, right) => compareFeedEntries(left, right))
    .slice(-maxAttackMapFeedEntries);
}

export function mergeAttackMapAggregates(current: AttackMapAggregate[], response: AttackMapAggregateResponse): AttackMapAggregate[] {
  const merged = new Map(current.map((item) => [item.key, item]));
  for (const delta of response.items ?? []) {
    const existing = merged.get(delta.key);
    if (!existing) {
      merged.set(delta.key, cloneAggregate(delta));
      continue;
    }
    const severityRank = Math.max(existing.severity_rank, delta.severity_rank);
    merged.set(delta.key, {
      ...existing,
      ...delta,
      attacks: existing.attacks + delta.attacks,
      blocked: existing.blocked + delta.blocked,
      severity_rank: severityRank,
      severity: delta.severity_rank >= existing.severity_rank ? delta.severity : existing.severity,
      categories: mergeCounts(existing.categories, delta.categories),
      source_prefixes: mergeCounts(existing.source_prefixes, delta.source_prefixes),
      events: mergeEvents(existing.events, delta.events),
    });
  }
  return Array.from(merged.values())
    .sort((left, right) => right.attacks - left.attacks || left.key.localeCompare(right.key))
    .slice(0, maxAttackMapAggregateBuckets);
}

export function regionsFromAttackMapAggregates(aggregates: AttackMapAggregate[]): AttackRegion[] {
  const maxAttacks = Math.max(1, ...aggregates.map((item) => item.attacks));
  return aggregates.map((item) => {
    const countryFallback = countryCoordinates[item.country_code];
    const mappable = item.mappable || Boolean(countryFallback);
    const lon = item.mappable ? (item.lon ?? 0) : (countryFallback?.lon ?? 0);
    const lat = item.mappable ? (item.lat ?? 0) : (countryFallback?.lat ?? 0);
    const point = mappable ? projectMapPoint(lon, lat) : null;
    const sourcePrefixes = Object.entries(item.source_prefixes ?? {})
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, 3)
      .map(([value]) => value);
    return {
      key: item.key,
      countryCode: item.country_code || 'UNLOCATED',
      country: item.country || item.country_code || 'UNLOCATED',
      continent: item.continent || countryFallback?.continent || 'UNLOCATED',
      attacks: item.attacks,
      top: item.top_category || '-',
      severity: item.severity || 'info',
      severityRank: item.severity_rank,
      level: threatLevelFor(item.attacks, item.severity_rank, maxAttacks),
      lon,
      lat,
      mappable,
      x: point?.x ?? 50,
      y: point?.y ?? 50,
      size: Math.max(14, Math.min(40, 10 + Math.sqrt(item.attacks) * 3.6)),
      locationName: item.location_name || item.country_code || 'UNLOCATED',
      adminCode: item.admin_code || '',
      precision: normalizePrecision(item.precision),
      accuracyRadiusKm: item.accuracy_radius_km ?? null,
      locationSource: item.location_source || (countryFallback ? 'country-fallback' : 'aggregate'),
      sourcePrefixes,
      events: (item.events ?? []).map(eventToLogEntry),
    };
  });
}

export function nextAttackMapCursor(current: AttackMapCursor | null, response: AttackMapAggregateResponse): AttackMapCursor | null {
  if (!response.next?.time) {
    return current;
  }
  const next = { time: response.next.time, id: response.next.id ?? '' };
  if (!current) {
    return next;
  }
  return compareCursor(next, current) > 0 ? next : current;
}

function eventToLogEntry(event: AttackMapEvent): LogEntry {
  return {
    id: event.id,
    trace_id: event.trace_id ?? '',
    timestamp: event.timestamp,
    site_id: '',
    client_ip: event.client_ip ?? '',
    method: event.method ?? '',
    uri: event.uri ?? '',
    status_code: event.status_code ?? 0,
    action: event.action ?? '',
    detector_id: '',
    category: event.category ?? '',
    severity: event.severity ?? '',
    message: '',
    payload: '',
    user_agent: '',
    country: event.country ?? '',
    latency: 0,
    metadata: event.metadata,
  };
}

function feedKey(entry: Pick<LogEntry, 'id' | 'trace_id' | 'timestamp'>) {
  return entry.id || entry.trace_id || entry.timestamp;
}

function compareFeedEntries(left: LogEntry, right: LogEntry) {
  const time = Date.parse(left.timestamp) - Date.parse(right.timestamp);
  if (time !== 0) {
    return time;
  }
  return feedKey(left).localeCompare(feedKey(right));
}

function compareCursor(left: AttackMapCursor, right: AttackMapCursor) {
  const time = Date.parse(left.time) - Date.parse(right.time);
  if (time !== 0) {
    return time;
  }
  return left.id.localeCompare(right.id);
}

function cloneAggregate(value: AttackMapAggregate): AttackMapAggregate {
  return {
    ...value,
    categories: { ...value.categories },
    source_prefixes: { ...value.source_prefixes },
    events: value.events ? [...value.events] : [],
  };
}

function mergeCounts(left: Record<string, number> | undefined, right: Record<string, number> | undefined) {
  const merged: Record<string, number> = { ...left };
  for (const [key, value] of Object.entries(right ?? {})) {
    merged[key] = (merged[key] ?? 0) + value;
  }
  return merged;
}

function mergeEvents(left: AttackMapEvent[] | undefined, right: AttackMapEvent[] | undefined) {
  const merged = new Map<string, AttackMapEvent>();
  for (const event of [...(left ?? []), ...(right ?? [])]) {
    merged.set(event.id || event.trace_id || event.timestamp, event);
  }
  return Array.from(merged.values())
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp) || b.id.localeCompare(a.id))
    .slice(0, 6);
}

function normalizePrecision(value: string | undefined): LocationPrecision {
  switch (value) {
    case 'street':
    case 'district':
    case 'city':
    case 'region':
    case 'country':
    case 'ip-range':
      return value;
    default:
      return 'country';
  }
}
