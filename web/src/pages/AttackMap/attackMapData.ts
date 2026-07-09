import { geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import worldTopology from 'world-atlas/countries-110m.json';
import type { LogEntry } from '../../types/api';
import { displayCountry, normalizeCountryCode } from '../../utils/display';

export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';
export type LocationPrecision = 'street' | 'district' | 'city' | 'region' | 'country' | 'ip-range';
export type WorldFeature = {
  id?: string | number;
  type: 'Feature';
  geometry: unknown;
  properties?: Record<string, unknown>;
};
type WorldFeatureCollection = {
  type: 'FeatureCollection';
  features: WorldFeature[];
};
type CountryCoordinate = { lon: number; lat: number; continent: string };
type RegionBucket = {
  countryCode: string;
  continent: string;
  attacks: number;
  categories: Map<string, number>;
  severities: Map<string, number>;
  maxSeverity: number;
  lon: number;
  lat: number;
  mappable: boolean;
  locationName: string;
  adminCode: string;
  precision: LocationPrecision;
  accuracyRadiusKm: number | null;
  locationSource: string;
  sourcePrefixes: Map<string, number>;
  events: Array<Pick<LogEntry, 'id' | 'trace_id' | 'timestamp' | 'client_ip' | 'method' | 'uri' | 'action' | 'category' | 'severity' | 'status_code'>>;
};

export type ProtectedTarget = { lat: number; lon: number; label: string; source: 'metadata' | 'admin-host' | 'fallback' };
export type AttackRegion = {
  key: string;
  countryCode: string;
  country: string;
  continent: string;
  attacks: number;
  top: string;
  severity: string;
  severityRank: number;
  level: ThreatLevel;
  lon: number;
  lat: number;
  mappable: boolean;
  x: number;
  y: number;
  size: number;
  locationName: string;
  adminCode: string;
  precision: LocationPrecision;
  accuracyRadiusKm: number | null;
  locationSource: string;
  sourcePrefixes: string[];
  events: Array<Pick<LogEntry, 'id' | 'trace_id' | 'timestamp' | 'client_ip' | 'method' | 'uri' | 'action' | 'category' | 'severity' | 'status_code'>>;
};

const mapWidth = 1000;
const mapHeight = 500;
const topo = worldTopology as any;
const worldFeatureCollection = feature(topo, topo.objects.countries) as unknown as WorldFeatureCollection;
export const worldFeatures = worldFeatureCollection.features.filter((item) => item.geometry);
export const mapProjection = geoNaturalEarth1().fitExtent([[28, 28], [mapWidth - 28, mapHeight - 28]], worldFeatureCollection as any);
const mapPath = geoPath(mapProjection);
export const graticulePath = mapPath(geoGraticule10() as any) ?? '';
export const worldMapPaths = worldFeatures
  .map((item, index) => ({ id: normalizeWorldId(item.id ?? index), d: mapPath(item as any) ?? '' }))
  .filter((item) => item.d);

export const countryCoordinates: Record<string, CountryCoordinate> = {
  AR: { lon: -63.6, lat: -38.4, continent: 'South America' },
  AE: { lon: 54.4, lat: 23.4, continent: 'Asia' },
  AT: { lon: 14.6, lat: 47.5, continent: 'Europe' },
  AU: { lon: 133.8, lat: -25.3, continent: 'Oceania' },
  BE: { lon: 4.5, lat: 50.5, continent: 'Europe' },
  BG: { lon: 25.5, lat: 42.7, continent: 'Europe' },
  BR: { lon: -51.9, lat: -14.2, continent: 'South America' },
  CA: { lon: -106.3, lat: 56.1, continent: 'North America' },
  CH: { lon: 8.2, lat: 46.8, continent: 'Europe' },
  CL: { lon: -71.5, lat: -35.7, continent: 'South America' },
  CN: { lon: 104.2, lat: 35.9, continent: 'Asia' },
  CO: { lon: -74.3, lat: 4.6, continent: 'South America' },
  CZ: { lon: 15.5, lat: 49.8, continent: 'Europe' },
  DE: { lon: 10.5, lat: 51.1, continent: 'Europe' },
  DK: { lon: 9.5, lat: 56.3, continent: 'Europe' },
  EG: { lon: 30.8, lat: 26.8, continent: 'Africa' },
  ES: { lon: -3.7, lat: 40.4, continent: 'Europe' },
  FI: { lon: 25.7, lat: 61.9, continent: 'Europe' },
  FR: { lon: 2.2, lat: 46.2, continent: 'Europe' },
  GB: { lon: -3.4, lat: 55.4, continent: 'Europe' },
  GR: { lon: 21.8, lat: 39.1, continent: 'Europe' },
  HK: { lon: 114.2, lat: 22.3, continent: 'Asia' },
  MO: { lon: 113.5, lat: 22.2, continent: 'Asia' },
  HU: { lon: 19.5, lat: 47.2, continent: 'Europe' },
  ID: { lon: 113.9, lat: -0.8, continent: 'Asia' },
  IE: { lon: -8.2, lat: 53.4, continent: 'Europe' },
  IL: { lon: 34.9, lat: 31.0, continent: 'Asia' },
  IN: { lon: 78.9, lat: 20.6, continent: 'Asia' },
  IR: { lon: 53.7, lat: 32.4, continent: 'Asia' },
  IT: { lon: 12.6, lat: 42.8, continent: 'Europe' },
  JP: { lon: 138.2, lat: 36.2, continent: 'Asia' },
  KE: { lon: 37.9, lat: 0.0, continent: 'Africa' },
  KZ: { lon: 66.9, lat: 48.0, continent: 'Asia' },
  KR: { lon: 127.8, lat: 35.9, continent: 'Asia' },
  MA: { lon: -7.1, lat: 31.8, continent: 'Africa' },
  MX: { lon: -102.6, lat: 23.6, continent: 'North America' },
  MY: { lon: 101.9, lat: 4.2, continent: 'Asia' },
  NG: { lon: 8.7, lat: 9.1, continent: 'Africa' },
  NL: { lon: 5.3, lat: 52.1, continent: 'Europe' },
  NO: { lon: 8.5, lat: 60.5, continent: 'Europe' },
  NZ: { lon: 174.9, lat: -40.9, continent: 'Oceania' },
  PE: { lon: -75.0, lat: -9.2, continent: 'South America' },
  PH: { lon: 122.9, lat: 12.9, continent: 'Asia' },
  PK: { lon: 69.3, lat: 30.4, continent: 'Asia' },
  PL: { lon: 19.1, lat: 52.1, continent: 'Europe' },
  PT: { lon: -8.2, lat: 39.4, continent: 'Europe' },
  RO: { lon: 24.9, lat: 45.9, continent: 'Europe' },
  RU: { lon: 105.3, lat: 61.5, continent: 'Europe/Asia' },
  SA: { lon: 45.1, lat: 23.9, continent: 'Asia' },
  SE: { lon: 18.6, lat: 60.1, continent: 'Europe' },
  SG: { lon: 103.8, lat: 1.3, continent: 'Asia' },
  SI: { lon: 14.9, lat: 46.2, continent: 'Europe' },
  SK: { lon: 19.7, lat: 48.7, continent: 'Europe' },
  TH: { lon: 100.9, lat: 15.9, continent: 'Asia' },
  TR: { lon: 35.2, lat: 39.0, continent: 'Europe/Asia' },
  TW: { lon: 120.9, lat: 23.7, continent: 'Asia' },
  UA: { lon: 31.2, lat: 48.4, continent: 'Europe' },
  US: { lon: -95.7, lat: 37.1, continent: 'North America' },
  VE: { lon: -66.6, lat: 6.4, continent: 'South America' },
  VN: { lon: 108.3, lat: 14.1, continent: 'Asia' },
  ZA: { lon: 22.9, lat: -30.6, continent: 'Africa' },
};

export const countryNumericIds: Record<string, string> = {
  AR: '32',
  AE: '784',
  AT: '40',
  AU: '36',
  BE: '56',
  BG: '100',
  BR: '76',
  CA: '124',
  CH: '756',
  CL: '152',
  CN: '156',
  CO: '170',
  CZ: '203',
  DE: '276',
  DK: '208',
  EG: '818',
  ES: '724',
  FI: '246',
  FR: '250',
  GB: '826',
  GR: '300',
  HK: '344',
  MO: '446',
  HU: '348',
  ID: '360',
  IE: '372',
  IL: '376',
  IN: '356',
  IR: '364',
  IT: '380',
  JP: '392',
  KE: '404',
  KZ: '398',
  KR: '410',
  MA: '504',
  MX: '484',
  MY: '458',
  NG: '566',
  NL: '528',
  NO: '578',
  NZ: '554',
  PE: '604',
  PH: '608',
  PK: '586',
  PL: '616',
  PT: '620',
  RO: '642',
  RU: '643',
  SA: '682',
  SE: '752',
  SG: '702',
  SI: '705',
  SK: '703',
  TH: '764',
  TR: '792',
  TW: '158',
  UA: '804',
  US: '840',
  VE: '862',
  VN: '704',
  ZA: '710',
};

export function aggregateRegions(entries: LogEntry[]): AttackRegion[] {
  const buckets = new Map<string, RegionBucket>();
  for (const entry of entries) {
    if (!isSecurityEvent(entry)) {
      continue;
    }
    const location = resolveLocation(entry);
    const key = `${location.countryCode}|${location.adminCode}|${location.locationName}|${location.sourcePrefix}`;
    const current = buckets.get(key) ?? {
      countryCode: location.countryCode,
      continent: location.continent,
      attacks: 0,
      categories: new Map<string, number>(),
      severities: new Map<string, number>(),
      maxSeverity: 0,
      lon: location.lon,
      lat: location.lat,
      mappable: location.mappable,
      locationName: location.locationName,
      adminCode: location.adminCode,
      precision: location.precision,
      accuracyRadiusKm: location.accuracyRadiusKm,
      locationSource: location.locationSource,
      sourcePrefixes: new Map<string, number>(),
      events: [],
    };
    current.attacks += 1;
    const category = entry.category || entry.action || 'unknown';
    current.categories.set(category, (current.categories.get(category) ?? 0) + 1);
    const severity = entry.severity || severityFromAction(entry.action);
    current.severities.set(severity, (current.severities.get(severity) ?? 0) + 1);
    current.maxSeverity = Math.max(current.maxSeverity, severityRank(severity));
    if (location.sourcePrefix) {
      current.sourcePrefixes.set(location.sourcePrefix, (current.sourcePrefixes.get(location.sourcePrefix) ?? 0) + 1);
    }
    if (current.events.length < 6) {
      current.events.push(pickRegionEvent(entry));
    }
    buckets.set(key, current);
  }

  const baseItems = Array.from(buckets.entries()).map(([key, value]) => {
    const point = value.mappable ? projectMapPoint(value.lon, value.lat) : null;
    return {
      key,
      bucket: value,
      point,
      top: topMapValue(value.categories) ?? '-',
      severity: topMapValue(value.severities) ?? rankToSeverity(value.maxSeverity),
      sourcePrefixes: topMapEntries(value.sourcePrefixes, 3),
    };
  });
  const maxAttacks = Math.max(1, ...baseItems.map((item) => item.bucket.attacks));

  return baseItems
    .map(({ key, bucket, point, top, severity, sourcePrefixes }) => {
      const level = threatLevelFor(bucket.attacks, bucket.maxSeverity, maxAttacks);
      return {
        key,
        countryCode: bucket.countryCode,
        country: bucket.countryCode,
        continent: bucket.continent,
        attacks: bucket.attacks,
        top,
        severity,
        severityRank: bucket.maxSeverity,
        level,
        lon: bucket.lon,
        lat: bucket.lat,
        mappable: bucket.mappable,
        x: point ? point.x : 50,
        y: point ? point.y : 50,
        size: Math.max(14, Math.min(40, 10 + Math.sqrt(bucket.attacks) * 3.6)),
        locationName: bucket.locationName,
        adminCode: bucket.adminCode,
        precision: bucket.precision,
        accuracyRadiusKm: bucket.accuracyRadiusKm,
        locationSource: bucket.locationSource,
        sourcePrefixes,
        events: bucket.events,
      };
    })
    .sort((a, b) => b.attacks - a.attacks);
}

export function buildCountryLevelMap(regions: AttackRegion[]) {
  const byCountry = new Map<string, { attacks: number; severityRank: number }>();
  for (const region of regions) {
    if (!region.mappable || !countryNumericIds[region.countryCode]) {
      continue;
    }
    const current = byCountry.get(region.countryCode) ?? { attacks: 0, severityRank: 0 };
    current.attacks += region.attacks;
    current.severityRank = Math.max(current.severityRank, region.severityRank);
    byCountry.set(region.countryCode, current);
  }
  const maxAttacks = Math.max(1, ...Array.from(byCountry.values()).map((item) => item.attacks));
  const levels = new Map<string, ThreatLevel>();
  for (const [country, value] of byCountry.entries()) {
    levels.set(countryNumericIds[country], threatLevelFor(value.attacks, value.severityRank, maxAttacks));
  }
  return levels;
}

export function resolveProtectedTarget(entries: LogEntry[], t: (key: string, options?: Record<string, unknown>) => string): ProtectedTarget {
  for (const entry of entries) {
    const metadata = entry.metadata ?? {};
    const lat = readEntryNumber(entry, metadata, ['server_lat', 'server.latitude', 'server_latitude', 'origin_lat', 'origin.latitude', 'target_lat', 'target.latitude']);
    const lon = readEntryNumber(entry, metadata, ['server_lon', 'server.lng', 'server.longitude', 'server_longitude', 'origin_lon', 'origin.longitude', 'target_lon', 'target.longitude']);
    if (validCoordinate(lat, lon)) {
      const label = readEntryString(entry, metadata, ['server_region', 'server.city', 'origin_region', 'origin.city', 'target_region', 'target.city']) || t('attackMap.protectedTarget');
      return { lat: lat as number, lon: lon as number, label, source: 'metadata' };
    }
  }
  const hostCountry = inferCountryFromIP(typeof window !== 'undefined' ? window.location.hostname : '');
  const hostCoord = countryCoordinates[hostCountry];
  if (hostCoord) {
    return { lat: hostCoord.lat, lon: hostCoord.lon, label: displayCountry(hostCountry, t), source: 'admin-host' };
  }
  return { lat: countryCoordinates.CN.lat, lon: countryCoordinates.CN.lon, label: t('attackMap.protectedTarget'), source: 'fallback' };
}

export function projectMapPoint(lon: number, lat: number) {
  const point = mapProjection([lon, lat]);
  if (!point) {
    return null;
  }
  return {
    x: (point[0] / mapWidth) * 100,
    y: (point[1] / mapHeight) * 100,
  };
}

function resolveLocation(entry: LogEntry) {
  const metadata = entry.metadata ?? {};
  const countryCode = inferCountry(entry);
  const coord = countryCoordinates[countryCode];
  const metadataContinent = normalizeContinent(readMetadataString(metadata, ['continent', 'continent_name', 'geo.continent', 'geo.continent_name']));
  const metadataCountryName = readEntryString(entry, metadata, ['country_name', 'geo.country_name']);
  const lat = readEntryNumber(entry, metadata, ['lat', 'latitude', 'geo_lat', 'geo.lat', 'geo.latitude', 'location.lat', 'location.latitude']);
  const lon = readEntryNumber(entry, metadata, ['lon', 'lng', 'longitude', 'geo_lon', 'geo.lon', 'geo.lng', 'geo.longitude', 'location.lon', 'location.lng', 'location.longitude']);
  const street = readEntryString(entry, metadata, ['street', 'street_name', 'road', 'road_name', 'township', 'town', 'geo.street', 'geo.street_name', 'geo.road', 'geo.road_name', 'geo.township', 'geo.town', 'location.street', 'location.street_name', 'location.road', 'location.road_name']);
  const district = readEntryString(entry, metadata, ['district', 'district_name', 'county', 'county_name', 'area', 'geo.district', 'geo.district_name', 'geo.county', 'geo.county_name', 'geo.area', 'location.district', 'location.district_name', 'location.county', 'location.county_name', 'location.area']);
  const city = readEntryString(entry, metadata, ['city', 'city_name', 'geo.city', 'geo.city_name', 'location.city', 'location.city_name']);
  const region = readEntryString(entry, metadata, ['region', 'region_name', 'province', 'province_name', 'state', 'subdivision', 'geo.region', 'geo.region_name', 'geo.province', 'geo.province_name', 'geo.state', 'geo.subdivision']);
  const adminCode = readAdminCode(entry, metadata);
  const locationSource = readEntryString(entry, metadata, ['source', 'geo.source', 'location.source', 'provider', 'geo.provider']) || (lat !== null && lon !== null ? 'metadata' : (coord ? 'country-fallback' : 'unmapped'));
  const accuracyRadiusKm = readEntryNumber(entry, metadata, ['accuracy_radius', 'accuracy', 'geo.accuracy_radius', 'geo.accuracy', 'accuracyRadius', 'geo.accuracyRadius', 'location.accuracy_radius', 'location.accuracy']);
  const precise = validCoordinate(lat, lon);
  const sourcePrefix = ipPrefix(entry.client_ip);
  const fallbackName = countryCode === 'UNLOCATED' ? (metadataCountryName || sourcePrefix || 'UNLOCATED') : countryCode;
  const locationName = [region, city, district, street].filter(Boolean).join(' · ') || (sourcePrefix && !coord ? sourcePrefix : fallbackName);
  const point = precise ? { lon: lon as number, lat: lat as number } : null;
  return {
    countryCode,
    continent: metadataContinent || (coord?.continent ?? 'UNLOCATED'),
    lon: point?.lon ?? coord?.lon ?? 0,
    lat: point?.lat ?? coord?.lat ?? 0,
    mappable: Boolean(point || coord),
    locationName,
    adminCode,
    precision: precisionForLocation({ precise, street, district, city, region, sourcePrefix, countryCode }),
    accuracyRadiusKm: Number.isFinite(accuracyRadiusKm) && accuracyRadiusKm !== null ? Math.max(0, accuracyRadiusKm) : null,
    locationSource,
    sourcePrefix,
  };
}

function precisionForLocation(input: { precise: boolean; street: string; district: string; city: string; region: string; sourcePrefix: string; countryCode: string }): LocationPrecision {
  if (input.precise && input.street) return 'street';
  if (input.precise && input.district) return 'district';
  if (input.precise && input.city) return 'city';
  if (input.precise && input.region) return 'region';
  if (input.countryCode !== 'UNLOCATED') return 'country';
  return input.sourcePrefix ? 'ip-range' : 'country';
}

function pickRegionEvent(entry: LogEntry): AttackRegion['events'][number] {
  return {
    id: entry.id,
    trace_id: entry.trace_id,
    timestamp: entry.timestamp,
    client_ip: entry.client_ip,
    method: entry.method,
    uri: entry.uri,
    action: entry.action,
    category: entry.category,
    severity: entry.severity,
    status_code: entry.status_code,
  };
}

function inferCountry(entry: LogEntry) {
  const metadataCountry = readEntryString(entry, entry.metadata ?? {}, ['country_code', 'countryCode', 'geo.country_code', 'geo.country']);
  const country = normalizeCountryCode(metadataCountry || entry.country);
  if (country !== 'UNLOCATED') {
    return country;
  }
  return inferCountryFromIP(entry.client_ip);
}

function readAdminCode(entry: LogEntry, metadata: Record<string, unknown>) {
  const code = readEntryString(entry, metadata, [
    'adcode',
    'admin_code',
    'adminCode',
    'region_code',
    'regionCode',
    'province_code',
    'provinceCode',
    'city_code',
    'cityCode',
    'district_code',
    'districtCode',
    'county_code',
    'countyCode',
    'geo.adcode',
    'geo.admin_code',
    'geo.adminCode',
    'geo.region_code',
    'geo.regionCode',
    'geo.province_code',
    'geo.provinceCode',
    'geo.city_code',
    'geo.cityCode',
    'geo.district_code',
    'geo.districtCode',
    'geo.county_code',
    'geo.countyCode',
    'location.adcode',
    'location.admin_code',
    'location.adminCode',
    'location.region_code',
    'location.regionCode',
    'location.province_code',
    'location.provinceCode',
    'location.city_code',
    'location.cityCode',
    'location.district_code',
    'location.districtCode',
    'client.geo.adcode',
    'client.geo.admin_code',
    'client.geo.city_code',
    'client.geo.district_code',
  ]);
  const digits = code.replace(/\D+/g, '');
  return /^\d{6}$/.test(digits) ? digits : '';
}

function inferCountryFromIP(ip: string | undefined) {
  const parts = String(ip ?? '').split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return 'UNLOCATED';
  }
  const [a, b] = parts;
  if (a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return 'LOCAL';
  }
  if ([1, 14, 27, 36, 39, 42, 49, 58, 59, 60, 61, 101, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 139, 140, 150, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223].includes(a)) {
    return 'CN';
  }
  if (a === 5) {
    return 'NL';
  }
  if ([3, 4, 8, 13, 15, 18, 20, 23, 34, 35, 38, 44, 52, 54, 63, 64, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 98, 99, 100, 104, 107, 108, 129, 130, 131, 132, 134, 135, 136, 137, 138, 144, 146, 147, 148, 152, 155, 156, 157, 158, 159, 160, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216].includes(a)) {
    return 'US';
  }
  return 'UNLOCATED';
}

function isSecurityEvent(entry: LogEntry) {
  const action = String(entry.action ?? '').toLowerCase();
  return Boolean(entry.category || action === 'block' || action === 'challenge' || entry.status_code === 403 || entry.status_code === 429);
}

function severityFromAction(action: string | undefined) {
  switch (String(action ?? '').toLowerCase()) {
    case 'block':
      return 'high';
    case 'challenge':
      return 'medium';
    case 'log':
      return 'low';
    default:
      return 'info';
  }
}

export function severityRank(severity: string | undefined) {
  switch (String(severity ?? '').toLowerCase()) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    default:
      return 0;
  }
}

function rankToSeverity(rank: number) {
  if (rank >= 4) return 'critical';
  if (rank >= 3) return 'high';
  if (rank >= 2) return 'medium';
  if (rank >= 1) return 'low';
  return 'info';
}

export function threatLevelFor(attacks: number, maxSeverity: number, maxAttacks: number): ThreatLevel {
  const volume = attacks / Math.max(1, maxAttacks);
  if (maxSeverity >= 4 || attacks >= 50 || (attacks >= 20 && volume >= 0.6)) {
    return 'critical';
  }
  if (maxSeverity >= 3 || attacks >= 20 || volume >= 0.62) {
    return 'high';
  }
  if (maxSeverity >= 2 || attacks >= 6 || volume >= 0.28) {
    return 'medium';
  }
  return 'low';
}

function topMapValue(items: Map<string, number>) {
  return Array.from(items.entries()).sort((a, b) => b[1] - a[1])[0]?.[0];
}

function topMapEntries(items: Map<string, number>, limit: number) {
  return Array.from(items.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key]) => key);
}

function readMetadataString(metadata: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = readMetadataValue(metadata, key);
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
  }
  return '';
}

function readMetadataNumber(metadata: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = readMetadataValue(metadata, key);
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }
  return null;
}

function readEntryString(entry: LogEntry, metadata: Record<string, unknown>, keys: string[]) {
  const fromMetadata = readMetadataString(metadata, keys);
  if (fromMetadata) {
    return fromMetadata;
  }
  const loose = entry as unknown as Record<string, unknown>;
  for (const key of keys) {
    const value = readMetadataValue(loose, key);
    if (typeof value === 'string' && value.trim()) {
      return value.trim();
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
      return String(value);
    }
  }
  return '';
}

function readEntryNumber(entry: LogEntry, metadata: Record<string, unknown>, keys: string[]) {
  const fromMetadata = readMetadataNumber(metadata, keys);
  if (fromMetadata !== null) {
    return fromMetadata;
  }
  const loose = entry as unknown as Record<string, unknown>;
  for (const key of keys) {
    const value = readMetadataValue(loose, key);
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }
  return null;
}

function normalizeContinent(value: string) {
  const normalized = value.trim().toLowerCase().replace(/[_-]+/g, ' ');
  switch (normalized) {
    case 'af':
    case 'africa':
      return 'Africa';
    case 'as':
    case 'asia':
      return 'Asia';
    case 'eu':
    case 'europe':
      return 'Europe';
    case 'na':
    case 'north america':
      return 'North America';
    case 'oc':
    case 'oceania':
    case 'australia':
      return 'Oceania';
    case 'sa':
    case 'south america':
      return 'South America';
    default:
      return '';
  }
}

function readMetadataValue(metadata: Record<string, unknown>, key: string): unknown {
  const parts = key.split('.');
  let current: unknown = metadata;
  for (const part of parts) {
    if (!current || typeof current !== 'object') {
      return undefined;
    }
    current = caseInsensitiveGet(current as Record<string, unknown>, part);
  }
  return current;
}

function caseInsensitiveGet(record: Record<string, unknown>, key: string) {
  if (Object.prototype.hasOwnProperty.call(record, key)) {
    return record[key];
  }
  const found = Object.keys(record).find((item) => item.toLowerCase() === key.toLowerCase());
  return found ? record[found] : undefined;
}

function validCoordinate(lat: number | null, lon: number | null) {
  return typeof lat === 'number' && typeof lon === 'number' && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

function ipPrefix(ip: string | undefined) {
  const parts = String(ip ?? '').split('.');
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(Number(part)))) {
    return '';
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

export function normalizeWorldId(id: string | number) {
  const value = String(id);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? String(parsed) : value;
}
