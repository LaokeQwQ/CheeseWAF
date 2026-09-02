import { geoMercator, geoPath } from 'd3-geo';
import type { AttackRegion, GeoFeatureCollection, ThreatLevel, WorldFeature } from './attackMapData';

export type { GeoFeatureCollection };

export type ChinaBoundaryLayer = {
  key: string;
  adcode: string;
  name: string;
  englishName?: string;
  labelPoint?: { x: number; y: number };
  d: string;
  level: ThreatLevel | 'neutral';
  attacks: number;
  source: 'builtin-province' | 'builtin-city' | 'builtin-district' | 'external';
};

export type ChinaAdministrativeMap = {
  provinceLayers: ChinaBoundaryLayer[];
  cityLayers: ChinaBoundaryLayer[];
  districtLayers: ChinaBoundaryLayer[];
  customLayers: ChinaBoundaryLayer[];
  projection: ReturnType<typeof geoMercator>;
  path: ReturnType<typeof geoPath>;
  viewBox: string;
  width: number;
  height: number;
  sourceSummary: 'builtin-province' | 'builtin-city' | 'builtin-district' | 'external';
};

export type ChinaMapAssets = {
  country: GeoFeatureCollection;
  adminIndex: ChinaAdminIndex;
};

export type ChinaAdminIndex = {
  nameToCodes: Map<string, string[]>;
  codeToName: Map<string, string>;
};

export type ChinaComplianceAssets = {
  tenDash: GeoFeatureCollection;
  huangyan: GeoFeatureCollection;
  borders: GeoFeatureCollection;
};

export type ChinaComplianceFeatures = {
  tenDash: GeoFeatureCollection;
  huangyan: GeoFeatureCollection;
  borders: GeoFeatureCollection;
};

export type ChinaBoundaryGateConfig = {
  enabled?: boolean;
  license?: string;
  review_id?: string;
  source_type?: string;
};

/**
 * Coordinate reference systems an external China boundary source may declare.
 *
 * `unknown` is deliberately the fail-closed value: a boundary whose CRS cannot
 * be proven is never rendered. Guessing is not an option — a GCJ-02 source
 * drawn as WGS84 sits ~300~500m off, and a map with offset boundaries is a
 * compliance defect, not a cosmetic one.
 *
 * Baseline: the built-in packs this page renders (`china_province`,
 * `china_county`) are WGS84/CGCS2000, and the MapLibre / d3-geo canvas is Web
 * Mercator over WGS84, so WGS84 is the target of every conversion here.
 * (Measured: DataV `areas_v3` is GCJ-02; see the note on `china_region` in the
 * compliance audit — it is the one built-in pack that is not WGS84.)
 */
export type ChinaBoundaryCrs = 'WGS84' | 'GCJ02' | 'BD09' | 'unknown';

/** Why an external boundary collection was refused. Drives the operator-facing warning. */
export type ExternalChinaBoundaryRejection =
  | 'no-crs'
  | 'unsupported-crs'
  | 'no-adcode'
  | 'out-of-range';

export type ExternalChinaBoundaryAdmission = {
  /** Admitted, CRS-converted, code-filtered collection; `null` when refused. */
  collection: GeoFeatureCollection | null;
  /** `null` when accepted, or when there was simply nothing to admit. */
  rejection: ExternalChinaBoundaryRejection | null;
};

export function chinaFeatureAdcode(properties: Record<string, unknown> | null | undefined): string {
  const props = properties ?? {};
  const gb = typeof props.gb === 'string' && props.gb.length >= 8 ? props.gb.slice(3) : '';
  const adcode = typeof props.adcode === 'string' || typeof props.adcode === 'number' ? String(props.adcode) : '';
  return gb || adcode;
}

export function isChinaBoundaryEnabled(gate?: ChinaBoundaryGateConfig | null): boolean {
  if (!gate || gate.enabled === false) return false;
  const hasLicense = Boolean((gate.license ?? '').trim());
  const hasReviewId = Boolean((gate.review_id ?? '').trim());
  return hasLicense || hasReviewId;
}

export function buildChinaComplianceFeatures(
  assets: ChinaComplianceAssets | null | undefined,
  enabled: boolean,
): ChinaComplianceFeatures | null {
  if (!enabled) return null;
  const tenDash = assets?.tenDash;
  const huangyan = assets?.huangyan;
  const borders = assets?.borders;
  if (!tenDash?.features?.length && !huangyan?.features?.length && !borders?.features?.length) return null;
  return {
    tenDash: tenDash ?? emptyFeatureCollection,
    huangyan: huangyan ?? emptyFeatureCollection,
    borders: borders ?? emptyFeatureCollection,
  };
}

export function filterChinaCollectionByPrefix(collection: GeoFeatureCollection, prefixLength: number): GeoFeatureCollection {
  return {
    type: 'FeatureCollection',
    features: collection.features.filter((feature) => chinaFeatureAdcode(feature.properties ?? {}).length >= prefixLength),
  };
}

export async function fetchGzJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const base = (import.meta.env.BASE_URL || '/').replace(/\/?$/, '/');
  const absolute = /^https?:\/\//.test(url) ? url : `${base}${url.replace(/^\//, '')}`;
  const response = await fetch(absolute, { headers: { Accept: 'application/json' }, signal });
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
  }
  if (url.endsWith('.gz')) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error(`DecompressionStream is unavailable; cannot decompress ${url}`);
    }
    const body = response.body;
    if (!body) throw new Error(`No response body for ${url}`);
    const decompressed = body.pipeThrough(new DecompressionStream('gzip'));
    return new Response(decompressed).json() as Promise<T>;
  }
  return response.json() as Promise<T>;
}

const chinaMapWidth = 960;
const chinaMapHeight = 620;
const chinaViewBox = `0 0 ${chinaMapWidth} ${chinaMapHeight}`;
const directAdminProvincePrefixes = new Set(['11', '12', '31', '50', '71', '81', '82']);
const emptyFeatureCollection: GeoFeatureCollection = { type: 'FeatureCollection', features: [] };
const chinaAdminNameAliases: Record<string, string> = {
  anhui: '安徽',
  beijing: '北京',
  chongqing: '重庆',
  fujian: '福建',
  gansu: '甘肃',
  guangdong: '广东',
  guangxi: '广西',
  guizhou: '贵州',
  hainan: '海南',
  hebei: '河北',
  heilongjiang: '黑龙江',
  henan: '河南',
  hongkong: '香港',
  hubei: '湖北',
  hunan: '湖南',
  innermongolia: '内蒙古',
  jiangsu: '江苏',
  jiangxi: '江西',
  jilin: '吉林',
  liaoning: '辽宁',
  macau: '澳门',
  ningxia: '宁夏',
  qinghai: '青海',
  shaanxi: '陕西',
  shandong: '山东',
  shanghai: '上海',
  shanxi: '山西',
  sichuan: '四川',
  taiwan: '台湾',
  tianjin: '天津',
  tibet: '西藏',
  xinjiang: '新疆',
  yunnan: '云南',
  zhejiang: '浙江',
  anqing: '安庆',
  bengbu: '蚌埠',
  changchun: '长春',
  changsha: '长沙',
  changzhou: '常州',
  chengdu: '成都',
  dalian: '大连',
  dongguan: '东莞',
  foshan: '佛山',
  fuzhou: '福州',
  guangzhou: '广州',
  guiyang: '贵阳',
  haikou: '海口',
  hangzhou: '杭州',
  harbin: '哈尔滨',
  hefei: '合肥',
  hohhot: '呼和浩特',
  huizhou: '惠州',
  jiaxing: '嘉兴',
  jinan: '济南',
  jinhua: '金华',
  kunming: '昆明',
  lanzhou: '兰州',
  lhasa: '拉萨',
  nanchang: '南昌',
  nanjing: '南京',
  nanning: '南宁',
  nantong: '南通',
  ningbo: '宁波',
  qingdao: '青岛',
  quanzhou: '泉州',
  shenyang: '沈阳',
  shenzhen: '深圳',
  shijiazhuang: '石家庄',
  suzhou: '苏州',
  taizhou: '台州',
  urumqi: '乌鲁木齐',
  wenzhou: '温州',
  wuhan: '武汉',
  wuxi: '无锡',
  xiamen: '厦门',
  xian: '西安',
  xining: '西宁',
  xuzhou: '徐州',
  yinchuan: '银川',
  zhengzhou: '郑州',
  zhongshan: '中山',
  zhuhai: '珠海',
  westlake: '西湖',
  xihu: '西湖',
  xihudistrict: '西湖',
};

export type VendoredChinaKind = 'province' | 'city' | 'county';

/**
 * Shipped coordinate system of each built-in pack, measured against
 * WGS84 references rather than assumed from the file name.
 *
 * - `china_province` / `china_county`: WGS84 / CGCS2000.
 * - `china_region`: **GCJ-02** (DataV GeoAtlas `areas_v3`). Measured on the 16
 *   Beijing districts that exist in both this pack and `china_county`: the
 *   area-weighted centroids sit `+565 m` east / `+143 m` north of the county
 *   pack, against a GCJ-02 theoretical offset of `+533 m / +155 m` at
 *   Tiananmen. Inverting GCJ-02 collapses the same measurement to
 *   `+14 m / +2.5 m`, i.e. the residual generalisation difference between the
 *   two packs.
 *
 * Because these three packs are merged into one layer chain, a pack declared
 * `WGS84` here is passed through untouched and only `city` is rewritten.
 */
export const vendoredChinaBoundarySources: Record<
  VendoredChinaKind,
  { url: string; crs: Exclude<ChinaBoundaryCrs, 'unknown'> }
> = {
  province: { url: 'map/china/china_province.geojson.gz', crs: 'WGS84' },
  city: { url: 'map/china/china_region.geojson.gz', crs: 'GCJ02' },
  county: { url: 'map/china/china_county.geojson.gz', crs: 'WGS84' },
};

const vendoredChinaCache = new Map<VendoredChinaKind, Promise<GeoFeatureCollection>>();

/**
 * Load a built-in pack and normalise it to WGS84.
 *
 * The conversion happens here — once, after decompression and before the
 * promise is cached — so it never runs per render. `city` is the only pack
 * that actually moves; the WGS84 packs short-circuit inside
 * `projectChinaBoundaryToWgs84` and are returned by identity, so they cost
 * nothing and stay byte-identical.
 *
 * The compliance geometry (`ten_dash`, `huangyan`, `china_borders`) is loaded
 * by `loadChinaComplianceAssets()` and deliberately does not go through here:
 * it is reviewed geometry and must never be rewritten.
 */
export function loadVendoredChinaCollection(kind: VendoredChinaKind, signal?: AbortSignal): Promise<GeoFeatureCollection> {
  let pending = vendoredChinaCache.get(kind);
  if (!pending) {
    const { url, crs } = vendoredChinaBoundarySources[kind];
    pending = fetchGzJson<GeoFeatureCollection>(url, signal)
      .then((collection) => projectChinaBoundaryToWgs84(collection, crs))
      .catch((error) => {
        vendoredChinaCache.delete(kind);
        throw error;
      });
    vendoredChinaCache.set(kind, pending);
  }
  return pending;
}

export async function loadChinaComplianceAssets(): Promise<ChinaComplianceAssets> {
  const [tenDash, huangyan, borders] = await Promise.all([
    fetchGzJson<GeoFeatureCollection>('map/china/ten_dash.geojson'),
    fetchGzJson<GeoFeatureCollection>('map/china/huangyan.geojson'),
    fetchGzJson<GeoFeatureCollection>('map/china/china_borders.geojson.gz'),
  ]);
  return { tenDash, huangyan, borders };
}

export async function loadChinaMapAssets(): Promise<ChinaMapAssets> {
  const [country, adminIndex] = await Promise.all([
    loadVendoredChinaCollection('province'),
    loadChinaAdminIndex(),
  ]);
  return {
    country: country ?? emptyFeatureCollection,
    adminIndex,
  };
}

export type MergedChinaBoundary = {
  collection: GeoFeatureCollection;
  sourceSummary: ChinaAdministrativeMap['sourceSummary'];
};

const WGS84_CRS_TOKENS = new Set(['WGS84', 'WGS-84', 'EPSG:4326', '4326', 'CRS84', 'OGC:CRS84', 'GCS_WGS_1984']);
const GCJ02_CRS_TOKENS = new Set(['GCJ02', 'GCJ-02', 'GCJ02LL', 'AMAP', 'AUTONAVI']);
const BD09_CRS_TOKENS = new Set(['BD09', 'BD-09', 'BD09LL', 'BAIDU']);
/**
 * Recognised-but-unusable declarations. Projected metres must never be fed to a
 * lon/lat pipeline, and silently reinterpreting them would draw the boundary
 * thousands of kilometres away, so they resolve to `unknown` (fail-closed).
 */
const PROJECTED_CRS_TOKENS = new Set(['EPSG:3857', '3857', 'EPSG:900913', 'EPSG:3785', 'EPSG:102100']);

/**
 * Accepted CRS declaration shapes, all of which must be spelled out explicitly:
 * - plain string: `"WGS84"`, `"EPSG:4326"`, `"GCJ-02"`, …
 * - legacy GeoJSON 2008 object: `{ "type": "name", "properties": { "name": "urn:ogc:def:crs:OGC:1.3:CRS84" } }`
 */
function extractCrsToken(value: unknown): string {
  if (typeof value === 'string') {
    return normalizeCrsToken(value);
  }
  if (!value || typeof value !== 'object') {
    return '';
  }
  const record = value as Record<string, unknown>;
  const properties = record.properties;
  if (properties && typeof properties === 'object') {
    const name = (properties as Record<string, unknown>).name;
    if (typeof name === 'string') {
      return normalizeCrsToken(name);
    }
  }
  return '';
}

function normalizeCrsToken(raw: string): string {
  let token = raw.trim().toUpperCase().replace(/\s+/g, '');
  if (!token) {
    return '';
  }
  if (PROJECTED_CRS_TOKENS.has(token)) {
    return '';
  }
  // urn:ogc:def:crs:OGC:1.3:CRS84 -> CRS84 ; urn:ogc:def:crs:EPSG::4326 -> EPSG::4326
  const urn = token.match(/^URN:OGC:DEF:CRS:(?:OGC:[\d.]+:)?(.+)$/);
  if (urn) {
    token = urn[1];
  }
  return token.replace(/^EPSG:{1,2}/, 'EPSG:');
}

/**
 * Whether a declaration is *present*, regardless of whether it is understood.
 *
 * Kept separate from `extractCrsToken` so the operator can be told apart:
 * "this source declares nothing" from "this source declares something we
 * cannot use". `extractCrsToken` deliberately blanks recognised-but-unusable
 * tokens (projected CRS), which would collapse the two cases into one.
 */
function hasCrsDeclaration(value: unknown): boolean {
  if (typeof value === 'string') {
    return value.trim().length > 0;
  }
  if (!value || typeof value !== 'object') {
    return false;
  }
  const properties = (value as Record<string, unknown>).properties;
  if (properties && typeof properties === 'object') {
    const name = (properties as Record<string, unknown>).name;
    return typeof name === 'string' && name.trim().length > 0;
  }
  return false;
}

/**
 * Map an external CRS declaration onto a supported CRS.
 *
 * Anything missing, blank, misspelled, projected, or otherwise unrecognised
 * resolves to `unknown` — callers must then refuse to render the data.
 */
export function parseChinaBoundaryCrs(value: unknown): ChinaBoundaryCrs {
  const token = extractCrsToken(value);
  if (!token) {
    return 'unknown';
  }
  if (WGS84_CRS_TOKENS.has(token)) return 'WGS84';
  if (GCJ02_CRS_TOKENS.has(token)) return 'GCJ02';
  if (BD09_CRS_TOKENS.has(token)) return 'BD09';
  return 'unknown';
}

/** In-band declarations: the GeoJSON document states its own CRS. */
function inBandCrsDeclaration(collection: unknown): unknown {
  if (!collection || typeof collection !== 'object') {
    return undefined;
  }
  const record = collection as Record<string, unknown>;
  return record.crs ?? record.coordinate_system ?? record.coordinateSystem;
}

const CRS_SEMI_MAJOR_AXIS = 6378245.0;
const CRS_ECCENTRICITY_SQ = 0.00669342162296594323;
const BD09_X_PI = (Math.PI * 3000.0) / 180.0;
/** GCJ-02 applies no offset outside this box; there WGS84 === GCJ-02. */
const CRS_OFFSET_BOX = { minLon: 72.004, maxLon: 137.8347, minLat: 0.8293, maxLat: 55.8271 };

function isOutsideCrsOffsetBox(lon: number, lat: number): boolean {
  return lon < CRS_OFFSET_BOX.minLon
    || lon > CRS_OFFSET_BOX.maxLon
    || lat < CRS_OFFSET_BOX.minLat
    || lat > CRS_OFFSET_BOX.maxLat;
}

function gcjOffsetLat(lon: number, lat: number): number {
  const x = lon - 105.0;
  const y = lat - 35.0;
  let offset = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
  offset += ((20.0 * Math.sin(6.0 * x * Math.PI)) + (20.0 * Math.sin(2.0 * x * Math.PI))) * 2.0 / 3.0;
  offset += ((20.0 * Math.sin(y * Math.PI)) + (40.0 * Math.sin(y / 3.0 * Math.PI))) * 2.0 / 3.0;
  offset += ((160.0 * Math.sin(y / 12.0 * Math.PI)) + (320 * Math.sin(y * Math.PI / 30.0))) * 2.0 / 3.0;
  return offset;
}

function gcjOffsetLon(lon: number, lat: number): number {
  const x = lon - 105.0;
  const y = lat - 35.0;
  let offset = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
  offset += ((20.0 * Math.sin(6.0 * x * Math.PI)) + (20.0 * Math.sin(2.0 * x * Math.PI))) * 2.0 / 3.0;
  offset += ((20.0 * Math.sin(x * Math.PI)) + (40.0 * Math.sin(x / 3.0 * Math.PI))) * 2.0 / 3.0;
  offset += ((150.0 * Math.sin(x / 12.0 * Math.PI)) + (300.0 * Math.sin(x / 30.0 * Math.PI))) * 2.0 / 3.0;
  return offset;
}

/** WGS84 → GCJ-02. Public, deterministic, invertible; used by the inverse below. */
export function wgs84ToGcj02(lon: number, lat: number): [number, number] {
  if (isOutsideCrsOffsetBox(lon, lat)) {
    return [lon, lat];
  }
  let dLat = gcjOffsetLat(lon, lat);
  let dLon = gcjOffsetLon(lon, lat);
  const radLat = lat / 180.0 * Math.PI;
  let magic = Math.sin(radLat);
  magic = 1 - CRS_ECCENTRICITY_SQ * magic * magic;
  const sqrtMagic = Math.sqrt(magic);
  dLat = (dLat * 180.0) / ((CRS_SEMI_MAJOR_AXIS * (1 - CRS_ECCENTRICITY_SQ)) / (magic * sqrtMagic) * Math.PI);
  dLon = (dLon * 180.0) / (CRS_SEMI_MAJOR_AXIS / sqrtMagic * Math.cos(radLat) * Math.PI);
  return [lon + dLon, lat + dLat];
}

/** GCJ-02 → WGS84. Fixed-point inversion of `wgs84ToGcj02` (converges to <1e-10 deg). */
export function gcj02ToWgs84(lon: number, lat: number): [number, number] {
  if (isOutsideCrsOffsetBox(lon, lat)) {
    return [lon, lat];
  }
  let wLon = lon;
  let wLat = lat;
  for (let step = 0; step < 12; step += 1) {
    const [gLon, gLat] = wgs84ToGcj02(wLon, wLat);
    const dLon = gLon - lon;
    const dLat = gLat - lat;
    if (Math.abs(dLon) < 1e-11 && Math.abs(dLat) < 1e-11) {
      break;
    }
    wLon -= dLon;
    wLat -= dLat;
  }
  return [wLon, wLat];
}

/** BD-09 → WGS84 (BD-09 → GCJ-02 is exact; then invert GCJ-02). */
export function bd09ToWgs84(lon: number, lat: number): [number, number] {
  const x = lon - 0.0065;
  const y = lat - 0.006;
  const z = Math.sqrt(x * x + y * y) - 0.00002 * Math.sin(y * BD09_X_PI);
  const theta = Math.atan2(y, x) - 0.000003 * Math.cos(x * BD09_X_PI);
  return gcj02ToWgs84(z * Math.cos(theta), z * Math.sin(theta));
}

function isGeoPosition(value: unknown): value is [number, number] {
  return Array.isArray(value) && value.length >= 2 && typeof value[0] === 'number' && typeof value[1] === 'number';
}

function mapGeometryCoordinates(
  value: unknown,
  project: (lon: number, lat: number) => [number, number],
): unknown {
  if (isGeoPosition(value)) {
    return project(value[0], value[1]);
  }
  if (Array.isArray(value)) {
    return value.map((child) => mapGeometryCoordinates(child, project));
  }
  return value;
}

/** Rewrite every coordinate of a collection into WGS84. `WGS84` input is returned untouched. */
export function projectChinaBoundaryToWgs84(
  collection: GeoFeatureCollection,
  crs: Exclude<ChinaBoundaryCrs, 'unknown'>,
): GeoFeatureCollection {
  if (crs === 'WGS84') {
    return collection;
  }
  const project = (lon: number, lat: number): [number, number] => (
    crs === 'BD09' ? bd09ToWgs84(lon, lat) : gcj02ToWgs84(lon, lat)
  );
  return {
    type: 'FeatureCollection',
    features: collection.features.map((feature) => {
      const geometry = feature.geometry as { coordinates?: unknown } | null | undefined;
      if (!geometry || typeof geometry !== 'object') {
        return feature;
      }
      return {
        ...feature,
        geometry: {
          ...(geometry as Record<string, unknown>),
          coordinates: mapGeometryCoordinates(geometry.coordinates, project),
        },
      };
    }),
  };
}

/** Generous box covering the whole territory the nine-dash line encloses. */
const CHINA_ADMISSION_BOUNDS = { minLon: 70, maxLon: 138, minLat: 0, maxLat: 56 };

/**
 * Backstop against a misdeclared or projected source: every coordinate of an
 * admitted Chinese administrative boundary must land inside this box after
 * conversion. Rejecting here only costs an optional overlay — drawing a
 * boundary at the wrong place costs compliance.
 */
export function isWithinChinaBounds(collection: GeoFeatureCollection): boolean {
  let positions = 0;
  const visit = (value: unknown): boolean => {
    if (isGeoPosition(value)) {
      const [lon, lat] = value;
      if (!Number.isFinite(lon) || !Number.isFinite(lat)) {
        return false;
      }
      positions += 1;
      return lon >= CHINA_ADMISSION_BOUNDS.minLon
        && lon <= CHINA_ADMISSION_BOUNDS.maxLon
        && lat >= CHINA_ADMISSION_BOUNDS.minLat
        && lat <= CHINA_ADMISSION_BOUNDS.maxLat;
    }
    if (Array.isArray(value)) {
      return value.every(visit);
    }
    return true;
  };
  const inside = collection.features.every((feature) => visit((feature.geometry as { coordinates?: unknown } | null)?.coordinates));
  return inside && positions > 0;
}

/**
 * Whether an external feature may be drawn, keyed by its canonical 6-digit code.
 *
 * Two hard requirements, both fail-closed:
 * 1. District / county level only (`xxYYzz`, not ending in `00`). The endpoint is
 *    documented as a district-level supplement; letting an external province or
 *    city polygon win the merge would *replace* a GS(2024)0650 / GS(2025)5996
 *    boundary with an unvetted one.
 * 2. Inside the requested adcode scope. The backend returns the whole configured
 *    file per adcode without filtering, so the client has to scope it.
 */
export function isAllowedExternalAdcode(code: string, allowedAdcodes: string[]): boolean {
  if (!/^\d{6}$/.test(code) || code.endsWith('00')) {
    return false;
  }
  return allowedAdcodes.some((raw) => {
    if (!/^\d{6}$/.test(raw)) {
      return false;
    }
    if (raw === code) {
      return true;
    }
    // city parent (xxYY00) -> its districts ; 直辖市 province (xx0000) -> its districts
    if (raw.endsWith('00') && raw.slice(0, 4) === code.slice(0, 4)) {
      return true;
    }
    return raw.endsWith('0000') && raw.slice(0, 2) === code.slice(0, 2);
  });
}

/**
 * Gate an external China boundary collection before it can reach the map.
 *
 * Fail-closed in every uncertain case: no CRS declaration, an unsupported CRS,
 * no verifiable district-level adcode, or coordinates outside China. A refused
 * collection returns `null` so callers keep rendering the built-in boundaries.
 */
export function admitExternalChinaBoundary(options: {
  geojson: unknown;
  /** Explicit declaration from the API (`coordinate_system`) — takes precedence. */
  declaredCrs?: unknown;
  allowedAdcodes: string[];
}): ExternalChinaBoundaryAdmission {
  const collection = asFeatureCollection(options.geojson);
  if (collection.features.length === 0) {
    return { collection: null, rejection: null };
  }
  const declared = options.declaredCrs ?? inBandCrsDeclaration(options.geojson);
  const hasDeclaration = hasCrsDeclaration(declared);
  const crs = parseChinaBoundaryCrs(declared);
  if (crs === 'unknown') {
    return { collection: null, rejection: hasDeclaration ? 'unsupported-crs' : 'no-crs' };
  }
  const projected = projectChinaBoundaryToWgs84(collection, crs);
  const features = projected.features.filter((feature) => (
    isAllowedExternalAdcode(chinaFeatureAdcode(feature.properties ?? {}), options.allowedAdcodes)
  ));
  if (features.length === 0) {
    return { collection: null, rejection: 'no-adcode' };
  }
  const admitted: GeoFeatureCollection = { type: 'FeatureCollection', features };
  if (!isWithinChinaBounds(admitted)) {
    return { collection: null, rejection: 'out-of-range' };
  }
  return { collection: admitted, rejection: null };
}

/**
 * Merge builtin + offline + external China boundary layers into a single
 * deduplicated GeoFeatureCollection. Priority: external > offline > builtin.
 * Used by both the MapLibre overlay and the lightweight SVG sourceSummary path.
 *
 * Dedup key is the canonical 6-digit code from `chinaFeatureAdcode()`, which is
 * the only identifier both code families share: the province/county packs carry
 * it as `gb` (`"156440304"`), the city pack and external sources as `adcode`.
 *
 * A feature with no resolvable code used to fall back to `idx-N`, which made the
 * key unique per feature and silently disabled deduplication entirely — external
 * geometry then stacked on top of the built-in boundary and produced a double
 * border. Now a keyless feature is only ever *appended* (never merged), and a
 * keyless **external** feature is dropped outright: an unidentified polygon
 * cannot be proven not to duplicate a compliant boundary, so it must not paint.
 */
export function mergeChinaBoundaries(
  builtin: GeoFeatureCollection | null,
  offline: GeoFeatureCollection | null,
  external: GeoFeatureCollection | null,
): MergedChinaBoundary {
  const sources = [
    { rank: 1, features: builtin?.features ?? [] },
    { rank: 2, features: offline?.features ?? [] },
    { rank: 3, features: external?.features ?? [] },
  ];
  const byCode = new Map<string, { rank: number; feature: WorldFeature }>();
  const order: string[] = [];
  /** Unkeyed builtin/offline extras (border lines, the nine-dash feature) — never merged, only kept. */
  const extras: WorldFeature[] = [];
  for (const source of sources) {
    for (const feature of source.features) {
      const key = chinaFeatureAdcode(feature.properties ?? {});
      if (!key) {
        if (source.rank !== 3) {
          extras.push(feature);
        }
        continue;
      }
      if (!byCode.has(key)) {
        order.push(key);
      }
      const existing = byCode.get(key);
      if (!existing || source.rank > existing.rank) {
        byCode.set(key, { rank: source.rank, feature });
      }
    }
  }
  const features = [
    ...order.map((key) => byCode.get(key)!.feature),
    ...extras,
  ].map(ensureFeatureAdminLevel);
  const hasExternal = Boolean(external && external.features.length > 0);
  const levels = new Set(features.map((feature) => inferAdminLevel(feature)));
  let sourceSummary: ChinaAdministrativeMap['sourceSummary'];
  if (hasExternal) {
    sourceSummary = 'external';
  } else if (levels.has('district') || levels.has('county')) {
    sourceSummary = 'builtin-district';
  } else if (levels.has('city')) {
    sourceSummary = 'builtin-city';
  } else {
    sourceSummary = 'builtin-province';
  }
  return { collection: { type: 'FeatureCollection', features }, sourceSummary };
}

export function createChinaAdministrativeMap(
  assets: ChinaMapAssets,
  regions: AttackRegion[],
  customBoundary?: GeoFeatureCollection | null,
  builtinBoundary?: GeoFeatureCollection | null,
): ChinaAdministrativeMap {
  const merged = mergeChinaBoundaries(
    assets.country.features.length > 0 ? assets.country : emptyFeatureCollection,
    builtinBoundary ?? null,
    customBoundary ?? null,
  );
  const countryBoundary = merged.collection;
  const projection = geoMercator().fitExtent(
    [[30, 24], [chinaMapWidth - 30, chinaMapHeight - 24]],
    countryBoundary as any,
  );
  const path = geoPath(projection);
  // The SVG layer chain is intentionally lightweight: only `sourceSummary`
  // is consumed today, so we avoid projecting every feature for an unused
  // layer list. Layers remain typed for future SVG rendering.
  return {
    provinceLayers: [],
    cityLayers: [],
    districtLayers: [],
    customLayers: [],
    projection,
    path,
    viewBox: chinaViewBox,
    width: chinaMapWidth,
    height: chinaMapHeight,
    sourceSummary: merged.sourceSummary,
  };
}

export function normalizeChinaAdminName(value: string) {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/\b(province|city|district|county|prefecture|municipality|autonomous|region|special administrative region)\b/g, '')
    .replace(/中国|中华人民共和国/g, '')
    .replace(/省|市|区|县|自治州|自治县|自治区|特别行政区|地区|盟|新区/g, '')
    .replace(/维吾尔|壮族|回族|藏族|蒙古族|哈萨克|朝鲜族|苗族|土家族|布依族|侗族|彝族|羌族|傣族|景颇族|傈僳族|白族/g, '')
    .replace(/[^a-z0-9\u4e00-\u9fff]+/g, '');
  return chinaAdminNameAliases[normalized] ?? normalized;
}

export function normalizeChinaAdminCode(value: unknown, fallbackName = '', adminIndex?: ChinaAdminIndex) {
  const raw = String(value ?? '').trim();
  if (/^\d{6}$/.test(raw)) {
    return raw;
  }
  return adminIndex ? (adminCodeFromName(fallbackName || raw, adminIndex) ?? '') : '';
}

export function adminCodeCandidatesFromRegion(region: AttackRegion, adminIndex: ChinaAdminIndex) {
  const codes = new Set<string>();
  const direct = normalizeChinaAdminCode(region.adminCode, '', adminIndex);
  if (direct) {
    codes.add(direct);
  }
  const parts = locationParts(region.locationName);
  for (const part of parts) {
    for (const code of codesFromName(part, codes, adminIndex)) {
      codes.add(code);
    }
  }
  for (const code of Array.from(codes)) {
    codes.add(provinceCode(code));
    const city = cityCode(code);
    if (city) {
      codes.add(city);
    }
  }
  return Array.from(codes).filter(Boolean);
}

export function boundaryAdcodesFromRegions(regions: AttackRegion[], adminIndex?: ChinaAdminIndex) {
  if (!adminIndex) {
    return [];
  }
  const adcodes = new Set<string>();
  for (const region of regions) {
    for (const code of adminCodeCandidatesFromRegion(region, adminIndex)) {
      const city = cityCode(code);
      if (city && city !== provinceCode(code)) {
        adcodes.add(city);
      }
      if (directAdminProvincePrefixes.has(code.slice(0, 2))) {
        adcodes.add(provinceCode(code));
      }
      if (/^\d{6}$/.test(code) && !code.endsWith('0000') && !code.endsWith('00')) {
        adcodes.add(code);
      }
    }
  }
  return Array.from(adcodes).slice(0, 12);
}


/**
 * Offline China admin boundaries from local `china-map-echarts` (no network).
 * - `xx0000.json` (province parent) → city polygons (or districts for 直辖市)
 * - `xxYY00.json` (city parent) → district / county polygons
 *
 * Progressive load (avoids blocking china mode on ~300 city-parent files / ~26MB):
 * 1. Province parents always (city outlines)
 * 2. preferAdcodes city/district parents first (attack-relevant 区县)
 * 3. Remaining city parents only when includeDistricts (default false)
 * `onPartial` receives cumulative FeatureCollections after each phase.
 * `signal` aborts in-flight fetches when the page switches mode / unmounts.
 */
export async function loadOfflineChinaBoundaryTree(options: {
  includeDistricts?: boolean;
  preferAdcodes?: string[];
  onPartial?: (collection: GeoFeatureCollection) => void;
  signal?: AbortSignal;
} = {}): Promise<GeoFeatureCollection> {
  const includeDistricts = options.includeDistricts ?? false;
  const signal = options.signal;
  if (signal?.aborted) return emptyFeatureCollection;

  const emit = (features: WorldFeature[]): GeoFeatureCollection => {
    const collection: GeoFeatureCollection = {
      type: 'FeatureCollection',
      features: dedupeFeaturesByAdcode(features).map(ensureFeatureAdminLevel),
    };
    options.onPartial?.(collection);
    return collection;
  };

  // Phase 1: city-level polygons (includes 直辖市 parent features) always.
  const cityCollection = await loadVendoredChinaCollection('city', signal);
  if (signal?.aborted) return emptyFeatureCollection;
  const collected: WorldFeature[] = [...cityCollection.features];
  let result = emit(collected);

  const prefer = new Set<string>();
  for (const rawCode of options.preferAdcodes ?? []) {
    const code = String(rawCode);
    if (!/^\d{6}$/.test(code)) continue;
    if (directAdminProvincePrefixes.has(code.slice(0, 2))) {
      prefer.add(provinceCode(code));
    }
    const city = cityCode(code);
    if (city) prefer.add(city);
    if (!code.endsWith('00')) prefer.add(code);
  }

  const needDistricts = includeDistricts || prefer.size > 0;
  if (needDistricts) {
    const countyCollection = await loadVendoredChinaCollection('county', signal);
    if (signal?.aborted) return result;
    const countyByCode = new Map<string, WorldFeature>();
    const countyByCity = new Map<string, WorldFeature[]>();
    const countyByProvince = new Map<string, WorldFeature[]>();
    for (const feature of countyCollection.features) {
      const code = chinaFeatureAdcode(feature.properties ?? {});
      if (!code) continue;
      countyByCode.set(code, feature);
      const province = provinceCode(code);
      const city = cityCode(code);
      const provinceBucket = countyByProvince.get(province) ?? [];
      provinceBucket.push(feature);
      countyByProvince.set(province, provinceBucket);
      if (city) {
        const cityBucket = countyByCity.get(city) ?? [];
        cityBucket.push(feature);
        countyByCity.set(city, cityBucket);
      }
    }
    // Preferred districts are already in the full pack.
    const preferredCodes = includeDistricts ? [] : [...prefer];
    for (const code of preferredCodes) {
      if (/^\d{6}$/.test(code) && !code.endsWith('0000') && !code.endsWith('00')) {
        const feature = countyByCode.get(code);
        if (feature) collected.push(feature);
      }
    }
    for (const code of preferredCodes) {
      if (/^\d{6}$/.test(code) && !code.endsWith('0000') && code.endsWith('00')) {
        for (const feature of countyByCity.get(code) ?? []) collected.push(feature);
      }
    }
    for (const code of preferredCodes) {
      if (/^\d{6}$/.test(code) && code.endsWith('0000') && directAdminProvincePrefixes.has(code.slice(0, 2))) {
        for (const feature of countyByProvince.get(code) ?? []) collected.push(feature);
      }
    }
    if (includeDistricts) {
      for (const feature of countyCollection.features) collected.push(feature);
    }
    result = emit(collected);
  }

  return result;
}



function dedupeFeaturesByAdcode(features: WorldFeature[]): WorldFeature[] {
  const seen = new Set<string>();
  const out: WorldFeature[] = [];
  for (const feature of features) {
    const props = feature.properties ?? {};
    const key = (chinaFeatureAdcode(props) || String(props.id ?? feature.id ?? '')).trim() || `idx-${out.length}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(feature);
  }
  return out;
}

export function chinaBoundarySourceLabel(source: ChinaAdministrativeMap['sourceSummary'], t: (key: string) => string) {
  switch (source) {
    case 'external':
      return t('attackMap.boundaryExternalDistrict');
    case 'builtin-district':
      return t('attackMap.boundaryBuiltinDistrict');
    case 'builtin-city':
      return t('attackMap.boundaryBuiltinCity');
    default:
      return t('attackMap.boundaryBuiltinProvince');
  }
}


/**
 * code→name 索引由构建期脚本 scripts/build-china-admin-index.mjs 从
 * china_aux.geojson.gz 提取生成（public/map/lookup/china_admin_index.json），
 * 避免运行时为建索引拉取 8MB 完整几何数据。
 */
async function loadChinaAdminIndex(): Promise<ChinaAdminIndex> {
  const entries = await fetchGzJson<Array<{ code: string; name: string }>>('map/lookup/china_admin_index.json');
  const nameToCodes = new Map<string, string[]>();
  const codeToName = new Map<string, string>();
  for (const entry of Array.isArray(entries) ? entries : []) {
    const code = String(entry?.code ?? '').trim();
    const name = String(entry?.name ?? '').trim();
    if (!/^\d{6}$/.test(code) || !name) continue;
    codeToName.set(code, name);
    const normalized = normalizeChinaAdminName(name);
    if (!normalized) continue;
    const items = nameToCodes.get(normalized) ?? [];
    items.push(code);
    nameToCodes.set(normalized, items);
  }
  return { nameToCodes, codeToName };
}



function toLayer(
  feature: WorldFeature,
  index: number,
  intensity: Map<string, { attacks: number; level: ThreatLevel }>,
  source: ChinaBoundaryLayer['source'],
  path: ReturnType<typeof geoPath>,
  adminIndex: ChinaAdminIndex,
): ChinaBoundaryLayer | null {
  const properties = feature.properties ?? {};
  const name = String(properties.name ?? properties.fullname ?? properties.NAME ?? '').trim();
  const adcode = normalizeChinaAdminCode(properties.adcode ?? properties.id ?? feature.id, name, adminIndex) || `feature-${index}`;
  const d = path(feature as any) ?? '';
  if (!d) {
    return null;
  }
  const active = lookupIntensity(intensity, adcode, name);
  const englishName = String(properties.englishName ?? properties.en ?? '').trim();
  const centroid = path.centroid(feature as any);
  const labelPoint = Number.isFinite(centroid[0]) && Number.isFinite(centroid[1])
    ? { x: centroid[0], y: centroid[1] }
    : undefined;
  return {
    key: `${source}-${adcode}-${index}`,
    adcode,
    name: name || adminIndex.codeToName.get(adcode) || adcode,
    ...(englishName ? { englishName } : {}),
    ...(labelPoint ? { labelPoint } : {}),
    d,
    level: active?.level ?? 'neutral',
    attacks: active?.attacks ?? 0,
    source,
  };
}

function buildRegionIntensity(regions: AttackRegion[], level: 'province' | 'city' | 'district', adminIndex: ChinaAdminIndex) {
  const map = new Map<string, { attacks: number; level: ThreatLevel; severityRank: number }>();
  const maxAttacks = Math.max(1, ...regions.map((region) => region.attacks));
  for (const region of regions) {
    const keys = new Set<string>();
    for (const code of adminCodeCandidatesFromRegion(region, adminIndex)) {
      if (level === 'province') {
        keys.add(provinceCode(code));
      } else if (level === 'city') {
        keys.add(cityCode(code) || provinceCode(code));
      } else {
        keys.add(code);
        const city = cityCode(code);
        if (city) {
          keys.add(city);
        }
      }
    }
    for (const part of locationParts(region.locationName)) {
      const normalized = normalizeChinaAdminName(part);
      if (normalized) {
        keys.add(normalized);
      }
    }
    const normalizedName = normalizeChinaAdminName(region.locationName);
    if (normalizedName) {
      keys.add(normalizedName);
    }
    for (const key of keys) {
      const current = map.get(key) ?? { attacks: 0, level: 'low' as ThreatLevel, severityRank: 0 };
      current.attacks += region.attacks;
      current.severityRank = Math.max(current.severityRank, region.severityRank);
      current.level = threatLevelFromRegion(region, current.attacks, maxAttacks);
      map.set(key, current);
    }
  }
  return map;
}

function lookupIntensity(intensity: Map<string, { attacks: number; level: ThreatLevel }>, adcode: string, name: string) {
  return intensity.get(adcode)
    ?? intensity.get(cityCode(adcode) ?? '')
    ?? intensity.get(provinceCode(adcode))
    ?? intensity.get(normalizeChinaAdminName(name));
}

function codesFromName(value: string, knownCodes: Set<string>, adminIndex: ChinaAdminIndex) {
  const normalized = normalizeChinaAdminName(value);
  if (!normalized) {
    return [];
  }
  const matches = adminIndex.nameToCodes.get(normalized) ?? [];
  if (matches.length <= 1) {
    return matches;
  }
  const scoped = matches.filter((code) => {
    const province = provinceCode(code);
    const city = cityCode(code);
    return knownCodes.has(province) || (city ? knownCodes.has(city) : false);
  });
  return scoped.length > 0 ? scoped : matches;
}

function adminCodeFromName(value: string, adminIndex: ChinaAdminIndex) {
  return codesFromName(value, new Set(), adminIndex)[0] ?? '';
}

function locationParts(value: string) {
  return value.split(/\s+路\s+|\s*·\s*|\s*\/\s*/).map((part) => part.trim()).filter(Boolean);
}

function provinceCode(code: string) {
  return /^\d{6}$/.test(code) ? `${code.slice(0, 2)}0000` : code;
}

function cityCode(code: string) {
  if (!/^\d{6}$/.test(code) || code.endsWith('0000')) {
    return '';
  }
  if (directAdminProvincePrefixes.has(code.slice(0, 2))) {
    return provinceCode(code);
  }
  return `${code.slice(0, 4)}00`;
}

function readFeatureLevel(feature: WorldFeature) {
  return inferAdminLevel(feature);
}

/** Ensure paint/style `level` is present (province | city | district | county). */
function ensureFeatureAdminLevel(feature: WorldFeature): WorldFeature {
  const properties = feature.properties ?? {};
  const level = inferAdminLevel(feature);
  const adcode = chinaFeatureAdcode(properties);
  const nextAdcode = String(properties.adcode ?? '') || adcode;
  if (String(properties.level ?? '') === level && String(properties.adcode ?? '') === nextAdcode) {
    return feature;
  }
  return {
    ...feature,
    properties: {
      ...properties,
      ...(nextAdcode ? { adcode: nextAdcode } : {}),
      level,
    },
  };
}

function inferAdminLevel(feature: WorldFeature): string {
  const existing = String(feature.properties?.level ?? '').toLowerCase();
  if (existing === 'province' || existing === 'city' || existing === 'district' || existing === 'county') {
    return existing;
  }
  const code = chinaFeatureAdcode(feature.properties ?? {})
    || String(feature.properties?.adcode ?? feature.properties?.id ?? feature.id ?? '').trim();
  if (/^\d{6}$/.test(code)) {
    if (code.endsWith('0000')) {
      return 'province';
    }
    if (code.endsWith('00')) {
      return 'city';
    }
    return 'district';
  }
  return 'province';
}

function threatLevelFromRegion(region: AttackRegion, attacks: number, maxAttacks: number): ThreatLevel {
  const volume = attacks / Math.max(1, maxAttacks);
  if (region.severityRank >= 4 || attacks >= 50 || (attacks >= 20 && volume >= 0.6)) {
    return 'critical';
  }
  if (region.severityRank >= 3 || attacks >= 20 || volume >= 0.62) {
    return 'high';
  }
  if (region.severityRank >= 2 || attacks >= 6 || volume >= 0.28) {
    return 'medium';
  }
  return 'low';
}

function asNullableFeatureCollection(value: unknown): GeoFeatureCollection | null {
  const collection = asFeatureCollection(value);
  return collection.features.length > 0 ? collection : null;
}

function asFeatureCollection(value: unknown): GeoFeatureCollection {
  if (!value || typeof value !== 'object') {
    return { type: 'FeatureCollection', features: [] };
  }
  const record = value as GeoFeatureCollection;
  return record.type === 'FeatureCollection' && Array.isArray(record.features)
    ? record
    : { type: 'FeatureCollection', features: [] };
}

type GeoGeometryRecord = {
  type?: unknown;
  coordinates?: unknown;
};

function rewindBuiltinFeatureCollection(collection: GeoFeatureCollection): GeoFeatureCollection {
  return {
    ...collection,
    features: collection.features.map(rewindBuiltinFeature),
  };
}

function rewindBuiltinFeature(feature: WorldFeature): WorldFeature {
  const geometry = feature.geometry;
  if (!geometry || typeof geometry !== 'object') {
    return feature;
  }
  const record = geometry as GeoGeometryRecord;
  if (record.type === 'Polygon') {
    return {
      ...feature,
      geometry: {
        ...record,
        coordinates: orientPolygonRings(record.coordinates),
      },
    };
  }
  if (record.type === 'MultiPolygon') {
    return {
      ...feature,
      geometry: {
        ...record,
        coordinates: orientMultiPolygon(record.coordinates),
      },
    };
  }
  return feature;
}

function orientMultiPolygon(coordinates: unknown) {
  return Array.isArray(coordinates)
    ? coordinates.map((polygon) => orientPolygonRings(polygon))
    : coordinates;
}

/**
 * Normalise ring winding instead of unconditionally reversing every ring.
 * GeoJSON RFC 7946 requires exterior rings counter-clockwise (positive planar
 * signed area) and interior rings clockwise (negative). If a source polygon is
 * already wound that way we leave it untouched; otherwise we flip it.
 */
function orientPolygonRings(coordinates: unknown) {
  if (!Array.isArray(coordinates) || coordinates.length === 0) {
    return coordinates;
  }
  const rings = coordinates;
  const exteriorArea = signedRingArea(rings[0]);
  const exterior = exteriorArea < 0 ? [...(rings[0] as unknown[])].reverse() : rings[0];
  const wantHoleSign = -Math.sign(signedRingArea(exterior) || 1);
  const out: unknown[] = [exterior];
  for (let index = 1; index < rings.length; index += 1) {
    const hole = rings[index];
    const area = signedRingArea(hole);
    out.push(Math.sign(area) !== wantHoleSign ? [...(hole as unknown[])].reverse() : hole);
  }
  return out;
}

function signedRingArea(ring: unknown): number {
  if (!Array.isArray(ring) || ring.length < 3) {
    return 0;
  }
  let sum = 0;
  for (let index = 0; index < ring.length; index += 1) {
    const a = ring[index] as unknown[];
    const b = ring[(index + 1) % ring.length] as unknown[];
    const ax = Number(a?.[0]);
    const ay = Number(a?.[1]);
    const bx = Number(b?.[0]);
    const by = Number(b?.[1]);
    if (Number.isFinite(ax) && Number.isFinite(ay) && Number.isFinite(bx) && Number.isFinite(by)) {
      sum += ax * by - bx * ay;
    }
  }
  return sum / 2;
}
