import { geoMercator, geoPath } from 'd3-geo';
import type { AttackRegion, ThreatLevel, WorldFeature } from './attackMapData';

export type GeoFeatureCollection = {
  type: 'FeatureCollection';
  features: WorldFeature[];
};

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

type AdminRecord = {
  code: string;
  name: string;
  province?: string;
  city?: string;
  area?: string;
};

export type ChinaAdminIndex = {
  nameToCodes: Map<string, string[]>;
  codeToName: Map<string, string>;
};

const chinaMapWidth = 960;
const chinaMapHeight = 620;
const chinaViewBox = `0 0 ${chinaMapWidth} ${chinaMapHeight}`;
const directAdminProvincePrefixes = new Set(['11', '12', '31', '50', '71', '81', '82']);
const emptyFeatureCollection: GeoFeatureCollection = { type: 'FeatureCollection', features: [] };
let builtinAdcodeManifest: Promise<Set<string>> | null = null;
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

export async function loadChinaMapAssets(): Promise<ChinaMapAssets> {
  const [country, adminIndex] = await Promise.all([
    loadBuiltinFeatureCollection('100000'),
    loadChinaAdminIndex(),
  ]);
  return {
    country: country ?? emptyFeatureCollection,
    adminIndex,
  };
}

export function createChinaAdministrativeMap(
  assets: ChinaMapAssets,
  regions: AttackRegion[],
  customBoundary?: GeoFeatureCollection | null,
  builtinBoundary?: GeoFeatureCollection | null,
): ChinaAdministrativeMap {
  const countryBoundary = assets.country.features.length > 0 ? assets.country : emptyFeatureCollection;
  const projection = geoMercator().fitExtent(
    [[30, 24], [chinaMapWidth - 30, chinaMapHeight - 24]],
    countryBoundary as any,
  );
  const path = geoPath(projection);
  const provinceIntensity = buildRegionIntensity(regions, 'province', assets.adminIndex);
  const cityIntensity = buildRegionIntensity(regions, 'city', assets.adminIndex);
  const districtIntensity = buildRegionIntensity(regions, 'district', assets.adminIndex);
  const provinceLayers = countryBoundary.features
    .map((feature, index) => toLayer(feature, index, provinceIntensity, 'builtin-province', path, assets.adminIndex))
    .filter((item): item is ChinaBoundaryLayer => item !== null);
  // Offline pack tags levels explicitly: province parents hold city (or municipality
  // district) polygons; city parents hold district/county polygons.
  const offlineFeatures = builtinBoundary?.features ?? [];
  const cityLayers = offlineFeatures
    .filter((featureItem) => readFeatureLevel(featureItem) === 'city')
    .map((feature, index) => toLayer(feature, index, cityIntensity, 'builtin-city', path, assets.adminIndex))
    .filter((item): item is ChinaBoundaryLayer => item !== null);
  const districtLayers = offlineFeatures
    .filter((featureItem) => {
      const level = readFeatureLevel(featureItem);
      return level === 'district' || level === 'county';
    })
    .map((feature, index) => toLayer(feature, index, districtIntensity, 'builtin-district', path, assets.adminIndex))
    .filter((item): item is ChinaBoundaryLayer => item !== null);
  const customLayers = customBoundary?.features
    ?.map((feature, index) => toLayer(feature, index, districtIntensity, 'external', path, assets.adminIndex))
    .filter((item): item is ChinaBoundaryLayer => item !== null) ?? [];

  return {
    provinceLayers,
    cityLayers,
    districtLayers,
    customLayers,
    projection,
    path,
    viewBox: chinaViewBox,
    width: chinaMapWidth,
    height: chinaMapHeight,
    sourceSummary: customLayers.length > 0
      ? 'external'
      : districtLayers.length > 0
        ? 'builtin-district'
        : cityLayers.length > 0
          ? 'builtin-city'
          : 'builtin-province',
  };
}

export function projectChinaAdministrativePercent(map: ChinaAdministrativeMap, lon: number, lat: number) {
  const point = map.projection([lon, lat]);
  if (!point) {
    return null;
  }
  return { x: (point[0] / chinaMapWidth) * 100, y: (point[1] / chinaMapHeight) * 100 };
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

export async function loadBuiltinChinaBoundary(adcodes: string[]): Promise<GeoFeatureCollection | null> {
  const collections = await mapPool(adcodes, 10, (adcode) => loadBuiltinFeatureCollectionCached(adcode));
  const features = dedupeFeaturesByAdcode(collections.flatMap((collection) => collection?.features ?? []));
  return features.length > 0 ? { type: 'FeatureCollection', features } : null;
}

/**
 * Offline China admin boundaries from local `china-map-echarts` (no network).
 * - `xx0000.json` (province parent) → city polygons (or districts for 直辖市)
 * - `xxYY00.json` (city parent) → district / county polygons
 *
 * Progressive load (avoids blocking china mode on ~300 city-parent files / ~26MB):
 * 1. Province parents always (city outlines)
 * 2. preferAdcodes city/district parents first (attack-relevant 区县)
 * 3. Remaining city parents in background when includeDistricts
 * `onPartial` receives cumulative FeatureCollections after each phase.
 */
export async function loadOfflineChinaBoundaryTree(options: {
  includeDistricts?: boolean;
  preferAdcodes?: string[];
  onPartial?: (collection: GeoFeatureCollection) => void;
} = {}): Promise<GeoFeatureCollection> {
  const manifest = await loadBuiltinAdcodeManifest();
  const codes = Array.from(manifest).filter((code) => /^\d{6}$/.test(code));
  const codeSet = new Set(codes);
  const provinceParents = codes.filter((code) => code.endsWith('0000') && code !== '100000');
  const cityParents = codes.filter((code) => code.endsWith('00') && !code.endsWith('0000'));
  const cityParentSet = new Set(cityParents);

  const prefer = new Set<string>();
  for (const raw of options.preferAdcodes ?? []) {
    const code = String(raw);
    if (!/^\d{6}$/.test(code)) {
      continue;
    }
    if (directAdminProvincePrefixes.has(code.slice(0, 2))) {
      prefer.add(provinceCode(code));
    }
    const city = cityCode(code);
    if (city) {
      prefer.add(city);
    }
    if (!code.endsWith('00')) {
      prefer.add(code);
    }
  }

  const collected: WorldFeature[] = [];
  const loadedParents = new Set<string>();

  const emit = (): GeoFeatureCollection => {
    const features = dedupeFeaturesByAdcode(collected).map(ensureFeatureAdminLevel);
    const collection: GeoFeatureCollection = { type: 'FeatureCollection', features };
    options.onPartial?.(collection);
    return collection;
  };

  const loadParents = async (adcodes: string[], concurrency: number) => {
    const pending = adcodes.filter((code) => codeSet.has(code) && !loadedParents.has(code));
    if (pending.length === 0) {
      return;
    }
    for (const code of pending) {
      loadedParents.add(code);
    }
    const collections = await mapPool(pending, concurrency, (adcode) => loadBuiltinFeatureCollectionCached(adcode));
    for (const collection of collections) {
      if (collection?.features?.length) {
        collected.push(...collection.features);
      }
    }
  };

  // Phase 1: province parents → city (or 直辖市 district) polygons
  await loadParents(provinceParents, 12);
  let result = emit();

  // Prefer city/district parents related to log aggregates (paint attacked 区县 first)
  const preferParents = Array.from(prefer).filter(
    (code) => cityParentSet.has(code) || provinceParents.includes(code) || codeSet.has(code),
  );
  // Phase 2: attack-relevant city/district parents first (prefer already filtered)
  if (preferParents.length > 0) {
    await loadParents(preferParents, 10);
    result = emit();
  }

  // Phase 3: remaining city parents → full district capability (lower concurrency)
  if (options.includeDistricts) {
    const remainingCityParents = cityParents.filter((code) => !loadedParents.has(code));
    if (remainingCityParents.length > 0) {
      await loadParents(remainingCityParents, 6);
      result = emit();
    }
  }

  return result;
}

const offlineFeatureCache = new Map<string, Promise<GeoFeatureCollection | null>>();

function loadBuiltinFeatureCollectionCached(adcode: string) {
  let pending = offlineFeatureCache.get(adcode);
  if (!pending) {
    pending = loadBuiltinFeatureCollection(adcode);
    offlineFeatureCache.set(adcode, pending);
  }
  return pending;
}

async function mapPool<T, R>(items: T[], concurrency: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }
  const limit = Math.max(1, Math.min(concurrency, items.length));
  const results = new Array<R>(items.length);
  let cursor = 0;
  async function run() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index]);
    }
  }
  await Promise.all(Array.from({ length: limit }, () => run()));
  return results;
}

function dedupeFeaturesByAdcode(features: WorldFeature[]): WorldFeature[] {
  const seen = new Set<string>();
  const out: WorldFeature[] = [];
  for (const feature of features) {
    const props = feature.properties ?? {};
    const key = String(props.adcode ?? props.id ?? feature.id ?? '').trim() || `idx-${out.length}`;
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

async function loadBuiltinFeatureCollection(adcode: string) {
  if (!/^\d{6}$/.test(adcode)) {
    return null;
  }
  const availableAdcodes = await loadBuiltinAdcodeManifest();
  if (availableAdcodes.size > 0 && !availableAdcodes.has(adcode)) {
    return null;
  }
  const collection = asNullableFeatureCollection(await fetchChinaMapJSON(adcode));
  return collection ? rewindBuiltinFeatureCollection(collection) : null;
}

async function loadChinaAdminIndex(): Promise<ChinaAdminIndex> {
  const [provinceRecords, cityRecords, areaRecords] = await Promise.all([
    fetchAdminRecords('province/province.json'),
    fetchAdminRecords('city/city.json'),
    fetchAdminRecords('area/area.json'),
  ]);
  const records = [...provinceRecords, ...cityRecords, ...areaRecords];
  const nameToCodes = new Map<string, string[]>();
  const codeToName = new Map<string, string>();
  const add = (record: AdminRecord) => {
    if (!/^\d{6}$/.test(record.code)) {
      return;
    }
    codeToName.set(record.code, record.name);
    const normalized = normalizeChinaAdminName(record.name);
    if (!normalized) {
      return;
    }
    const items = nameToCodes.get(normalized) ?? [];
    items.push(record.code);
    nameToCodes.set(normalized, items);
  };
  records.forEach(add);
  return { nameToCodes, codeToName };
}

async function fetchChinaMapJSON(adcode: string) {
  try {
    const response = await fetch(chinaMapAssetURL(adcode), {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
  } catch {
    return null;
  }
}

async function loadBuiltinAdcodeManifest() {
  if (!builtinAdcodeManifest) {
    builtinAdcodeManifest = fetchBuiltinAdcodeManifest();
  }
  return builtinAdcodeManifest;
}

async function fetchBuiltinAdcodeManifest() {
  try {
    const response = await fetch(staticAssetURL('china-map-echarts/map/index.json'), {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      return new Set<string>();
    }
    const value = await response.json();
    return new Set(Array.isArray(value) ? value.filter((item): item is string => /^\d{6}$/.test(String(item))) : []);
  } catch {
    return new Set<string>();
  }
}

async function fetchAdminRecords(path: string): Promise<AdminRecord[]> {
  if (!/^(province\/province|city\/city|area\/area)\.json$/.test(path)) {
    return [];
  }
  try {
    const response = await fetch(staticAssetURL(`province-city-china/${path}`), {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      return [];
    }
    const value = await response.json();
    return Array.isArray(value) ? value as AdminRecord[] : [];
  } catch {
    return [];
  }
}

function chinaMapAssetURL(adcode: string) {
  return staticAssetURL(`china-map-echarts/map/${adcode}.json`);
}

function staticAssetURL(path: string) {
  const base = (import.meta.env.BASE_URL || '/').replace(/\/?$/, '/');
  return `${base}${path}`;
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
  if (String(properties.level ?? '') === level) {
    return feature;
  }
  return {
    ...feature,
    properties: {
      ...properties,
      level,
    },
  };
}

function inferAdminLevel(feature: WorldFeature): string {
  const existing = String(feature.properties?.level ?? '').toLowerCase();
  if (existing === 'province' || existing === 'city' || existing === 'district' || existing === 'county') {
    return existing;
  }
  const code = String(feature.properties?.adcode ?? feature.properties?.id ?? feature.id ?? '').trim();
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
        coordinates: reversePolygonRings(record.coordinates),
      },
    };
  }
  if (record.type === 'MultiPolygon') {
    return {
      ...feature,
      geometry: {
        ...record,
        coordinates: reverseMultiPolygonRings(record.coordinates),
      },
    };
  }
  return feature;
}

function reverseMultiPolygonRings(coordinates: unknown) {
  return Array.isArray(coordinates)
    ? coordinates.map((polygon) => reversePolygonRings(polygon))
    : coordinates;
}

function reversePolygonRings(coordinates: unknown) {
  return Array.isArray(coordinates)
    ? coordinates.map((ring) => reverseLinearRing(ring))
    : coordinates;
}

function reverseLinearRing(ring: unknown) {
  return Array.isArray(ring) ? [...ring].reverse() : ring;
}
