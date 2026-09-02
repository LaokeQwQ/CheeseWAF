import { gzipSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  admitExternalChinaBoundary,
  bd09ToWgs84,
  buildChinaComplianceFeatures,
  chinaFeatureAdcode,
  filterChinaCollectionByPrefix,
  gcj02ToWgs84,
  isAllowedExternalAdcode,
  isChinaBoundaryEnabled,
  isWithinChinaBounds,
  loadVendoredChinaCollection,
  mergeChinaBoundaries,
  parseChinaBoundaryCrs,
  projectChinaBoundaryToWgs84,
  vendoredChinaBoundarySources,
  wgs84ToGcj02,
  type GeoFeatureCollection,
} from './chinaBoundaries';

const fc = (features: any[]): GeoFeatureCollection => ({ type: 'FeatureCollection', features });

describe('china boundary compliance gate', () => {
  it('requires enabled plus license or review_id', () => {
    expect(isChinaBoundaryEnabled({ enabled: false, license: '' })).toBe(false);
    expect(isChinaBoundaryEnabled({ enabled: true, review_id: 'GS(2024)0650' })).toBe(true);
    expect(isChinaBoundaryEnabled({ enabled: true, license: '评审号' })).toBe(true);
    expect(isChinaBoundaryEnabled({ enabled: true })).toBe(false);
    expect(isChinaBoundaryEnabled(undefined)).toBe(false);
  });

  it('builds empty compliance when disabled or no assets', () => {
    expect(buildChinaComplianceFeatures(null, true)).toBeNull();
    expect(buildChinaComplianceFeatures({ tenDash: fc([]), huangyan: fc([]), borders: fc([]) }, true)).toBeNull();
    expect(buildChinaComplianceFeatures(null, false)).toBeNull();
    const assets = {
      tenDash: fc([{ type: 'Feature' as const, properties: { name: '十段线' }, geometry: { type: 'MultiLineString', coordinates: [] } }]),
      huangyan: fc([]),
      borders: fc([]),
    };
    const features = buildChinaComplianceFeatures(assets, true);
    expect(features).not.toBeNull();
    expect(features?.tenDash.features.length).toBe(1);
    expect(features?.huangyan.features.length).toBe(0);
  });
});

describe('chinaFeatureAdcode', () => {
  it('derives adcode from gb prefix 156', () => {
    expect(chinaFeatureAdcode({ gb: '156420704' })).toBe('420704');
    expect(chinaFeatureAdcode({ adcode: '440300' })).toBe('440300');
    expect(chinaFeatureAdcode({})).toBe('');
    expect(chinaFeatureAdcode(null)).toBe('');
  });
});

describe('filterChinaCollectionByPrefix', () => {
  it('keeps features by adcode prefix', () => {
    const collection = fc([
      { type: 'Feature' as const, properties: { gb: '156440000' }, geometry: { type: 'Polygon', coordinates: [] } },
      { type: 'Feature' as const, properties: { gb: '156440300' }, geometry: { type: 'Polygon', coordinates: [] } },
      { type: 'Feature' as const, properties: { gb: '156810100' }, geometry: { type: 'Polygon', coordinates: [] } },
    ]);
    const filtered = filterChinaCollectionByPrefix(collection, 2);
    expect(filtered.features.length).toBe(3); // all six-digit adcodes qualify
    const guangdong = filterChinaCollectionByPrefix(collection, 8);
    expect(guangdong.features.length).toBe(0); // no adcode has 8 digits
  });
});

/**
 * Reference values below are anchored, not invented: `116.416718, 39.912934` is
 * the DataV.GeoAtlas centroid of 北京市东城区 (adcode 110101). Converting it from
 * GCJ-02 to WGS84 yields `116.410476, 39.911531`, which matches the OSM /
 * Nominatim WGS84 centroid of the same district measured at
 * `116.410451, 39.911578` — i.e. within ~2 m east and ~5 m north. That is the
 * sanity anchor for the whole conversion chain: a wrong sign or a swapped
 * lon/lat would land hundreds of metres away instead.
 */
describe('parseChinaBoundaryCrs', () => {
  it('accepts explicit WGS84 spellings', () => {
    expect(parseChinaBoundaryCrs('WGS84')).toBe('WGS84');
    expect(parseChinaBoundaryCrs('wgs-84')).toBe('WGS84');
    expect(parseChinaBoundaryCrs('EPSG:4326')).toBe('WGS84');
    expect(parseChinaBoundaryCrs('CRS84')).toBe('WGS84');
    expect(parseChinaBoundaryCrs('urn:ogc:def:crs:OGC:1.3:CRS84')).toBe('WGS84');
    expect(parseChinaBoundaryCrs('urn:ogc:def:crs:EPSG::4326')).toBe('WGS84');
    // legacy GeoJSON 2008 crs member
    expect(parseChinaBoundaryCrs({ type: 'name', properties: { name: 'urn:ogc:def:crs:OGC:1.3:CRS84' } })).toBe('WGS84');
  });

  it('accepts GCJ-02 and BD-09 spellings', () => {
    expect(parseChinaBoundaryCrs('GCJ02')).toBe('GCJ02');
    expect(parseChinaBoundaryCrs('GCJ-02')).toBe('GCJ02');
    expect(parseChinaBoundaryCrs('AMAP')).toBe('GCJ02');
    expect(parseChinaBoundaryCrs('BD-09')).toBe('BD09');
    expect(parseChinaBoundaryCrs('BAIDU')).toBe('BD09');
  });

  it('fails closed on missing, blank, misspelled or projected declarations', () => {
    expect(parseChinaBoundaryCrs(undefined)).toBe('unknown');
    expect(parseChinaBoundaryCrs('')).toBe('unknown');
    expect(parseChinaBoundaryCrs('   ')).toBe('unknown');
    expect(parseChinaBoundaryCrs(4326)).toBe('unknown');
    expect(parseChinaBoundaryCrs({})).toBe('unknown');
    expect(parseChinaBoundaryCrs({ properties: {} })).toBe('unknown');
    // misspelled: refusing is correct, guessing is not
    expect(parseChinaBoundaryCrs('WGS-1984')).toBe('unknown');
    expect(parseChinaBoundaryCrs('wgs84 (approx)')).toBe('unknown');
    // projected metres must never enter a lon/lat pipeline
    expect(parseChinaBoundaryCrs('EPSG:3857')).toBe('unknown');
    expect(parseChinaBoundaryCrs('EPSG:900913')).toBe('unknown');
  });
});

describe('crs conversion', () => {
  it('converts WGS84 -> GCJ-02 with the published offset magnitude', () => {
    const [lon, lat] = wgs84ToGcj02(116.3976, 39.9055);
    expect(lon).toBeCloseTo(116.40384318403385, 10);
    expect(lat).toBeCloseTo(39.906903381493144, 10);
    // ~695 m east, ~156 m north: squarely inside the documented 300~1000 m band
    const east = (lon - 116.3976) * 111_320 * Math.cos(39.9055 * Math.PI / 180);
    const north = (lat - 39.9055) * 110_946;
    expect(east).toBeGreaterThan(300);
    expect(east).toBeLessThan(1000);
    expect(north).toBeGreaterThan(0);
  });

  it('inverts GCJ-02 -> WGS84 to sub-millimetre precision', () => {
    const [lon, lat] = gcj02ToWgs84(116.40384318403385, 39.906903381493144);
    expect(Math.abs(lon - 116.3976)).toBeLessThan(1e-9);
    expect(Math.abs(lat - 39.9055)).toBeLessThan(1e-9);
  });

  it('maps the anchored DataV centroid onto the OSM WGS84 ground truth', () => {
    const [lon, lat] = gcj02ToWgs84(116.416718, 39.912934);
    expect(lon).toBeCloseTo(116.41047615761195, 10);
    expect(lat).toBeCloseTo(39.9115312087127, 10);
    // measured OSM centroid of the same district
    expect(Math.abs(lon - 116.410451)).toBeLessThan(0.0001);
    expect(Math.abs(lat - 39.911578)).toBeLessThan(0.0001);
  });

  it('applies no offset outside the GCJ-02 box', () => {
    // Tokyo (lon 139.7) and Hong Kong-adjacent sea are outside 72.004~137.8347
    expect(gcj02ToWgs84(139.7, 35.6)).toEqual([139.7, 35.6]);
    expect(wgs84ToGcj02(139.7, 35.6)).toEqual([139.7, 35.6]);
  });

  it('converts BD-09 -> WGS84 through GCJ-02', () => {
    const [lon, lat] = bd09ToWgs84(116.41021918803482, 39.913243252620454);
    expect(Math.abs(lon - 116.3976)).toBeLessThan(1e-5);
    expect(Math.abs(lat - 39.9055)).toBeLessThan(1e-5);
  });
});

describe('projectChinaBoundaryToWgs84', () => {
  const ring = [[116.40, 39.90], [116.42, 39.90], [116.42, 39.92], [116.40, 39.90]];
  const collection = fc([
    { type: 'Feature', properties: { adcode: '110101' }, geometry: { type: 'Polygon', coordinates: [ring] } },
  ]);

  it('returns WGS84 input untouched', () => {
    expect(projectChinaBoundaryToWgs84(collection, 'WGS84')).toBe(collection);
  });

  it('rewrites every coordinate for GCJ-02 input', () => {
    const projected = projectChinaBoundaryToWgs84(collection, 'GCJ02');
    expect(projected).not.toBe(collection);
    const [lon, lat] = (projected.features[0].geometry as any).coordinates[0][0];
    expect(lon).toBeCloseTo(gcj02ToWgs84(116.40, 39.90)[0], 10);
    expect(lat).toBeCloseTo(gcj02ToWgs84(116.40, 39.90)[1], 10);
    // and it really moved west / south, i.e. the correction is not a no-op
    expect(lon).toBeLessThan(116.40);
    expect(lat).toBeLessThan(39.90);
  });

  it('rewrites every coordinate for BD-09 input', () => {
    const projected = projectChinaBoundaryToWgs84(collection, 'BD09');
    const [lon, lat] = (projected.features[0].geometry as any).coordinates[0][0];
    expect(lon).toBeCloseTo(bd09ToWgs84(116.40, 39.90)[0], 10);
    expect(lat).toBeCloseTo(bd09ToWgs84(116.40, 39.90)[1], 10);
  });
});

describe('isWithinChinaBounds', () => {
  const point = (lon: number, lat: number) => fc([
    { type: 'Feature', properties: { adcode: '110101' }, geometry: { type: 'Point', coordinates: [lon, lat] } },
  ]);

  it('accepts coordinates inside the admission box', () => {
    expect(isWithinChinaBounds(point(116.4, 39.9))).toBe(true);
    expect(isWithinChinaBounds(point(73.5, 39.4))).toBe(true); // 新疆
    expect(isWithinChinaBounds(point(112.0, 4.0))).toBe(true); // 南海
  });

  it('rejects projected metres, swapped axes and empty geometry', () => {
    expect(isWithinChinaBounds(point(12_965_000, 4_850_000))).toBe(false); // EPSG:3857 metres
    expect(isWithinChinaBounds(point(39.9, 116.4))).toBe(false); // lat/lon swapped
    expect(isWithinChinaBounds(point(Number.NaN, 39.9))).toBe(false);
    expect(isWithinChinaBounds(fc([]))).toBe(false);
  });
});

describe('isAllowedExternalAdcode', () => {
  it('admits district-level codes inside the requested scope only', () => {
    expect(isAllowedExternalAdcode('310115', ['310100'])).toBe(true); // city parent
    expect(isAllowedExternalAdcode('310115', ['310000'])).toBe(true); // 直辖市 province parent
    expect(isAllowedExternalAdcode('310115', ['310115'])).toBe(true); // exact
    expect(isAllowedExternalAdcode('110101', ['310100'])).toBe(false); // outside scope
  });

  it('rejects city and province level codes so they cannot replace a vetted boundary', () => {
    expect(isAllowedExternalAdcode('310100', ['310100'])).toBe(false); // city
    expect(isAllowedExternalAdcode('310000', ['310000'])).toBe(false); // province
    expect(isAllowedExternalAdcode('', ['310100'])).toBe(false);
    expect(isAllowedExternalAdcode('31', ['310100'])).toBe(false);
  });
});

describe('admitExternalChinaBoundary', () => {
  const district = (adcode: string, ring: number[][] = [[116.40, 39.90], [116.42, 39.90], [116.42, 39.92], [116.40, 39.90]]) => ({
    type: 'Feature' as const,
    properties: { adcode },
    geometry: { type: 'Polygon' as const, coordinates: [ring] },
  });

  it('refuses data with no CRS declaration at all (the reported defect)', () => {
    const result = admitExternalChinaBoundary({
      geojson: fc([district('110101')]),
      allowedAdcodes: ['110000'],
    });
    expect(result.collection).toBeNull();
    expect(result.rejection).toBe('no-crs');
  });

  it('refuses a declaration it cannot honour', () => {
    const result = admitExternalChinaBoundary({
      geojson: fc([district('110101')]),
      declaredCrs: 'EPSG:3857',
      allowedAdcodes: ['110000'],
    });
    expect(result.collection).toBeNull();
    expect(result.rejection).toBe('unsupported-crs');
  });

  it('accepts an in-band GeoJSON crs member', () => {
    const geojson = {
      type: 'FeatureCollection',
      crs: { type: 'name', properties: { name: 'urn:ogc:def:crs:OGC:1.3:CRS84' } },
      features: [district('110101')],
    };
    const result = admitExternalChinaBoundary({ geojson, allowedAdcodes: ['110000'] });
    expect(result.rejection).toBeNull();
    expect(result.collection?.features.length).toBe(1);
  });

  it('converts declared GCJ-02 coordinates into WGS84 before admitting', () => {
    const result = admitExternalChinaBoundary({
      geojson: fc([district('110101', [[116.416718, 39.912934], [116.43, 39.91], [116.43, 39.93], [116.416718, 39.912934]])]),
      declaredCrs: 'GCJ-02',
      allowedAdcodes: ['110000'],
    });
    expect(result.rejection).toBeNull();
    const [lon, lat] = (result.collection!.features[0].geometry as any).coordinates[0][0];
    expect(lon).toBeCloseTo(116.41047615761195, 10);
    expect(lat).toBeCloseTo(39.9115312087127, 10);
  });

  it('refuses features whose adcode is missing or not district level', () => {
    const noCode = admitExternalChinaBoundary({
      geojson: fc([{ type: 'Feature', properties: { name: '未知区域' }, geometry: district('110101').geometry }]),
      declaredCrs: 'WGS84',
      allowedAdcodes: ['110000'],
    });
    expect(noCode.collection).toBeNull();
    expect(noCode.rejection).toBe('no-adcode');

    const cityLevel = admitExternalChinaBoundary({
      geojson: fc([district('110100')]),
      declaredCrs: 'WGS84',
      allowedAdcodes: ['110000'],
    });
    expect(cityLevel.collection).toBeNull();
    expect(cityLevel.rejection).toBe('no-adcode');
  });

  it('refuses coordinates that land outside China even when the CRS is declared', () => {
    const result = admitExternalChinaBoundary({
      geojson: fc([district('110101', [[12_965_000, 4_850_000], [12_966_000, 4_851_000], [12_967_000, 4_850_000], [12_965_000, 4_850_000]])]),
      declaredCrs: 'WGS84',
      allowedAdcodes: ['110000'],
    });
    expect(result.collection).toBeNull();
    expect(result.rejection).toBe('out-of-range');
  });

  it('treats an empty payload as "nothing to admit" rather than a rejection', () => {
    const result = admitExternalChinaBoundary({ geojson: fc([]), allowedAdcodes: ['110000'] });
    expect(result.collection).toBeNull();
    expect(result.rejection).toBeNull();
  });
});

describe('mergeChinaBoundaries dedup', () => {
  const feature = (properties: Record<string, unknown>, name: string) => ({
    type: 'Feature' as const,
    properties: { ...properties, name },
    geometry: { type: 'Polygon' as const, coordinates: [[[116.40, 39.90], [116.42, 39.90], [116.42, 39.92], [116.40, 39.90]]] },
  });
  /** Builtin county pack carries `gb` ("156110101"); external sources carry `adcode`. */
  const builtinDistrict = feature({ gb: '156110101' }, '东城区 builtin');
  const externalDistrict = feature({ adcode: '110101' }, '东城区 external');

  it('dedups across the gb/adcode code families so no double border appears', () => {
    const merged = mergeChinaBoundaries(fc([builtinDistrict]), null, fc([externalDistrict]));
    expect(merged.collection.features.length).toBe(1);
    expect(merged.collection.features[0].properties?.name).toBe('东城区 external');
  });

  it('keeps genuinely different codes apart', () => {
    const merged = mergeChinaBoundaries(
      fc([feature({ gb: '156110000' }, '北京市')]),
      null,
      fc([externalDistrict]),
    );
    expect(merged.collection.features.length).toBe(2);
  });

  it('drops an unidentified external polygon instead of stacking it on the map', () => {
    const unnamedExternal = feature({ name: 'unnamed' } as Record<string, unknown>, 'unnamed');
    const merged = mergeChinaBoundaries(fc([builtinDistrict]), null, fc([unnamedExternal]));
    expect(merged.collection.features.length).toBe(1);
    expect(merged.collection.features[0].properties?.name).toBe('东城区 builtin');
  });

  it('still keeps keyless builtin geometry such as border lines', () => {
    const borderLine = {
      type: 'Feature' as const,
      properties: { name: '国界线', kind: '国界线' },
      geometry: { type: 'LineString' as const, coordinates: [[116.4, 39.9], [116.5, 39.9]] },
    };
    const merged = mergeChinaBoundaries(fc([builtinDistrict, borderLine]), null, null);
    expect(merged.collection.features.length).toBe(2);
  });

  it('prefers external over offline over builtin for the same code', () => {
    const offline = feature({ adcode: '110101' }, '东城区 offline');
    const merged = mergeChinaBoundaries(fc([builtinDistrict]), fc([offline]), fc([externalDistrict]));
    expect(merged.collection.features.length).toBe(1);
    expect(merged.collection.features[0].properties?.name).toBe('东城区 external');
    const withoutExternal = mergeChinaBoundaries(fc([builtinDistrict]), fc([offline]), null);
    expect(withoutExternal.collection.features[0].properties?.name).toBe('东城区 offline');
  });

  it('reports the external source only when external geometry survived', () => {
    expect(mergeChinaBoundaries(fc([builtinDistrict]), null, fc([externalDistrict])).sourceSummary).toBe('external');
    expect(mergeChinaBoundaries(fc([builtinDistrict]), null, null).sourceSummary).toBe('builtin-district');
  });
});

/**
 * The built-in city pack ships as GCJ-02 while the province and county packs
 * ship as WGS84, so the three layers used to sit ~500 m apart on the map. The
 * fix is applied inside `loadVendoredChinaCollection`, i.e. once at load time
 * and then cached — never per render.
 */
describe('vendored china pack CRS normalisation', () => {
  /**
   * The DataV.GeoAtlas centroid of 北京市东城区 (adcode 110101) in GCJ-02.
   * Converted to WGS84 it must land on `116.41047615761195, 39.9115312087127`,
   * the same anchor the conversion chain above is pinned to.
   */
  const GCJ_CENTROID: [number, number] = [116.416718, 39.912934];
  const WGS_CENTROID: [number, number] = [116.41047615761195, 39.9115312087127];
  const ring = [
    GCJ_CENTROID,
    [116.426718, 39.912934],
    [116.426718, 39.922934],
    GCJ_CENTROID,
  ];

  const stubPackFetch = (collection: GeoFeatureCollection) => {
    const fetchMock = vi.fn(async () => {
      const gz = gzipSync(Buffer.from(JSON.stringify(collection), 'utf8'));
      const body = new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(gz));
          controller.close();
        },
      });
      return new Response(body, { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('declares the measured CRS of every built-in pack', () => {
    expect(vendoredChinaBoundarySources.city.crs).toBe('GCJ02');
    expect(vendoredChinaBoundarySources.province.crs).toBe('WGS84');
    expect(vendoredChinaBoundarySources.county.crs).toBe('WGS84');
  });

  it('converts the GCJ-02 city pack to WGS84 as it is loaded', async () => {
    stubPackFetch(fc([{
      type: 'Feature',
      properties: { adcode: '110101', name: '东城区' },
      geometry: { type: 'Polygon', coordinates: [ring] },
    }]));

    const collection = await loadVendoredChinaCollection('city');
    const [lon, lat] = (collection.features[0].geometry as any).coordinates[0][0];
    expect(lon).toBeCloseTo(WGS_CENTROID[0], 10);
    expect(lat).toBeCloseTo(WGS_CENTROID[1], 10);
  });

  it('leaves a WGS84 pack byte-identical', async () => {
    stubPackFetch(fc([{
      type: 'Feature',
      properties: { gb: '156110101', name: '东城区' },
      geometry: { type: 'Polygon', coordinates: [ring] },
    }]));

    const collection = await loadVendoredChinaCollection('province');
    const [lon, lat] = (collection.features[0].geometry as any).coordinates[0][0];
    // not "close to" — exactly the input, proving no rewrite happened
    expect(lon).toBe(GCJ_CENTROID[0]);
    expect(lat).toBe(GCJ_CENTROID[1]);
  });

  it('fetches and converts each pack once, then serves it from cache', async () => {
    const fetchMock = stubPackFetch(fc([{
      type: 'Feature',
      properties: { gb: '156110101', name: '东城区' },
      geometry: { type: 'Polygon', coordinates: [ring] },
    }]));

    const [first, second] = await Promise.all([
      loadVendoredChinaCollection('county'),
      loadVendoredChinaCollection('county'),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);
  });
});
