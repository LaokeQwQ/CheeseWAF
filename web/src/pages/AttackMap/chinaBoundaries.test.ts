import { describe, expect, it } from 'vitest';
import {
  buildChinaComplianceFeatures,
  chinaFeatureAdcode,
  filterChinaCollectionByPrefix,
  isChinaBoundaryEnabled,
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
    expect(buildChinaComplianceFeatures({ tenDash: fc([]), huangyan: fc([]) }, true)).toBeNull();
    expect(buildChinaComplianceFeatures(null, false)).toBeNull();
    const assets = {
      tenDash: fc([{ type: 'Feature' as const, properties: { name: '十段线' }, geometry: { type: 'MultiLineString', coordinates: [] } }]),
      huangyan: fc([]),
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
