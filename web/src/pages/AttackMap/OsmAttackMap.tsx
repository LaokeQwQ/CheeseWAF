import { useEffect, useMemo, useRef, type MutableRefObject } from 'react';
import maplibregl, { type GeoJSONSource, type Map as MapLibreMap, type StyleSpecification } from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { worldFeatures, type AttackRegion, type ThreatLevel } from './attackMapData';
import type { GeoFeatureCollection } from './chinaBoundaries';

/**
 * Offline attack map basemap.
 *
 * Requirements:
 * - Works with no network (no tile CDN, no OpenFreeMap/Mapbox online styles)
 * - District/county precision for China is enough (not full street OSM)
 *
 * Data (all local npm packs, served/bundled offline):
 * - world-atlas countries-110m → coarse world land
 * - china-map-echarts + optional offline tree → province / city / district polygons
 * - attack log aggregates → point markers
 *
 * Rendering: MapLibre GL (open Mapbox GL fork) + Mapbox-like palette, GeoJSON only.
 */

type FeatureCollection = {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    id?: string | number;
    properties: Record<string, unknown> | null;
    geometry: { type: string; coordinates: unknown };
  }>;
};

export type OsmMapMode = 'world' | 'china';

export type OsmAttackMapHandle = {
  zoomIn: () => void;
  zoomOut: () => void;
  resetView: () => void;
  flyToRegion: (region: AttackRegion) => void;
};

type OsmAttackMapProps = {
  mode: OsmMapMode;
  regions: AttackRegion[];
  selectedRegionKey: string | null;
  onSelectRegion: (key: string | null) => void;
  ariaLabel: string;
  /** Offline China admin GeoJSON (WGS84), province→city→district as available. */
  chinaBoundary?: GeoFeatureCollection | null;
  countryLevels?: Map<string, ThreatLevel>;
  mapRef?: MutableRefObject<OsmAttackMapHandle | null>;
  formatTooltip: (region: AttackRegion) => string;
};

const WORLD_CENTER: [number, number] = [12, 18];
const WORLD_ZOOM = 1.25;
const CHINA_BOUNDS: [[number, number], [number, number]] = [
  [73.5, 18.1],
  [135.1, 53.6],
];

/** Mapbox-inspired offline palette (no external glyphs/sprites required). */
const palette = {
  water: '#d9e8f5',
  land: '#f4f7fb',
  landStroke: '#c5d0dc',
  landActive: '#e8eef6',
  chinaFillProvince: 'rgba(37, 99, 235, 0.08)',
  chinaFillCity: 'rgba(14, 165, 233, 0.06)',
  chinaFillDistrict: 'rgba(8, 145, 178, 0.05)',
  chinaLineProvince: '#1d4ed8',
  chinaLineCity: '#0284c7',
  chinaLineDistrict: '#0e7490',
};

const riskColor: Record<ThreatLevel | 'neutral', string> = {
  low: '#2176d2',
  medium: '#d98912',
  high: '#f97316',
  critical: '#dd3b3b',
  neutral: '#94a3b8',
};

const WORLD_SOURCE = 'offline-world-land';
const WORLD_FILL = 'offline-world-fill';
const WORLD_LINE = 'offline-world-line';
const ATTACK_SOURCE = 'attack-regions';
const ATTACK_CIRCLE = 'attack-regions-circle';
const ATTACK_GLOW = 'attack-regions-glow';
const CHINA_SOURCE = 'china-admin-boundary';
const CHINA_FILL = 'china-admin-fill';
const CHINA_LINE = 'china-admin-line';

/** Fully offline MapLibre style: solid water background, no tile sources. */
function buildOfflineStyle(): StyleSpecification {
  return {
    version: 8,
    name: 'cheesewaf-offline-mapbox-like',
    // No glyphs/sprites → works fully offline (labels use maplibre default when present).
    sources: {},
    layers: [
      {
        id: 'background',
        type: 'background',
        paint: { 'background-color': palette.water },
      },
    ],
  };
}

export default function OsmAttackMap({
  mode,
  regions,
  selectedRegionKey,
  onSelectRegion,
  ariaLabel,
  chinaBoundary,
  countryLevels,
  mapRef,
  formatTooltip,
}: OsmAttackMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<MapLibreMap | null>(null);
  const readyRef = useRef(false);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const regionsRef = useRef(regions);
  const formatRef = useRef(formatTooltip);
  const onSelectRef = useRef(onSelectRegion);
  const countryLevelsRef = useRef(countryLevels);
  const modeRef = useRef(mode);
  const chinaBoundaryRef = useRef(chinaBoundary);
  const selectedRegionKeyRef = useRef(selectedRegionKey);
  regionsRef.current = regions;
  formatRef.current = formatTooltip;
  onSelectRef.current = onSelectRegion;
  countryLevelsRef.current = countryLevels;
  modeRef.current = mode;
  chinaBoundaryRef.current = chinaBoundary;
  selectedRegionKeyRef.current = selectedRegionKey;

  const attackGeo = useMemo(() => regionsToGeoJSON(regions), [regions]);
  const worldGeo = useMemo(() => worldLandGeoJSON(countryLevels), [countryLevels]);

  useEffect(() => {
    if (!containerRef.current || mapInstance.current) {
      return undefined;
    }

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: buildOfflineStyle(),
      center: modeRef.current === 'china' ? [104.2, 35.9] : WORLD_CENTER,
      zoom: modeRef.current === 'china' ? 3.4 : WORLD_ZOOM,
      minZoom: 0.6,
      maxZoom: 12,
      attributionControl: { compact: true },
      dragRotate: false,
      pitchWithRotate: false,
      touchPitch: false,
      // Avoid remote CJK glyph fallback fetches when any label layer is absent.
      localIdeographFontFamily: 'sans-serif',
    });

    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), 'top-right');
    map.addControl(new maplibregl.ScaleControl({ maxWidth: 120 }), 'bottom-left');

    popupRef.current = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 12,
      className: 'osm-attack-popup',
    });

    map.on('load', () => {
      readyRef.current = true;
      ensureWorldLayers(map);
      ensureChinaLayers(map);
      ensureAttackLayers(map);
      syncSource(map, WORLD_SOURCE, worldLandGeoJSON(countryLevelsRef.current));
      syncSource(map, ATTACK_SOURCE, regionsToGeoJSON(regionsRef.current), selectedRegionKeyRef.current);
      // Re-read props via refs so boundaries that resolved before `load` still paint.
      syncChina(map, chinaBoundaryRef.current ?? null, modeRef.current);
      if (modeRef.current === 'china') {
        applyChinaCamera(map);
      }
      bindHandle(mapRef, map, modeRef.current);
    });

    map.on('mouseenter', ATTACK_CIRCLE, () => {
      map.getCanvas().style.cursor = 'pointer';
    });
    map.on('mouseleave', ATTACK_CIRCLE, () => {
      map.getCanvas().style.cursor = '';
      popupRef.current?.remove();
    });
    map.on('mousemove', ATTACK_CIRCLE, (event) => {
      const feature = event.features?.[0];
      if (!feature || !popupRef.current) {
        return;
      }
      const key = String(feature.properties?.key ?? '');
      const region = regionsRef.current.find((item) => item.key === key);
      if (!region) {
        return;
      }
      popupRef.current
        .setLngLat(event.lngLat)
        .setHTML(`<strong>${escapeHtml(formatRef.current(region))}</strong>`)
        .addTo(map);
    });
    map.on('click', ATTACK_CIRCLE, (event) => {
      const feature = event.features?.[0];
      const key = feature ? String(feature.properties?.key ?? '') : '';
      onSelectRef.current(key || null);
    });
    map.on('click', (event) => {
      const hits = map.queryRenderedFeatures(event.point, { layers: [ATTACK_CIRCLE] });
      if (hits.length === 0) {
        onSelectRef.current(null);
      }
    });

    mapInstance.current = map;
    bindHandle(mapRef, map, mode);

    return () => {
      readyRef.current = false;
      popupRef.current?.remove();
      popupRef.current = null;
      map.remove();
      mapInstance.current = null;
      if (mapRef) {
        mapRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mode camera + china overlay visibility. chinaBoundary may resolve before or after map `load`
  // (readyRef gates); on load, chinaBoundaryRef is re-synced so early arrivals still paint.
  useEffect(() => {
    const map = mapInstance.current;
    if (!map || !readyRef.current) {
      return;
    }
    bindHandle(mapRef, map, mode);
    if (mode === 'china') {
      applyChinaCamera(map);
    } else {
      map.easeTo({ center: WORLD_CENTER, zoom: WORLD_ZOOM, duration: 400 });
    }
    syncChina(map, chinaBoundary ?? null, mode);
  }, [mode, mapRef, chinaBoundary]);

  useEffect(() => {
    const map = mapInstance.current;
    if (!map || !readyRef.current) {
      return;
    }
    syncSource(map, WORLD_SOURCE, worldGeo);
  }, [worldGeo]);

  useEffect(() => {
    const map = mapInstance.current;
    if (!map || !readyRef.current) {
      return;
    }
    syncSource(map, ATTACK_SOURCE, attackGeo, selectedRegionKey);
  }, [attackGeo, selectedRegionKey]);

  return (
    <div
      ref={containerRef}
      className="osm-attack-map osm-attack-map-offline"
      role="img"
      aria-label={ariaLabel}
      data-testid="osm-attack-map"
      data-map-mode={mode}
      data-map-engine="maplibre-offline"
      data-map-offline="true"
    />
  );
}

function bindHandle(
  mapRef: MutableRefObject<OsmAttackMapHandle | null> | undefined,
  map: MapLibreMap,
  mode: OsmMapMode,
) {
  if (!mapRef) {
    return;
  }
  // Capture mode at bind time; callers re-bind when mode changes.
  const activeMode = mode;
  mapRef.current = {
    zoomIn: () => map.zoomIn({ duration: 200 }),
    zoomOut: () => map.zoomOut({ duration: 200 }),
    resetView: () => {
      if (activeMode === 'china') {
        applyChinaCamera(map);
      } else {
        map.easeTo({ center: WORLD_CENTER, zoom: WORLD_ZOOM, duration: 400 });
      }
    },
    flyToRegion: (region) => {
      if (!Number.isFinite(region.lon) || !Number.isFinite(region.lat)) {
        return;
      }
      map.flyTo({
        center: [region.lon, region.lat],
        zoom: Math.max(map.getZoom(), activeMode === 'china' ? 6.2 : 5.2),
        duration: 550,
      });
    },
  };
}

function ensureWorldLayers(map: MapLibreMap) {
  if (!map.getSource(WORLD_SOURCE)) {
    map.addSource(WORLD_SOURCE, { type: 'geojson', data: emptyFC() as never });
  }
  if (!map.getLayer(WORLD_FILL)) {
    map.addLayer({
      id: WORLD_FILL,
      type: 'fill',
      source: WORLD_SOURCE,
      paint: {
        'fill-color': [
          'case',
          ['==', ['get', 'risk'], 'critical'], '#fecaca',
          ['==', ['get', 'risk'], 'high'], '#fed7aa',
          ['==', ['get', 'risk'], 'medium'], '#fde68a',
          ['==', ['get', 'risk'], 'low'], '#bfdbfe',
          palette.land,
        ],
        'fill-opacity': 0.95,
      },
    });
  }
  if (!map.getLayer(WORLD_LINE)) {
    map.addLayer({
      id: WORLD_LINE,
      type: 'line',
      source: WORLD_SOURCE,
      paint: {
        'line-color': palette.landStroke,
        'line-width': 0.6,
        'line-opacity': 0.9,
      },
    });
  }
}

function ensureChinaLayers(map: MapLibreMap) {
  if (!map.getSource(CHINA_SOURCE)) {
    map.addSource(CHINA_SOURCE, { type: 'geojson', data: emptyFC() as never });
  }
  if (!map.getLayer(CHINA_FILL)) {
    map.addLayer({
      id: CHINA_FILL,
      type: 'fill',
      source: CHINA_SOURCE,
      layout: { visibility: 'none' },
      paint: {
        'fill-color': [
          'match',
          ['coalesce', ['get', 'level'], ''],
          'province', palette.chinaFillProvince,
          'city', palette.chinaFillCity,
          'district', palette.chinaFillDistrict,
          'county', palette.chinaFillDistrict,
          palette.chinaFillProvince,
        ],
        'fill-outline-color': palette.chinaLineCity,
      },
    });
  }
  if (!map.getLayer(CHINA_LINE)) {
    map.addLayer({
      id: CHINA_LINE,
      type: 'line',
      source: CHINA_SOURCE,
      layout: { visibility: 'none' },
      paint: {
        'line-color': [
          'match',
          ['coalesce', ['get', 'level'], ''],
          'province', palette.chinaLineProvince,
          'city', palette.chinaLineCity,
          'district', palette.chinaLineDistrict,
          'county', palette.chinaLineDistrict,
          palette.chinaLineCity,
        ],
        'line-width': [
          'match',
          ['coalesce', ['get', 'level'], ''],
          'province', 1.15,
          'city', 0.75,
          'district', 0.4,
          'county', 0.4,
          0.7,
        ],
        'line-opacity': 0.88,
      },
    });
  }
}

function ensureAttackLayers(map: MapLibreMap) {
  if (!map.getSource(ATTACK_SOURCE)) {
    map.addSource(ATTACK_SOURCE, { type: 'geojson', data: emptyFC() as never });
  }
  if (!map.getLayer(ATTACK_GLOW)) {
    map.addLayer({
      id: ATTACK_GLOW,
      type: 'circle',
      source: ATTACK_SOURCE,
      paint: {
        'circle-radius': ['interpolate', ['linear'], ['get', 'attacks'], 1, 10, 20, 18, 100, 26],
        'circle-color': ['get', 'color'],
        'circle-opacity': 0.2,
        'circle-blur': 0.7,
      },
    });
  }
  if (!map.getLayer(ATTACK_CIRCLE)) {
    map.addLayer({
      id: ATTACK_CIRCLE,
      type: 'circle',
      source: ATTACK_SOURCE,
      paint: {
        'circle-radius': [
          'case',
          ['boolean', ['get', 'selected'], false],
          ['interpolate', ['linear'], ['get', 'attacks'], 1, 8, 20, 12, 100, 16],
          ['interpolate', ['linear'], ['get', 'attacks'], 1, 6, 20, 10, 100, 14],
        ],
        'circle-color': ['get', 'color'],
        'circle-stroke-width': ['case', ['boolean', ['get', 'selected'], false], 3, 1.5],
        'circle-stroke-color': '#ffffff',
        'circle-opacity': 0.94,
      },
    });
  }
  // No symbol/text layer: offline style ships without glyph PBF, and attack
  // volume is already encoded in circle radius (district-level precision goal).
}

function syncChina(map: MapLibreMap, chinaBoundary: GeoFeatureCollection | null, mode: OsmMapMode) {
  const collection =
    chinaBoundary && chinaBoundary.features.length > 0
      ? (normalizeChinaFeatureLevels(chinaBoundary) as FeatureCollection)
      : emptyFC();
  syncSource(map, CHINA_SOURCE, collection);
  const visible = mode === 'china' && collection.features.length > 0;
  // In china mode, world land stays as context but faded; china admin lines on top.
  if (map.getLayer(WORLD_FILL)) {
    map.setPaintProperty(WORLD_FILL, 'fill-opacity', mode === 'china' ? 0.35 : 0.95);
  }
  if (map.getLayer(WORLD_LINE)) {
    map.setPaintProperty(WORLD_LINE, 'line-opacity', mode === 'china' ? 0.35 : 0.9);
  }
  if (map.getLayer(CHINA_FILL)) {
    map.setLayoutProperty(CHINA_FILL, 'visibility', visible ? 'visible' : 'none');
  }
  if (map.getLayer(CHINA_LINE)) {
    map.setLayoutProperty(CHINA_LINE, 'visibility', visible ? 'visible' : 'none');
  }
}

/** Coerce admin `level` for MapLibre paint match expressions (city/district styling). */
function normalizeChinaFeatureLevels(collection: GeoFeatureCollection): FeatureCollection {
  return {
    type: 'FeatureCollection',
    features: collection.features.map((feature, index) => {
      const properties = { ...(feature.properties ?? {}) };
      const existing = String(properties.level ?? '').toLowerCase();
      if (existing !== 'province' && existing !== 'city' && existing !== 'district' && existing !== 'county') {
        const code = String(properties.adcode ?? properties.id ?? feature.id ?? '').trim();
        if (/^\d{6}$/.test(code)) {
          properties.level = code.endsWith('0000') ? 'province' : code.endsWith('00') ? 'city' : 'district';
        } else {
          properties.level = 'province';
        }
      } else {
        properties.level = existing;
      }
      // MapLibre match on string; adcode in pack is often numeric.
      if (properties.adcode != null) {
        properties.adcode = String(properties.adcode);
      }
      return {
        type: 'Feature' as const,
        id: feature.id ?? index,
        properties,
        geometry: feature.geometry as { type: string; coordinates: unknown },
      };
    }),
  };
}

function syncSource(
  map: MapLibreMap,
  sourceId: string,
  data: FeatureCollection,
  selectedRegionKey?: string | null,
) {
  const source = map.getSource(sourceId) as GeoJSONSource | undefined;
  if (!source) {
    return;
  }
  if (sourceId === ATTACK_SOURCE && selectedRegionKey !== undefined) {
    source.setData({
      type: 'FeatureCollection',
      features: data.features.map((feature) => ({
        ...feature,
        properties: {
          ...(feature.properties ?? {}),
          selected: feature.properties?.key === selectedRegionKey,
        },
      })),
    } as never);
    return;
  }
  source.setData(data as never);
}

function worldLandGeoJSON(countryLevels?: Map<string, ThreatLevel>): FeatureCollection {
  return {
    type: 'FeatureCollection',
    features: worldFeatures
      .filter((feature) => feature.geometry)
      .map((feature, index) => {
        const id = String(feature.id ?? index);
        const risk = countryLevels?.get(id) ?? 'neutral';
        return {
          type: 'Feature' as const,
          id,
          properties: {
            id,
            risk,
            name: String((feature.properties as { name?: string } | undefined)?.name ?? id),
          },
          geometry: feature.geometry as { type: string; coordinates: unknown },
        };
      }),
  };
}

function regionsToGeoJSON(regions: AttackRegion[]): FeatureCollection {
  return {
    type: 'FeatureCollection',
    features: regions
      .filter((region) => region.mappable && Number.isFinite(region.lon) && Number.isFinite(region.lat))
      .map((region) => ({
        type: 'Feature' as const,
        properties: {
          key: region.key,
          attacks: region.attacks,
          level: region.level,
          color: riskColor[region.level] ?? riskColor.neutral,
          label: region.locationName || region.countryCode,
        },
        geometry: {
          type: 'Point',
          coordinates: [region.lon, region.lat],
        },
      })),
  };
}

function applyChinaCamera(map: MapLibreMap) {
  map.fitBounds(CHINA_BOUNDS, { padding: 40, duration: 420, maxZoom: 5.4 });
}

function emptyFC(): FeatureCollection {
  return { type: 'FeatureCollection', features: [] };
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}
