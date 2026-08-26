import { useEffect, useMemo, useRef, type MutableRefObject } from 'react';
import {
  Map as MapLibreMap,
  NavigationControl,
  Popup,
  ScaleControl,
  type GeoJSONSource,
  type StyleSpecification,
} from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { normalizeWorldId, worldFeatures, type AttackRegion, type ThreatLevel } from './attackMapData';
import { threatPaletteHex, threatPaletteNeutralHex } from './threatPalette';
import { type ChinaComplianceFeatures, type GeoFeatureCollection } from './chinaBoundaries';

/**
 * Offline attack map basemap.
 *
 * Requirements:
 * - Works with no network (no tile CDN, no OpenFreeMap/Mapbox online styles)
 * - District/county precision for China is enough (not full street OSM)
 *
 * Data (all local, served/bundled offline):
 * - world-atlas countries-110m → coarse world land
 * - vendored public/map GeoJSON (province / city / district) + optional offline tree
 * - attack log aggregates → point markers
 *
 * Rendering: MapLibre GL (open Mapbox GL fork) + Mapbox-like palette, GeoJSON only.
 */

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
  /** 十段线 + 黄岩岛 compliance geometry (rendered only when gate enabled). */
  chinaCompliance?: ChinaComplianceFeatures | null;
  /** Whether the China boundary compliance gate is enabled (licensed + review_id). Fail-closed: callers must pass the resolved gate. */
  chinaBoundaryEnabled: boolean;
  countryLevels?: Map<string, ThreatLevel>;
  mapRef?: MutableRefObject<OsmAttackMapHandle | null>;
  formatTooltip: (region: AttackRegion) => string;
};

const WORLD_CENTER: [number, number] = [12, 18];
const WORLD_ZOOM = 1.25;
const CHINA_BOUNDS: [[number, number], [number, number]] = [
  // Lower bound pulled to ~3.5N so the South China Sea islands (西沙/南沙/曾母暗沙)
  // stay visible; if any fetched GeoJSON lacks those island features, the view
  // still renders the mainland and degrades gracefully (no islands to show).
  [73.5, 3.5],
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
  ...threatPaletteHex,
  neutral: threatPaletteNeutralHex,
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
const OSM_SOURCE = 'osm-raster';
const OSM_LAYER = 'osm-raster-background';
/**
 * OSM 在线瓦片（仅世界模式可选底图，中国模式永不启用）。
 * 合规风险提示：该 URL 指向境外 OSM 公共服务，存在可用性与地图数据合规风险；
 * 后续应改为可配置项（如内网瓦片服务或具备审图号的合规图源），此处先集中为常量便于替换。
 */
const OSM_TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const CHINA_TEN_DASH_SOURCE = 'china-ten-dash';
const CHINA_TEN_DASH_LINE = 'china-ten-dash-line';
const CHINA_HUANGYAN_SOURCE = 'china-huangyan';
const CHINA_HUANGYAN_FILL = 'china-huangyan-fill';
const CHINA_HUANGYAN_LINE = 'china-huangyan-line';
const TEN_DASH_NAME = '十段线';
const HUANGYAN_NAME = '黄岩岛';

/** Fully offline MapLibre style: solid water background, no tile sources. */
/** Offline-first MapLibre style: solid water background plus an OSM raster
 * source/layer that is only shown in world mode (never China mode). */
function buildOfflineStyle(): StyleSpecification {
  return {
    version: 8,
    name: 'cheesewaf-offline-mapbox-like',
    // No remote glyphs/sprites → labels render only via DOM markers/popups.
    sources: {
      [OSM_SOURCE]: {
        type: 'raster',
        tiles: [OSM_TILE_URL],
        tileSize: 256,
        attribution: '© OpenStreetMap contributors',
      },
    },
    layers: [
      {
        id: 'background',
        type: 'background',
        paint: { 'background-color': palette.water },
      },
      {
        id: OSM_LAYER,
        type: 'raster',
        source: OSM_SOURCE,
        layout: { visibility: 'none' },
        paint: { 'raster-opacity': 0.5 },
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
  chinaCompliance,
  chinaBoundaryEnabled,
  countryLevels,
  mapRef,
  formatTooltip,
}: OsmAttackMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<MapLibreMap | null>(null);
  const readyRef = useRef(false);
  const popupRef = useRef<Popup | null>(null);
  const regionsRef = useRef(regions);
  const formatRef = useRef(formatTooltip);
  const onSelectRef = useRef(onSelectRegion);
  const countryLevelsRef = useRef(countryLevels);
  const modeRef = useRef(mode);
  const chinaBoundaryRef = useRef(chinaBoundary);
  const chinaComplianceRef = useRef(chinaCompliance);
  const chinaBoundaryEnabledRef = useRef(chinaBoundaryEnabled);
  const selectedRegionKeyRef = useRef(selectedRegionKey);
  regionsRef.current = regions;
  formatRef.current = formatTooltip;
  onSelectRef.current = onSelectRegion;
  countryLevelsRef.current = countryLevels;
  modeRef.current = mode;
  chinaBoundaryRef.current = chinaBoundary;
  chinaComplianceRef.current = chinaCompliance;
  chinaBoundaryEnabledRef.current = chinaBoundaryEnabled;
  selectedRegionKeyRef.current = selectedRegionKey;

  const attackGeo = useMemo(() => regionsToGeoJSON(regions), [regions]);
  const worldGeo = useMemo(() => worldLandGeoJSON(countryLevels), [countryLevels]);

  // Dedupe marker: load handler and the props effect both funnel here, so a
  // china sync with identical inputs runs at most once.
  const lastChinaSyncRef = useRef<{
    boundary: GeoFeatureCollection | null;
    compliance: ChinaComplianceFeatures | null;
    mode: OsmMapMode;
    enabled: boolean;
  } | null>(null);
  const syncChinaDeduped = (map: MapLibreMap) => {
    const next = {
      boundary: chinaBoundaryRef.current ?? null,
      compliance: chinaComplianceRef.current ?? null,
      mode: modeRef.current,
      enabled: chinaBoundaryEnabledRef.current,
    };
    const prev = lastChinaSyncRef.current;
    if (
      prev
      && prev.boundary === next.boundary
      && prev.compliance === next.compliance
      && prev.mode === next.mode
      && prev.enabled === next.enabled
    ) {
      return;
    }
    lastChinaSyncRef.current = next;
    syncChina(map, next.boundary, next.mode, next.compliance, next.enabled);
  };

  useEffect(() => {
    if (!containerRef.current || mapInstance.current) {
      return undefined;
    }

    const map = new MapLibreMap({
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

    map.addControl(new NavigationControl({ showCompass: false }), 'top-right');
    map.addControl(new ScaleControl({ maxWidth: 120 }), 'bottom-left');
    map.on('error', (event) => {
      // World-mode OSM tiles are optional; keep the offline water/land style if they fail.
      const sourceId = (event as { sourceId?: string }).sourceId;
      if (sourceId === OSM_SOURCE && map.getLayer(OSM_LAYER)) {
        map.setLayoutProperty(OSM_LAYER, 'visibility', 'none');
      }
    });

    popupRef.current = new Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 12,
      className: 'osm-attack-popup',
    });

    map.on('load', () => {
      readyRef.current = true;
      ensureWorldLayers(map);
      ensureChinaLayers(map);
      ensureChinaComplianceLayers(map);
      ensureAttackLayers(map);
      syncSource(map, WORLD_SOURCE, worldLandGeoJSON(countryLevelsRef.current));
      syncSource(map, ATTACK_SOURCE, regionsToGeoJSON(regionsRef.current), selectedRegionKeyRef.current);
      // Re-read props via refs so boundaries that resolved before `load` still paint.
      syncChinaDeduped(map);
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
    const complianceLayers = [CHINA_TEN_DASH_LINE, CHINA_HUANGYAN_FILL, CHINA_HUANGYAN_LINE];
    map.on('mousemove', complianceLayers, (event) => {
      const feature = event.features?.[0];
      if (!feature || !popupRef.current) return;
      const rawName = String(feature.properties?.name ?? '').trim();
      const name = rawName || (feature.source === CHINA_TEN_DASH_SOURCE ? TEN_DASH_NAME : feature.source === CHINA_HUANGYAN_SOURCE ? HUANGYAN_NAME : rawName);
      if (!name) return;
      map.getCanvas().style.cursor = 'pointer';
      popupRef.current.setLngLat(event.lngLat).setHTML(`<strong>${escapeHtml(name)}</strong>`).addTo(map);
    });
    map.on('mouseleave', complianceLayers, () => {
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
    syncChinaDeduped(map);
  }, [mode, mapRef, chinaBoundary, chinaCompliance, chinaBoundaryEnabled]);

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
          ['==', ['get', 'risk'], 'critical'], threatPaletteHex.critical,
          ['==', ['get', 'risk'], 'high'], threatPaletteHex.high,
          ['==', ['get', 'risk'], 'medium'], threatPaletteHex.medium,
          ['==', ['get', 'risk'], 'low'], threatPaletteHex.low,
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

function ensureChinaComplianceLayers(map: MapLibreMap) {
  if (!map.getSource(CHINA_TEN_DASH_SOURCE)) {
    map.addSource(CHINA_TEN_DASH_SOURCE, { type: 'geojson', data: emptyFC() as never });
  }
  if (!map.getLayer(CHINA_TEN_DASH_LINE)) {
    map.addLayer({
      id: CHINA_TEN_DASH_LINE,
      type: 'line',
      source: CHINA_TEN_DASH_SOURCE,
      layout: { visibility: 'none' },
      paint: {
        'line-color': '#e11d48',
        'line-width': 2.2,
        'line-dasharray': [4, 3],
        'line-opacity': 0.95,
      },
    });
  }
  if (!map.getSource(CHINA_HUANGYAN_SOURCE)) {
    map.addSource(CHINA_HUANGYAN_SOURCE, { type: 'geojson', data: emptyFC() as never });
  }
  if (!map.getLayer(CHINA_HUANGYAN_FILL)) {
    map.addLayer({
      id: CHINA_HUANGYAN_FILL,
      type: 'fill',
      source: CHINA_HUANGYAN_SOURCE,
      layout: { visibility: 'none' },
      paint: {
        'fill-color': '#f59e0b',
        'fill-opacity': 0.22,
        'fill-outline-color': '#d97706',
      },
    });
  }
  if (!map.getLayer(CHINA_HUANGYAN_LINE)) {
    map.addLayer({
      id: CHINA_HUANGYAN_LINE,
      type: 'line',
      source: CHINA_HUANGYAN_SOURCE,
      layout: { visibility: 'none' },
      paint: {
        'line-color': '#d97706',
        'line-width': 2,
        'line-opacity': 0.95,
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

function syncChina(
  map: MapLibreMap,
  chinaBoundary: GeoFeatureCollection | null,
  mode: OsmMapMode,
  chinaCompliance: ChinaComplianceFeatures | null,
  chinaBoundaryEnabled: boolean,
) {
  const collection =
    chinaBoundary && chinaBoundary.features.length > 0 && chinaBoundaryEnabled
      ? normalizeChinaFeatureLevels(chinaBoundary)
      : emptyFC();
  syncSource(map, CHINA_SOURCE, collection);
  const boundaryVisible = mode === 'china' && chinaBoundaryEnabled && collection.features.length > 0;
  if (map.getLayer(WORLD_FILL)) {
    map.setPaintProperty(WORLD_FILL, 'fill-opacity', mode === 'china' ? 0.35 : 0.95);
  }
  if (map.getLayer(WORLD_LINE)) {
    map.setPaintProperty(WORLD_LINE, 'line-opacity', mode === 'china' ? 0.35 : 0.9);
  }
  if (map.getLayer(OSM_LAYER)) {
    map.setLayoutProperty(OSM_LAYER, 'visibility', mode === 'china' ? 'none' : 'visible');
  }
  if (map.getLayer(CHINA_FILL)) {
    map.setLayoutProperty(CHINA_FILL, 'visibility', boundaryVisible ? 'visible' : 'none');
  }
  if (map.getLayer(CHINA_LINE)) {
    map.setLayoutProperty(CHINA_LINE, 'visibility', boundaryVisible ? 'visible' : 'none');
  }
  const complianceVisible = mode === 'china' && chinaBoundaryEnabled;
  const tenDash = complianceVisible && chinaCompliance?.tenDash?.features?.length ? chinaCompliance.tenDash : emptyFC();
  const huangyan = complianceVisible && chinaCompliance?.huangyan?.features?.length ? chinaCompliance.huangyan : emptyFC();
  syncSource(map, CHINA_TEN_DASH_SOURCE, tenDash);
  syncSource(map, CHINA_HUANGYAN_SOURCE, huangyan);
  if (map.getLayer(CHINA_TEN_DASH_LINE)) {
    map.setLayoutProperty(CHINA_TEN_DASH_LINE, 'visibility', complianceVisible && tenDash.features.length > 0 ? 'visible' : 'none');
  }
  if (map.getLayer(CHINA_HUANGYAN_FILL)) {
    map.setLayoutProperty(CHINA_HUANGYAN_FILL, 'visibility', complianceVisible && huangyan.features.length > 0 ? 'visible' : 'none');
  }
  if (map.getLayer(CHINA_HUANGYAN_LINE)) {
    map.setLayoutProperty(CHINA_HUANGYAN_LINE, 'visibility', complianceVisible && huangyan.features.length > 0 ? 'visible' : 'none');
  }
}

/** Coerce admin `level` for MapLibre paint match expressions (city/district styling). */
function normalizeChinaFeatureLevels(collection: GeoFeatureCollection): GeoFeatureCollection {
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
  data: GeoFeatureCollection,
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

function worldLandGeoJSON(countryLevels?: Map<string, ThreatLevel>): GeoFeatureCollection {
  return {
    type: 'FeatureCollection',
    features: worldFeatures
      .filter((feature) => feature.geometry)
      .map((feature, index) => {
        const id = normalizeWorldId(feature.id ?? index);
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

function regionsToGeoJSON(regions: AttackRegion[]): GeoFeatureCollection {
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

function emptyFC(): GeoFeatureCollection {
  return { type: 'FeatureCollection', features: [] };
}

function escapeHtml(value: string) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}
