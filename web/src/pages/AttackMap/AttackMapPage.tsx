import { Button, Radio, Table, Tag } from '@arco-design/web-react';
import { lazy, Suspense, useMemo, useRef, useState, type CSSProperties, type PointerEvent, type WheelEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Maximize2, Minus, Plus, RotateCcw } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { geoContains, geoGraticule10, geoMercator, geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import worldTopology from 'world-atlas/countries-110m.json';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';
import { displayAction, displayCategory, displayCountry, displaySeverity, normalizeCountryCode } from '../../utils/display';

const GlobeMap = lazy(() => import('./GlobeMap'));

type MapMode = '2d' | '3d' | 'china';
export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';
type LocationPrecision = 'district' | 'city' | 'region' | 'country' | 'ip-range';
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
type MapPan = { x: number; y: number };
type DragState = { pointerId: number; startX: number; startY: number; originX: number; originY: number };
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
  precision: LocationPrecision;
  sourcePrefixes: string[];
  events: Array<Pick<LogEntry, 'id' | 'trace_id' | 'timestamp' | 'client_ip' | 'method' | 'uri' | 'action' | 'category' | 'severity' | 'status_code'>>;
};
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
  precision: LocationPrecision;
  sourcePrefixes: Map<string, number>;
  events: Array<Pick<LogEntry, 'id' | 'trace_id' | 'timestamp' | 'client_ip' | 'method' | 'uri' | 'action' | 'category' | 'severity' | 'status_code'>>;
};

const mapWidth = 1000;
const mapHeight = 500;
const chinaMapWidth = 960;
const chinaMapHeight = 620;
const topo = worldTopology as any;
const worldFeatureCollection = feature(topo, topo.objects.countries) as unknown as WorldFeatureCollection;
export const worldFeatures = worldFeatureCollection.features.filter((item) => item.geometry);
const mapProjection = geoNaturalEarth1().fitExtent([[28, 28], [mapWidth - 28, mapHeight - 28]], worldFeatureCollection as any);
const mapPath = geoPath(mapProjection);
const graticulePath = mapPath(geoGraticule10() as any) ?? '';
export const worldMapPaths = worldFeatures
  .map((item, index) => ({ id: normalizeWorldId(item.id ?? index), d: mapPath(item as any) ?? '' }))
  .filter((item) => item.d);

const countryCoordinates: Record<string, CountryCoordinate> = {
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

const countryNumericIds: Record<string, string> = {
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

const chinaNumericId = countryNumericIds.CN;
const chinaTerritoryIds = new Set([countryNumericIds.CN, countryNumericIds.HK, countryNumericIds.MO, countryNumericIds.TW]);
const chinaFeature = worldFeatures.find((item) => normalizeWorldId(item.id ?? '') === chinaNumericId);
const chinaTerritoryFeatures = worldFeatures.filter((item) => chinaTerritoryIds.has(normalizeWorldId(item.id ?? '')));
const chinaTerritoryCollection: WorldFeatureCollection = { type: 'FeatureCollection', features: chinaTerritoryFeatures.length ? chinaTerritoryFeatures : (chinaFeature ? [chinaFeature] : []) };
const chinaProjection = geoMercator().fitExtent(
  [[42, 34], [chinaMapWidth - 42, chinaMapHeight - 34]],
  (chinaTerritoryCollection.features.length ? chinaTerritoryCollection : worldFeatureCollection) as any,
);
const chinaMapPath = geoPath(chinaProjection);
const chinaGraticulePath = chinaMapPath(geoGraticule10() as any) ?? '';
const chinaPath = chinaFeature ? (chinaMapPath(chinaFeature as any) ?? '') : '';
const chinaTerritoryPaths = chinaTerritoryFeatures
  .map((item) => ({ id: normalizeWorldId(item.id ?? ''), d: chinaMapPath(item as any) ?? '' }))
  .filter((item) => item.d);
const chinaViewBox = `0 0 ${chinaMapWidth} ${chinaMapHeight}`;
const chinaReferencePoints = [
  { key: 'beijing', zh: '北京', en: 'Beijing', lon: 116.4, lat: 39.9 },
  { key: 'shanghai', zh: '上海', en: 'Shanghai', lon: 121.5, lat: 31.2 },
  { key: 'guangzhou', zh: '广州', en: 'Guangzhou', lon: 113.3, lat: 23.1 },
  { key: 'chengdu', zh: '成都', en: 'Chengdu', lon: 104.1, lat: 30.7 },
  { key: 'wuhan', zh: '武汉', en: 'Wuhan', lon: 114.3, lat: 30.6 },
  { key: 'xian', zh: '西安', en: "Xi'an", lon: 108.9, lat: 34.3 },
  { key: 'urumqi', zh: '乌鲁木齐', en: 'Urumqi', lon: 87.6, lat: 43.8 },
  { key: 'harbin', zh: '哈尔滨', en: 'Harbin', lon: 126.6, lat: 45.8 },
  { key: 'kunming', zh: '昆明', en: 'Kunming', lon: 102.8, lat: 25.0 },
  { key: 'lhasa', zh: '拉萨', en: 'Lhasa', lon: 91.1, lat: 29.7 },
  { key: 'hongkong', zh: '香港', en: 'Hong Kong', lon: 114.2, lat: 22.3 },
  { key: 'macau', zh: '澳门', en: 'Macau', lon: 113.5, lat: 22.2 },
  { key: 'taipei', zh: '台北', en: 'Taipei', lon: 121.6, lat: 25.0 },
  { key: 'haikou', zh: '海南', en: 'Hainan', lon: 110.3, lat: 20.0 },
].map((item) => ({ ...item, point: projectChinaSvgPoint(item.lon, item.lat) })).filter((item) => item.point);
const chinaIslandPoints = [
  { key: 'diaoyu', lon: 123.5, lat: 25.8 },
  { key: 'dongsha', lon: 116.8, lat: 20.7 },
  { key: 'xisha', lon: 112.0, lat: 16.8 },
  { key: 'nansha', lon: 114.2, lat: 10.2 },
].map((item) => ({ ...item, point: projectChinaSvgPoint(item.lon, item.lat) })).filter((item) => item.point);

export default function AttackMapPage() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<MapMode>(() => parseMapMode(searchParams.get('mode')));
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState<MapPan>({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [selectedRegionKey, setSelectedRegionKey] = useState<string | null>(null);
  const dragRef = useRef<DragState | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 5_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);
  const mappedRegions = useMemo(() => regions.filter((region) => region.mappable), [regions]);
  const chinaRegions = useMemo(() => mappedRegions.filter(isChinaRegion), [mappedRegions]);
  const countryLevels = useMemo(() => buildCountryLevelMap(mappedRegions), [mappedRegions]);
  const chinaCountryLevels = useMemo(() => buildCountryLevelMap(chinaRegions), [chinaRegions]);
  const protectedTarget = useMemo(() => resolveProtectedTarget(data?.items ?? [], t), [data?.items, t]);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);
  const mappedTotal = mappedRegions.reduce((sum, region) => sum + region.attacks, 0);
  const chinaTotal = chinaRegions.reduce((sum, region) => sum + region.attacks, 0);
  const unmappedTotal = Math.max(0, total - mappedTotal);
  const mapTotal = mode === 'china' ? chinaTotal : total;
  const mapMappedTotal = mode === 'china' ? chinaTotal : mappedTotal;
  const showDetailedLabels = zoom >= 1.25;
  const visibleMapRegions = mode === 'china' ? chinaRegions : mappedRegions;
  const highlightedRegionKey = selectedRegionKey ?? (showDetailedLabels ? (visibleMapRegions[0]?.key ?? null) : null);

  function updateZoom(next: number | ((current: number) => number)) {
    setZoom((current) => {
      const raw = typeof next === 'function' ? next(current) : next;
      const clamped = Math.max(0.75, Math.min(3, Number(raw.toFixed(2))));
      setPan((currentPan) => clampPan(currentPan, clamped));
      return clamped;
    });
  }

  function resetView() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedRegionKey(null);
  }

  function selectMode(nextMode: MapMode) {
    const nextParams = new URLSearchParams(searchParams);
    if (nextMode === '2d') {
      nextParams.delete('mode');
    } else {
      nextParams.set('mode', nextMode);
    }
    setSearchParams(nextParams, { replace: true });
    setMode(nextMode);
    resetView();
  }

  function handleWheel(event: WheelEvent<HTMLElement>) {
    if (mode === '3d') {
      return;
    }
    event.preventDefault();
    updateZoom((current) => current + (event.deltaY > 0 ? -0.12 : 0.12));
  }

  function handlePointerDown(event: PointerEvent<HTMLElement>) {
    if (mode === '3d' || event.button !== 0 || zoom <= 1.01) {
      return;
    }
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originX: pan.x,
      originY: pan.y,
    };
    setDragging(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function handlePointerMove(event: PointerEvent<HTMLElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) {
      return;
    }
    setPan(clampPan({
      x: drag.originX + event.clientX - drag.startX,
      y: drag.originY + event.clientY - drag.startY,
    }, zoom));
  }

  function handlePointerEnd(event: PointerEvent<HTMLElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) {
      return;
    }
    dragRef.current = null;
    setDragging(false);
    event.currentTarget.releasePointerCapture(event.pointerId);
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
        <div className="map-controls">
          <span className="map-control-group map-mode-switch">
            <Radio.Group type="button" value={mode} onChange={(value) => selectMode(value as MapMode)}>
              <Radio value="2d">{t('attackMap.mode2d')}</Radio>
              <Radio value="3d">{t('attackMap.mode3d')}</Radio>
              <Radio value="china">{t('attackMap.modeChina')}</Radio>
            </Radio.Group>
          </span>
          <span className="map-control-group map-zoom-group">
            <Button icon={<Minus size={14} />} onClick={() => updateZoom((current) => current - 0.15)} title={t('attackMap.zoomOut')} />
            <span>{Math.round(zoom * 100)}%</span>
            <Button icon={<Plus size={14} />} onClick={() => updateZoom((current) => current + 0.15)} title={t('attackMap.zoomIn')} />
            <Button icon={<RotateCcw size={14} />} onClick={resetView} title={t('attackMap.resetView')} />
          </span>
          <span className="map-control-group map-action-group">
            <Button icon={<Maximize2 size={14} />} onClick={() => navigate('/attack-map/screen')}>{t('attackMap.bigScreen')}</Button>
          </span>
        </div>
      </header>

      <section
        className={`map-canvas map-mode-${mode} ${mode !== '3d' && zoom > 1.01 ? 'map-can-pan' : ''} ${dragging ? 'map-panning' : ''}`}
        onWheel={handleWheel}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerEnd}
        onPointerCancel={handlePointerEnd}
      >
        <div className="map-legend">
          <strong>{mapTotal}</strong>
          <span>{t('attackMap.attacks')}</span>
          <small>{mode === 'china' ? t('attackMap.mainlandMapped', { count: mapMappedTotal }) : t('attackMap.mapped', { count: mapMappedTotal })}</small>
          {mode === 'china' && total > chinaTotal && <small>{t('attackMap.otherRegions', { count: total - chinaTotal })}</small>}
          {mode !== 'china' && unmappedTotal > 0 && <small>{t('attackMap.unmapped', { count: unmappedTotal })}</small>}
        </div>
        <div className="map-risk-legend" aria-hidden="true">
          {(['low', 'medium', 'high', 'critical'] as ThreatLevel[]).map((level) => (
            <span key={level} className={`map-risk-dot map-risk-${level}`}>{t(`attackMap.risk.${level}`)}</span>
          ))}
        </div>
        {mode === '3d' ? (
          <Suspense fallback={<div className="globe-stage"><div className="page-spinner" aria-label={t('attackMap.loading')} aria-busy="true" /></div>}>
            <GlobeMap
              regions={mappedRegions}
              zoom={zoom}
              countryLevels={countryLevels}
              worldFeatures={worldFeatures}
              target={protectedTarget}
              fallback={renderGlobeFallback(mappedRegions, countryLevels)}
            />
          </Suspense>
        ) : (
          <div
            className="flat-map-stage"
            style={{ '--map-zoom': zoom, '--map-pan-x': `${pan.x}px`, '--map-pan-y': `${pan.y}px` } as CSSProperties}
          >
            {mode === 'china' ? <ChinaMainlandMap countryLevels={chinaCountryLevels} language={i18n.language.startsWith('zh') ? 'zh' : 'en'} /> : <WorldMapSVG countryLevels={countryLevels} />}
            {mode === '2d' && mappedRegions.map((region) => (
              <span
                key={region.key}
                tabIndex={0}
                className={[
                  'map-marker',
                  `map-risk-${region.level}`,
                  showDetailedLabels ? 'map-marker-detailed' : '',
                  highlightedRegionKey === region.key ? 'map-marker-selected' : '',
                  showDetailedLabels ? markerLabelAnchorClass(region.x) : '',
                ].filter(Boolean).join(' ')}
                style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
                title={formatRegionTooltip(region, t)}
                onClick={(event) => {
                  event.stopPropagation();
                  setSelectedRegionKey(region.key);
                }}
                onFocus={() => setSelectedRegionKey(region.key)}
              >
                <i />
                <span>
                  <strong>{showDetailedLabels ? formatRegionLocation(region, t) : displayCountry(region.countryCode, t)}</strong>
                  <em>{region.attacks}</em>
                  {showDetailedLabels && <small>{formatRegionDetail(region, t)}</small>}
                </span>
              </span>
            ))}
            {mode === 'china' && chinaRegions.map((region) => {
              const point = projectChinaPoint(region.lon, region.lat);
              if (!point) {
                return null;
              }
              return (
                <span
                  key={region.key}
                  tabIndex={0}
                  className={[
                    'map-marker',
                    `map-risk-${region.level}`,
                    showDetailedLabels ? 'map-marker-detailed' : '',
                    highlightedRegionKey === region.key ? 'map-marker-selected' : '',
                    showDetailedLabels ? markerLabelAnchorClass(point.x) : '',
                  ].filter(Boolean).join(' ')}
                  style={{ left: `${point.x}%`, top: `${point.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
                  title={formatRegionTooltip(region, t)}
                  onClick={(event) => {
                    event.stopPropagation();
                    setSelectedRegionKey(region.key);
                  }}
                  onFocus={() => setSelectedRegionKey(region.key)}
                >
                  <i />
                  <span>
                    <strong>{showDetailedLabels ? formatRegionLocation(region, t) : displayCountry(region.countryCode, t)}</strong>
                    <em>{region.attacks}</em>
                    {showDetailedLabels && <small>{formatRegionDetail(region, t)}</small>}
                  </span>
                </span>
              );
            })}
          </div>
        )}
        {(regions.length === 0 || (mode === 'china' && chinaRegions.length === 0)) && (
          <div className="map-empty">
            {isLoading ? t('attackMap.loading') : (mode === 'china' ? t('attackMap.mainlandEmpty') : `${t('attackMap.attacks')}: 0`)}
          </div>
        )}
      </section>

      <section className="table-panel attack-map-table">
        <Table
          rowKey="key"
          pagination={false}
          loading={isLoading}
          data={mode === 'china' ? chinaRegions : regions}
          expandedRowRender={(record) => <RegionEventDetails region={record as AttackRegion} />}
          columns={[
            { title: t('attackMap.country'), dataIndex: 'countryCode', render: (value: string) => displayCountry(value, t) },
            { title: t('attackMap.location'), dataIndex: 'locationName', render: (_: string, record: AttackRegion) => formatRegionLocation(record, t) },
            { title: t('attackMap.precision'), dataIndex: 'precision', render: (value: LocationPrecision) => t(`attackMap.precisionLevel.${value}`) },
            { title: t('attackMap.attacks'), dataIndex: 'attacks' },
            { title: t('attackMap.riskLabel'), dataIndex: 'level', render: (level: ThreatLevel) => <Tag color={riskTagColor(level)}>{t(`attackMap.risk.${level}`)}</Tag> },
            { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{displayCategory(top, t)}</Tag> },
            { title: t('attackMap.sources'), dataIndex: 'sourcePrefixes', render: (items: string[]) => items.join(', ') || '-' },
          ]}
        />
      </section>
    </section>
  );
}

function RegionEventDetails({ region }: { region: AttackRegion }) {
  const { t } = useTranslation();
  return (
    <div className="attack-region-detail">
      <div className="attack-region-detail-summary">
        <span>{formatRegionTooltip(region, t)}</span>
        <span>{t('attackMap.regionPrecisionHint')}</span>
      </div>
      <div className="attack-region-event-list">
        {region.events.map((event) => (
          <div key={event.trace_id || event.id} className="attack-region-event">
            <code>{event.trace_id || event.id || '-'}</code>
            <span>{formatShortTime(event.timestamp)}</span>
            <span>{event.client_ip || '-'}</span>
            <span>{event.method || 'GET'} {event.uri || '/'}</span>
            <Tag color={event.action === 'block' ? 'red' : 'orange'}>{displayAction(event.action, t)}</Tag>
            <Tag color={riskTagColor(threatLevelFor(1, severityRank(event.severity), 1))}>{displaySeverity(event.severity, t)}</Tag>
          </div>
        ))}
      </div>
    </div>
  );
}

function WorldMapSVG({ countryLevels, variant = 'default' }: { countryLevels: Map<string, ThreatLevel>; variant?: 'default' | 'china' }) {
  return (
    <svg className={`world-map-svg world-map-svg-${variant}`} viewBox="0 0 1000 500" aria-hidden="true">
      <rect className="map-ocean" x="16" y="16" width="968" height="468" rx="18" />
      <path className="map-graticule" d={graticulePath} />
      <g className="map-land">
        {worldMapPaths.map((item) => <path key={item.id} className={`map-risk-${countryLevels.get(item.id) ?? 'neutral'}`} d={item.d} />)}
      </g>
    </svg>
  );
}

function ChinaMainlandMap({ countryLevels, language }: { countryLevels: Map<string, ThreatLevel>; language: 'zh' | 'en' }) {
  const chinaLevel = countryLevels.get(chinaNumericId) ?? 'neutral';
  return (
    <svg className="china-map-svg world-map-svg" viewBox={chinaViewBox} aria-hidden="true">
      <defs>
        <clipPath id="china-mainland-clip">
          {chinaPath && <path d={chinaPath} />}
        </clipPath>
      </defs>
      <rect className="map-ocean china-map-ocean" x="0" y="0" width={chinaMapWidth} height={chinaMapHeight} rx="18" />
      <path className="map-graticule china-map-graticule" d={chinaGraticulePath} />
      {chinaPath && <path className="china-mainland-shadow" d={chinaPath} />}
      <g className="china-territories">
        {chinaTerritoryPaths.map((item) => (
          <path
            key={item.id}
            className={`china-mainland-path china-territory-${item.id} map-risk-${countryLevels.get(item.id) ?? (item.id === chinaNumericId ? chinaLevel : 'neutral')}`}
            d={item.d}
          />
        ))}
      </g>
      {chinaPath && <path className="china-mainland-inner-grid" d={chinaGraticulePath} clipPath="url(#china-mainland-clip)" />}
      <g className="china-island-dots">
        {chinaIslandPoints.map((item) => (
          <circle key={item.key} cx={item.point?.x ?? 0} cy={item.point?.y ?? 0} r="2.8" />
        ))}
      </g>
      <g className="china-map-labels">
        {chinaReferencePoints.map((item) => (
          <g key={item.key} transform={`translate(${item.point?.x ?? 0} ${item.point?.y ?? 0})`}>
            <circle r="3.2" />
            <text x="8" y="4">{language === 'zh' ? item.zh : item.en}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

function renderGlobeFallback(regions: AttackRegion[], countryLevels: Map<string, ThreatLevel>) {
  return (
    <div className="globe-stage globe-stage-fallback">
      <div className="flat-map-stage globe-fallback-flat" style={{ '--map-zoom': 1, '--map-pan-x': '0px', '--map-pan-y': '0px' } as CSSProperties}>
        <WorldMapSVG countryLevels={countryLevels} />
        {regions.map((region) => (
          <span
            key={region.key}
            className={`map-marker map-risk-${region.level}`}
            style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
            title={`${region.locationName} · ${region.attacks}`}
          >
            <i />
            <span><strong>{region.locationName}</strong><em>{region.attacks}</em></span>
          </span>
        ))}
      </div>
    </div>
  );
}

export function aggregateRegions(entries: LogEntry[]): AttackRegion[] {
  const buckets = new Map<string, RegionBucket>();
  for (const entry of entries) {
    if (!isSecurityEvent(entry)) {
      continue;
    }
    const location = resolveLocation(entry);
    const key = `${location.countryCode}|${location.locationName}|${location.sourcePrefix}`;
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
      precision: location.precision,
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
        precision: bucket.precision,
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

function resolveProtectedTarget(entries: LogEntry[], t: (key: string, options?: Record<string, unknown>) => string): ProtectedTarget {
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

function resolveLocation(entry: LogEntry) {
  const metadata = entry.metadata ?? {};
  const countryCode = inferCountry(entry);
  const coord = countryCoordinates[countryCode];
  const metadataContinent = normalizeContinent(readMetadataString(metadata, ['continent', 'continent_name', 'geo.continent', 'geo.continent_name']));
  const metadataCountryName = readEntryString(entry, metadata, ['country_name', 'geo.country_name']);
  const lat = readEntryNumber(entry, metadata, ['lat', 'latitude', 'geo_lat', 'geo.latitude', 'location.lat']);
  const lon = readEntryNumber(entry, metadata, ['lon', 'lng', 'longitude', 'geo_lon', 'geo.longitude', 'location.lon', 'location.lng']);
  const region = readEntryString(entry, metadata, ['district', 'county', 'area', 'city', 'region', 'province', 'state', 'subdivision', 'geo.region', 'geo.city']);
  const precise = validCoordinate(lat, lon);
  const sourcePrefix = ipPrefix(entry.client_ip);
  const fallbackName = countryCode === 'UNLOCATED' ? (metadataCountryName || sourcePrefix || 'UNLOCATED') : countryCode;
  const locationName = region || (sourcePrefix && !coord ? sourcePrefix : fallbackName);
  const point = precise ? jitterCoordinate(lon, lat, entry.client_ip || locationName) : null;
  return {
    countryCode,
    continent: metadataContinent || (coord?.continent ?? 'UNLOCATED'),
    lon: point?.lon ?? coord?.lon ?? 0,
    lat: point?.lat ?? coord?.lat ?? 0,
    mappable: Boolean(point || coord),
    locationName,
    precision: precisionForLocation({ precise, metadata, region, sourcePrefix, countryCode }),
    sourcePrefix,
  };
}

function precisionForLocation(input: { precise: boolean; metadata: Record<string, unknown>; region: string; sourcePrefix: string; countryCode: string }): LocationPrecision {
  if (input.precise && readMetadataString(input.metadata, ['district', 'county', 'area'])) {
    return 'district';
  }
  if (input.precise && readMetadataString(input.metadata, ['city', 'geo.city'])) {
    return 'city';
  }
  if (input.precise && input.region) {
    return 'region';
  }
  if (input.countryCode !== 'UNLOCATED') {
    return 'country';
  }
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

function severityRank(severity: string | undefined) {
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
  if (rank >= 4) {
    return 'critical';
  }
  if (rank >= 3) {
    return 'high';
  }
  if (rank >= 2) {
    return 'medium';
  }
  if (rank >= 1) {
    return 'low';
  }
  return 'info';
}

function threatLevelFor(attacks: number, maxSeverity: number, maxAttacks: number): ThreatLevel {
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

function riskTagColor(level: ThreatLevel) {
  switch (level) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orangered';
    case 'medium':
      return 'orange';
    default:
      return 'blue';
  }
}

function markerLabelAnchorClass(x: number) {
  if (x > 72) {
    return 'map-marker-label-left';
  }
  if (x < 28) {
    return 'map-marker-label-right';
  }
  return 'map-marker-label-bottom';
}

function parseMapMode(value: string | null): MapMode {
  if (value === '3d' || value === 'china') {
    return value;
  }
  return '2d';
}

function projectMapPoint(lon: number, lat: number) {
  const point = mapProjection([lon, lat]);
  if (!point) {
    return null;
  }
  return {
    x: (point[0] / mapWidth) * 100,
    y: (point[1] / mapHeight) * 100,
  };
}

function projectChinaPoint(lon: number, lat: number) {
  const point = projectChinaSvgPoint(lon, lat);
  if (!point) {
    return null;
  }
  return {
    x: (point.x / chinaMapWidth) * 100,
    y: (point.y / chinaMapHeight) * 100,
  };
}

function projectChinaSvgPoint(lon: number, lat: number) {
  const point = chinaProjection([lon, lat]);
  if (!point) {
    return null;
  }
  return {
    x: point[0],
    y: point[1],
  };
}

function isChinaRegion(region: AttackRegion) {
  if (!['CN', 'HK', 'MO', 'TW'].includes(region.countryCode)) {
    return false;
  }
  if (region.countryCode !== 'CN' || !chinaFeature || !validCoordinate(region.lat, region.lon)) {
    return true;
  }
  return geoContains(chinaFeature as any, [region.lon, region.lat]);
}

function formatRegionLocation(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  const country = displayCountry(region.countryCode, t);
  if (region.locationName && region.locationName !== region.countryCode && region.locationName !== 'UNLOCATED') {
    return `${country} · ${region.locationName}`;
  }
  return country;
}

function formatRegionDetail(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  const precision = t(`attackMap.precisionLevel.${region.precision}`);
  const source = region.sourcePrefixes[0] ? ` · ${region.sourcePrefixes[0]}` : '';
  return `${precision}${source}`;
}

function formatRegionTooltip(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  return `${formatRegionLocation(region, t)} · ${region.attacks} · ${displayCategory(region.top, t)} · ${t(`attackMap.risk.${region.level}`)} · ${formatRegionDetail(region, t)}`;
}

function formatShortTime(value: string) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return '-';
  }
  return new Date(time).toLocaleString(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
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

function jitterCoordinate(lon: number | null, lat: number | null, key: string) {
  if (!validCoordinate(lat, lon)) {
    return null;
  }
  const safeLon = lon as number;
  const safeLat = lat as number;
  const hash = Array.from(key).reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return {
    lon: safeLon + ((hash % 9) - 4) * 0.12,
    lat: safeLat + (((hash >> 3) % 9) - 4) * 0.08,
  };
}

function ipPrefix(ip: string | undefined) {
  const parts = String(ip ?? '').split('.');
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(Number(part)))) {
    return '';
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function clampPan(pan: MapPan, zoom: number) {
  const limitX = Math.max(0, (zoom - 1) * 420);
  const limitY = Math.max(0, (zoom - 1) * 260);
  return {
    x: Math.max(-limitX, Math.min(limitX, pan.x)),
    y: Math.max(-limitY, Math.min(limitY, pan.y)),
  };
}

export function normalizeWorldId(id: string | number) {
  const value = String(id);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? String(parsed) : value;
}
