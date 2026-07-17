import { Button, Radio, Table, Tag } from '@arco-design/web-react';
import { lazy, Suspense, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Maximize2, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { fetchChinaMapBoundaryByCode, fetchLogs } from '../../api/client';
import { preloadAttackScreenPage, preloadGlobeMap } from '../../routes/preload';
import type { LogEntry } from '../../types/api';
import { displayAction, displayCategory, displayCountry, displayGeoPlace, displaySeverity, isSameGeoCountry } from '../../utils/display';
import {
  aggregateRegions,
  buildCountryLevelMap,
  graticulePath,
  resolveProtectedTarget,
  severityRank,
  threatLevelFor,
  worldFeatures,
  worldMapPaths,
  type AttackRegion,
  type LocationPrecision,
  type ThreatLevel,
} from './attackMapData';
import type { GeoFeatureCollection } from './chinaBoundaries';
import OsmAttackMap, { type OsmAttackMapHandle } from './OsmAttackMap';
import '../../styles/attack-map.css';

const OFFLINE_CHINA_BOUNDARY_QUERY_KEY = ['attack-map-china-boundary-offline'] as const;

const GlobeMap = lazy(() => import('./GlobeMap'));

type MapMode = '2d' | '3d' | 'china';
type ChinaBoundariesModule = typeof import('./chinaBoundaries');

export default function AttackMapPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [mode, setMode] = useState<MapMode>(() => parseMapMode(searchParams.get('mode')));
  const [zoom, setZoom] = useState(1);
  const [selectedRegionKey, setSelectedRegionKey] = useState<string | null>(null);
  const osmMapRef = useRef<OsmAttackMapHandle | null>(null);
  const preferAdcodesRef = useRef<string[]>([]);
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 5_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);
  const mappedRegions = useMemo(() => regions.filter((region) => region.mappable), [regions]);
  const chinaRegions = useMemo(() => mappedRegions.filter(isChinaRegion), [mappedRegions]);
  const { data: chinaBoundaries, isLoading: isChinaModuleLoading, isError: isChinaModuleError } = useQuery<ChinaBoundariesModule>({
    queryKey: ['attack-map-china-boundaries-module'],
    queryFn: () => import('./chinaBoundaries'),
    enabled: mode === 'china',
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const { data: chinaAssets, isLoading: isChinaAssetsLoading, isError: isChinaAssetsError } = useQuery({
    queryKey: ['attack-map-china-assets'],
    queryFn: () => chinaBoundaries!.loadChinaMapAssets(),
    enabled: mode === 'china' && Boolean(chinaBoundaries),
    retry: false,
    staleTime: 60 * 60_000,
  });
  const chinaBoundaryAdcodes = useMemo(
    () => chinaBoundaries?.boundaryAdcodesFromRegions(chinaRegions, chinaAssets?.adminIndex) ?? [],
    [chinaAssets?.adminIndex, chinaBoundaries, chinaRegions],
  );
  preferAdcodesRef.current = chinaBoundaryAdcodes;
  // Offline open pack (`china-map-echarts` in node_modules / dist): progressive
  // province → prefer 区县 → remaining city parents. No network tile CDN.
  const { data: externalChinaBoundary } = useQuery({
    queryKey: ['attack-map-china-boundary-external', chinaBoundaryAdcodes],
    queryFn: async () => {
      const collections = await Promise.all(chinaBoundaryAdcodes.map(async (adcode) => {
        const response = await fetchChinaMapBoundaryByCode(adcode);
        return response.enabled && isFeatureCollection(response.geojson) ? response.geojson : null;
      }));
      const features = collections.flatMap((collection) => collection?.features ?? []);
      return features.length > 0 ? { type: 'FeatureCollection', features } as GeoFeatureCollection : null;
    },
    enabled: mode === 'china' && Boolean(chinaAssets) && chinaBoundaryAdcodes.length > 0,
    retry: false,
    staleTime: 30 * 60_000,
  });
  const { data: offlineChinaBoundary, isFetching: isOfflineBoundaryLoading, isError: isOfflineBoundaryError } = useQuery({
    // Stable key: full offline tree is identical regardless of prefer order.
    queryKey: OFFLINE_CHINA_BOUNDARY_QUERY_KEY,
    queryFn: () => chinaBoundaries!.loadOfflineChinaBoundaryTree({
      includeDistricts: true,
      preferAdcodes: preferAdcodesRef.current,
      onPartial: (partial) => {
        queryClient.setQueryData(OFFLINE_CHINA_BOUNDARY_QUERY_KEY, partial);
      },
    }),
    enabled: mode === 'china' && Boolean(chinaBoundaries) && Boolean(chinaAssets),
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const chinaAdministrativeMap = useMemo(
    () => chinaAssets && chinaBoundaries
      ? chinaBoundaries.createChinaAdministrativeMap(chinaAssets, chinaRegions, externalChinaBoundary ?? null, offlineChinaBoundary ?? null)
      : null,
    [offlineChinaBoundary, chinaAssets, chinaBoundaries, chinaRegions, externalChinaBoundary],
  );
  /** WGS84 GeoJSON overlay for MapLibre China mode (province + city + district offline pack). */
  const chinaMaplibreBoundary = useMemo<GeoFeatureCollection | null>(() => {
    const features = [
      ...(chinaAssets?.country.features ?? []),
      ...(offlineChinaBoundary?.features ?? []),
      ...(externalChinaBoundary?.features ?? []),
    ];
    return features.length > 0 ? { type: 'FeatureCollection', features } : null;
  }, [chinaAssets, offlineChinaBoundary, externalChinaBoundary]);
  const countryLevels = useMemo(() => buildCountryLevelMap(mappedRegions), [mappedRegions]);
  const protectedTarget = useMemo(() => resolveProtectedTarget(data?.items ?? [], t), [data?.items, t]);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);
  const mappedTotal = mappedRegions.reduce((sum, region) => sum + region.attacks, 0);
  const chinaTotal = chinaRegions.reduce((sum, region) => sum + region.attacks, 0);
  const unmappedTotal = Math.max(0, total - mappedTotal);
  const mapTotal = mode === 'china' ? chinaTotal : total;
  const mapMappedTotal = mode === 'china' ? chinaTotal : mappedTotal;
  const visibleMapRegions = mode === 'china' ? chinaRegions : mappedRegions;
  const mapCanvasRef = useRef<HTMLElement | null>(null);
  const chinaBoundaryUnavailable = mode === 'china' && (
    isChinaModuleError
    || isChinaAssetsError
    || isOfflineBoundaryError
    || Boolean(mode === 'china' && chinaAssets && (chinaAssets.country.features?.length ?? 0) === 0 && (offlineChinaBoundary?.features.length ?? 0) === 0)
  );
  // Province basemap (chinaAssets.country) is enough to paint; district pack fills progressively.
  const chinaBoundaryLoading = !chinaBoundaryUnavailable && (
    isChinaModuleLoading
    || isChinaAssetsLoading
    || (isOfflineBoundaryLoading && !(offlineChinaBoundary?.features.length) && !(chinaAssets?.country.features.length))
  );
  const chinaBoundaryDegraded = mode === 'china'
    && Boolean(chinaAdministrativeMap)
    && !chinaBoundaryUnavailable
    && chinaAdministrativeMap?.sourceSummary !== 'external'
    && chinaAdministrativeMap?.sourceSummary !== 'builtin-district'
    && (isOfflineBoundaryLoading || chinaAdministrativeMap?.sourceSummary === 'builtin-province');

  function updateZoom(next: number | ((current: number) => number)) {
    setZoom((current) => {
      const raw = typeof next === 'function' ? next(current) : next;
      return Math.max(0.75, Math.min(3, Number(raw.toFixed(2))));
    });
  }

  function resetView(forMode: MapMode = mode) {
    if (forMode === '2d' || forMode === 'china') {
      osmMapRef.current?.resetView();
      setSelectedRegionKey(null);
      return;
    }
    setZoom(1);
    setSelectedRegionKey(null);
  }

  function selectMode(nextMode: MapMode) {
    if (nextMode === '3d') {
      void preloadGlobeMap();
    }
    const nextParams = new URLSearchParams(searchParams);
    if (nextMode === '2d') {
      nextParams.delete('mode');
    } else {
      nextParams.set('mode', nextMode);
    }
    setSearchParams(nextParams, { replace: true });
    setMode(nextMode);
    resetView(nextMode);
  }

  useEffect(() => {
    if (!selectedRegionKey || (mode !== '2d' && mode !== 'china')) {
      return;
    }
    const region = visibleMapRegions.find((item) => item.key === selectedRegionKey);
    if (region) {
      osmMapRef.current?.flyToRegion(region);
    }
  }, [selectedRegionKey, mode, visibleMapRegions]);

  return (
    <section className="page-surface attack-map-page">
      <header className="page-header attack-map-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
      </header>

      <section className="map-workbench">
        <div className="map-workbench-header">
          <div className="map-legend">
            <strong>{mapTotal}</strong>
            <span>{t('attackMap.attacks')}</span>
            <small>{mode === 'china' ? t('attackMap.chinaRegionMapped', { count: mapMappedTotal }) : t('attackMap.mapped', { count: mapMappedTotal })}</small>
            {mode === 'china' && total > chinaTotal && <small>{t('attackMap.otherRegions', { count: total - chinaTotal })}</small>}
            {mode === 'china' && (
              <small>
                {chinaBoundaryUnavailable
                  ? t('attackMap.boundaryUnavailable')
                  : chinaAdministrativeMap && !chinaBoundaryLoading
                  ? t('attackMap.boundarySource', { source: chinaBoundaries?.chinaBoundarySourceLabel(chinaAdministrativeMap.sourceSummary, t) ?? t('attackMap.boundaryLoading') })
                  : t('attackMap.boundaryLoading')}
              </small>
            )}
            {chinaBoundaryDegraded && <small>{t('attackMap.boundaryDegraded')}</small>}
            {mode === 'china' && chinaAdministrativeMap && !chinaBoundaryLoading && chinaBoundaryAdcodes.length > 0 && chinaAdministrativeMap.sourceSummary !== 'external' && (
              <small>{t('attackMap.districtBoundarySourceHint')}</small>
            )}
            {mode !== 'china' && unmappedTotal > 0 && <small>{t('attackMap.unmapped', { count: unmappedTotal })}</small>}
          </div>
          <div className="map-risk-legend" aria-hidden="true">
            {(['low', 'medium', 'high', 'critical'] as ThreatLevel[]).map((level) => (
              <span key={level} className={`map-risk-dot map-risk-${level}`}>{t(`attackMap.risk.${level}`)}</span>
            ))}
          </div>
          <div className="attack-map-toolbar">
            <div className="map-controls">
              <span className="map-control-group map-mode-switch">
                <Radio.Group type="button" value={mode} onChange={(value) => selectMode(value as MapMode)}>
                  <Radio value="2d">{t('attackMap.mode2d')}</Radio>
                  <Radio
                    value="3d"
                    onMouseEnter={() => void preloadGlobeMap()}
                    onFocus={() => void preloadGlobeMap()}
                  >
                    {t('attackMap.mode3d')}
                  </Radio>
                  <Radio value="china">{t('attackMap.modeChina')}</Radio>
                </Radio.Group>
              </span>
              <span className="map-control-group map-zoom-group" role="group" aria-label={t('attackMap.zoomControlsAria')}>
                <Button
                  icon={<ZoomOut size={14} />}
                  aria-label={t('attackMap.zoomOut')}
                  title={t('attackMap.zoomOut')}
                  disabled={mode === '3d' && zoom <= 0.75}
                  onClick={() => {
                    if (mode === '2d' || mode === 'china') {
                      osmMapRef.current?.zoomOut();
                      return;
                    }
                    updateZoom((current) => current - 0.15);
                  }}
                />
                <Button
                  icon={<ZoomIn size={14} />}
                  aria-label={t('attackMap.zoomIn')}
                  title={t('attackMap.zoomIn')}
                  disabled={mode === '3d' && zoom >= 3}
                  onClick={() => {
                    if (mode === '2d' || mode === 'china') {
                      osmMapRef.current?.zoomIn();
                      return;
                    }
                    updateZoom((current) => current + 0.15);
                  }}
                />
                <Button icon={<RotateCcw size={14} />} onClick={() => resetView()} aria-label={t('attackMap.resetView')}>
                  {t('attackMap.resetView')}
                </Button>
              </span>
              <span className="map-control-group map-action-group">
                <Button
                  icon={<Maximize2 size={14} />}
                  onMouseEnter={() => {
                    void preloadAttackScreenPage();
                    void preloadGlobeMap();
                  }}
                  onFocus={() => {
                    void preloadAttackScreenPage();
                    void preloadGlobeMap();
                  }}
                  onClick={() => {
                    void preloadAttackScreenPage();
                    void preloadGlobeMap();
                    navigate('/attack-map/screen');
                  }}
                >
                  {t('attackMap.bigScreen')}
                </Button>
              </span>
            </div>
          </div>
        </div>

        <section
          ref={mapCanvasRef}
          className={`map-canvas map-mode-${mode} map-engine-osm ${mode === '3d' && zoom > 1.01 ? 'map-can-pan' : ''}`}
        >
          {mode === '3d' ? (
            <Suspense fallback={renderGlobeFallback(mappedRegions, countryLevels, t('attackMap.worldMapAria'))}>
              <GlobeMap
                regions={mappedRegions}
                zoom={zoom}
                countryLevels={countryLevels}
                worldFeatures={worldFeatures}
                target={protectedTarget}
                fallback={renderGlobeFallback(mappedRegions, countryLevels, t('attackMap.worldMapAria'))}
              />
            </Suspense>
          ) : (
            <OsmAttackMap
              mode={mode === 'china' ? 'china' : 'world'}
              regions={mode === 'china' ? chinaRegions : mappedRegions}
              selectedRegionKey={selectedRegionKey}
              onSelectRegion={setSelectedRegionKey}
              ariaLabel={mode === 'china' ? t('attackMap.chinaMapAria') : t('attackMap.worldMapAria')}
              chinaBoundary={mode === 'china' ? chinaMaplibreBoundary : null}
              countryLevels={countryLevels}
              mapRef={osmMapRef}
              formatTooltip={(region) => formatRegionTooltip(region, t)}
            />
          )}
          {(regions.length === 0 || (mode === 'china' && chinaRegions.length === 0)) && (
            <div className="map-empty" role="status" aria-live="polite">
              {isLoading ? t('attackMap.loading') : (mode === 'china' ? t('attackMap.chinaRegionEmpty') : `${t('attackMap.attacks')}: 0`)}
            </div>
          )}
          {chinaBoundaryUnavailable && (
            <div className="map-empty map-warning" role="status">
              {t('attackMap.boundaryUnavailableDetail')}
            </div>
          )}
          <div className="map-basemap-credit" aria-hidden="true">
            {mode === '3d'
              ? 'Three.js globe'
              : mode === 'china'
                ? 'Offline · world-atlas + china-map-echarts (区县) · MapLibre'
                : 'Offline · world-atlas · MapLibre'}
          </div>
        </section>
      </section>

      <section className="table-panel attack-map-table">
        <div className="panel-heading">
          <h2>{t('attackMap.locationDetails')}</h2>
          <span>{t('attackMap.locationDetailsHint')}</span>
        </div>
        <div className="desktop-table-wrap">
          <Table
            rowKey="key"
            pagination={{ pageSize: 8, showTotal: true }}
            loading={isLoading}
            data={visibleMapRegions}
            rowClassName={(record) => (record.key === selectedRegionKey ? 'attack-region-row-selected' : '')}
            onRow={(record) => ({
              onClick: () => setSelectedRegionKey(record.key),
            })}
            expandedRowRender={(record) => <RegionEventDetails region={record as AttackRegion} />}
            columns={[
              { title: t('attackMap.country'), dataIndex: 'countryCode', render: (value: string) => displayCountry(value, t) },
              { title: t('attackMap.location'), dataIndex: 'locationName', render: (_: string, record: AttackRegion) => formatRegionLocation(record, t) },
              { title: t('attackMap.precision'), dataIndex: 'precision', render: (value: LocationPrecision) => t(`attackMap.precisionLevel.${value}`) },
              { title: t('attackMap.accuracy'), dataIndex: 'accuracyRadiusKm', render: (_: number | null, record: AttackRegion) => formatAccuracy(record, t) },
              { title: t('attackMap.locationSource'), dataIndex: 'locationSource', render: (value: string) => value || '-' },
              { title: t('attackMap.attacks'), dataIndex: 'attacks' },
              { title: t('attackMap.riskLabel'), dataIndex: 'level', render: (level: ThreatLevel) => <Tag color={riskTagColor(level)}>{t(`attackMap.risk.${level}`)}</Tag> },
              { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{displayCategory(top, t)}</Tag> },
              { title: t('attackMap.sources'), dataIndex: 'sourcePrefixes', render: (items: string[]) => items.join(', ') || '-' },
            ]}
          />
        </div>
        <div className="mobile-card-list attack-region-cards">
          {visibleMapRegions.map((region) => (
            <AttackRegionCard
              key={region.key}
              region={region}
              selected={region.key === selectedRegionKey}
              onSelect={() => setSelectedRegionKey(region.key)}
              t={t}
            />
          ))}
        </div>
      </section>
    </section>
  );
}

function AttackRegionCard({
  region,
  selected,
  onSelect,
  t,
}: {
  region: AttackRegion;
  selected: boolean;
  onSelect: () => void;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  return (
    <article
      className={['mobile-data-card attack-region-card', selected ? 'attack-region-card-selected' : ''].filter(Boolean).join(' ')}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onSelect();
        }
      }}
    >
      <header>
        <strong>{formatRegionLocation(region, t)}</strong>
        <Tag color={riskTagColor(region.level)}>{t(`attackMap.risk.${region.level}`)}</Tag>
      </header>
      <dl>
        <div>
          <dt>{t('attackMap.precision')}</dt>
          <dd>{t(`attackMap.precisionLevel.${region.precision}`)}</dd>
        </div>
        <div>
          <dt>{t('attackMap.accuracy')}</dt>
          <dd>{formatAccuracy(region, t)}</dd>
        </div>
        <div>
          <dt>{t('attackMap.locationSource')}</dt>
          <dd>{region.locationSource || '-'}</dd>
        </div>
        <div>
          <dt>{t('attackMap.attacks')}</dt>
          <dd>{region.attacks}</dd>
        </div>
        <div>
          <dt>{t('attackMap.top')}</dt>
          <dd><Tag color="orange">{displayCategory(region.top, t)}</Tag></dd>
        </div>
        <div>
          <dt>{t('attackMap.sources')}</dt>
          <dd>{region.sourcePrefixes.join(', ') || '-'}</dd>
        </div>
      </dl>
    </article>
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

function WorldMapSVG({ countryLevels, ariaLabel }: { countryLevels: Map<string, ThreatLevel>; ariaLabel: string }) {
  return (
    <svg className="world-map-svg world-map-svg-default" viewBox="0 0 1000 500" role="img" aria-label={ariaLabel}>
      <title>{ariaLabel}</title>
      <rect className="map-ocean" x="16" y="16" width="968" height="468" rx="18" />
      <path className="map-graticule" d={graticulePath} />
      <g className="map-land">
        {worldMapPaths.map((item) => <path key={item.id} className={`map-risk-${countryLevels.get(item.id) ?? 'neutral'}`} d={item.d} />)}
      </g>
    </svg>
  );
}

function renderGlobeFallback(regions: AttackRegion[], countryLevels: Map<string, ThreatLevel>, ariaLabel = 'Attack source map') {
  return (
    <div className="globe-stage globe-stage-fallback">
      <div className="flat-map-stage globe-fallback-flat" style={{ '--map-zoom': 1, '--map-pan-x': '0px', '--map-pan-y': '0px' } as CSSProperties}>
        <WorldMapSVG countryLevels={countryLevels} ariaLabel={ariaLabel} />
        {regions.map((region) => (
          <span
            key={region.key}
            className={`map-marker map-risk-${region.level}`}
            aria-label={`${region.locationName} · ${region.attacks}`}
            style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
          >
            <i />
            <span><strong>{region.locationName}</strong><em>{region.attacks}</em></span>
          </span>
        ))}
      </div>
    </div>
  );
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

function parseMapMode(value: string | null): MapMode {
  if (value === '3d' || value === 'china') {
    return value;
  }
  return '2d';
}

function isFeatureCollection(value: unknown): value is GeoFeatureCollection {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record.type === 'FeatureCollection' && Array.isArray(record.features);
}

function isChinaRegion(region: AttackRegion) {
  return ['CN', 'HK', 'MO', 'TW'].includes(region.countryCode);
}

function formatRegionLocation(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  const country = displayCountry(region.countryCode, t);
  if (region.locationName && region.locationName !== region.countryCode && region.locationName !== 'UNLOCATED') {
    const location = region.locationName
      .split(/\s+路\s+|\s*·\s*|\s*\/\s*/)
      .filter((part) => !isSameGeoCountry(part, region.countryCode, t))
      .map((part) => displayGeoPlace(part, region.countryCode, t))
      .filter(Boolean)
      .join(' / ');
    return location ? `${country} / ${location}` : country;
  }
  return country;
}

function formatRegionDetail(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  const precision = t(`attackMap.precisionLevel.${region.precision}`);
  const accuracy = formatAccuracy(region, t);
  const locationSource = region.locationSource ? ` · ${region.locationSource}` : '';
  const source = region.sourcePrefixes[0] ? ` · ${region.sourcePrefixes[0]}` : '';
  return `${precision} · ${accuracy}${locationSource}${source}`;
}

function formatRegionTooltip(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  return `${formatRegionLocation(region, t)} · ${region.attacks} · ${displayCategory(region.top, t)} · ${t(`attackMap.risk.${region.level}`)} · ${formatRegionDetail(region, t)}`;
}

function formatAccuracy(region: AttackRegion, t: (key: string, options?: Record<string, unknown>) => string) {
  if (region.accuracyRadiusKm !== null && Number.isFinite(region.accuracyRadiusKm) && region.accuracyRadiusKm > 0) {
    return t('attackMap.accuracyRadius', { value: Math.round(region.accuracyRadiusKm) });
  }
  if (region.precision === 'country') {
    return t('attackMap.countryFallback');
  }
  if (region.precision === 'ip-range') {
    return t('attackMap.ipRangeFallback');
  }
  return t('attackMap.accuracyUnknown');
}

function formatShortTime(value: string) {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return '-';
  }
  return new Date(time).toLocaleString(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}
