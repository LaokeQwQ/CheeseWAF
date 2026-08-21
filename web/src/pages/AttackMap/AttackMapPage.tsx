import { Fragment, lazy, Suspense, useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { ChevronDown, ChevronLeft, ChevronRight, Maximize2, RotateCcw, ZoomIn, ZoomOut } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Badge,
  Button,
  Spinner,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui';
import { fetchChinaMapBoundaryByCode, fetchLogs } from '../../api/client';
import QueryErrorState from '../../components/QueryErrorState';
import { preloadAttackScreenPage, preloadGlobeMap } from '../../routes/preload';
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
import { threatLevels, threatShapeLabel, threatShapeClass } from './threatPalette';
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
  const lastFlyKeyRef = useRef<string | null>(null);
  const offlineAbortRef = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    offlineAbortRef.current = controller;
    return () => {
      controller.abort();
      if (offlineAbortRef.current === controller) {
        offlineAbortRef.current = null;
      }
    };
  }, [mode]);
  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['attack-map-logs'],
    queryFn: () => fetchLogs({ limit: 1000 }),
    refetchInterval: 5_000,
    retry: false,
  });
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
        return response.enabled ? sanitizeExternalBoundary(response.geojson) : null;
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
      includeDistricts: false,
      preferAdcodes: preferAdcodesRef.current,
      signal: offlineAbortRef.current?.signal,
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
    const merged = chinaBoundaries?.mergeChinaBoundaries(
      chinaAssets?.country ?? null,
      offlineChinaBoundary ?? null,
      externalChinaBoundary ?? null,
    );
    return merged && merged.collection.features.length > 0 ? merged.collection : null;
  }, [chinaBoundaries, chinaAssets, offlineChinaBoundary, externalChinaBoundary]);
  const countryLevels = useMemo(() => buildCountryLevelMap(mappedRegions), [mappedRegions]);
  const protectedTarget = useMemo(() => resolveProtectedTarget(data?.items ?? [], t), [data?.items, t]);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);
  const mappedTotal = mappedRegions.reduce((sum, region) => sum + region.attacks, 0);
  const chinaTotal = chinaRegions.reduce((sum, region) => sum + region.attacks, 0);
  const unmappedTotal = Math.max(0, total - mappedTotal);
  const mapTotal = mode === 'china' ? chinaTotal : total;
  const mapMappedTotal = mode === 'china' ? chinaTotal : mappedTotal;
  const visibleMapRegions = mode === 'china' ? chinaRegions : mappedRegions;
  const selectedRegionLat = selectedRegionKey
    ? visibleMapRegions.find((item) => item.key === selectedRegionKey)?.lat
    : undefined;
  const selectedRegionLon = selectedRegionKey
    ? visibleMapRegions.find((item) => item.key === selectedRegionKey)?.lon
    : undefined;
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

  // Keep mode in sync with browser back/forward on ?mode=.
  useEffect(() => {
    const nextMode = parseMapMode(searchParams.get('mode'));
    setMode((current) => (current === nextMode ? current : nextMode));
  }, [searchParams]);

  // Fly only when selection (or its coordinates) change — not on every logs refetch array rebuild.
  useEffect(() => {
    if (!selectedRegionKey || (mode !== '2d' && mode !== 'china')) {
      if (!selectedRegionKey) {
        lastFlyKeyRef.current = null;
      }
      return;
    }
    const flyToken = `${mode}:${selectedRegionKey}:${selectedRegionLat ?? ''}:${selectedRegionLon ?? ''}`;
    if (lastFlyKeyRef.current === flyToken) {
      return;
    }
    const region = visibleMapRegions.find((item) => item.key === selectedRegionKey);
    if (region) {
      osmMapRef.current?.flyToRegion(region);
      lastFlyKeyRef.current = flyToken;
    }
  }, [selectedRegionKey, mode, selectedRegionLat, selectedRegionLon, visibleMapRegions]);

  return (
    <section className="page-surface attack-map-page">
      <header className="page-header attack-map-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
      </header>

      {isError && !data && (
        <QueryErrorState onRetry={() => void refetch()} retrying={isFetching} />
      )}

      <section className="map-workbench">
        <div className="map-workbench-header">
          <div className="map-legend">
            <strong>{isError && !data ? '—' : mapTotal}</strong>
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
          <div className="map-risk-legend" role="list" aria-label={t('attackMap.riskLegend')}>
            {threatLevels.map((level) => (
              <span key={level} className={`map-risk-dot map-risk-${level}`} role="listitem">
                <i className={`map-risk-shape map-risk-shape-${threatShapeClass[level]}`} aria-hidden="false">{threatShapeLabel[level]}</i>
                {t(`attackMap.risk.${level}`)}
              </span>
            ))}
          </div>
          <div className="attack-map-toolbar">
            <div className="map-controls">
              <span className="map-control-group map-mode-switch inline-flex rounded-md border">
                {([
                  { value: '2d' as const, label: t('attackMap.mode2d') },
                  { value: '3d' as const, label: t('attackMap.mode3d'), preload: true },
                  { value: 'china' as const, label: t('attackMap.modeChina') },
                ]).map((item) => (
                  <Button
                    key={item.value}
                    type="button"
                    size="sm"
                    variant={mode === item.value ? 'default' : 'ghost'}
                    className="rounded-none first:rounded-l-md last:rounded-r-md"
                    onMouseEnter={item.preload ? () => void preloadGlobeMap() : undefined}
                    onFocus={item.preload ? () => void preloadGlobeMap() : undefined}
                    onClick={() => selectMode(item.value)}
                  >
                    {item.label}
                  </Button>
                ))}
              </span>
              <span className="map-control-group map-zoom-group" role="group" aria-label={t('attackMap.zoomControlsAria')}>
                <Button
                  size="icon"
                  variant="outline"
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
                >
                  <ZoomOut size={14} />
                </Button>
                <Button
                  size="icon"
                  variant="outline"
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
                >
                  <ZoomIn size={14} />
                </Button>
                <Button variant="outline" onClick={() => resetView()} aria-label={t('attackMap.resetView')}>
                  <RotateCcw size={14} />
                  {t('attackMap.resetView')}
                </Button>
              </span>
              <span className="map-control-group map-action-group">
                <Button
                  variant="outline"
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
                  <Maximize2 size={14} />
                  {t('attackMap.bigScreen')}
                </Button>
              </span>
            </div>
          </div>
        </div>

        <section
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
              {isLoading
                ? t('attackMap.loading')
                : isError
                  ? t('common.loadFailed')
                  : (mode === 'china' ? t('attackMap.chinaRegionEmpty') : `${t('attackMap.attacks')}: 0`)}
            </div>
          )}
          {chinaBoundaryUnavailable && (
            <div className="map-empty map-warning" role="status">
              {t('attackMap.boundaryUnavailableDetail')}
            </div>
          )}
          <div className="map-basemap-credit" aria-hidden="true">
            {mode === '3d'
              ? t('attackMap.basemapCredit3d')
              : mode === 'china'
                ? t('attackMap.basemapCreditChina')
                : t('attackMap.basemapCreditWorld')}
          </div>
        </section>
      </section>

      <section className="table-panel attack-map-table">
        <div className="panel-heading">
          <h2>{t('attackMap.locationDetails')}</h2>
          <span>{t('attackMap.locationDetailsHint')}</span>
        </div>
        <div className="desktop-table-wrap">
          <AttackRegionTable
            regions={visibleMapRegions}
            selectedRegionKey={selectedRegionKey}
            onSelectRegion={setSelectedRegionKey}
            loading={isLoading}
            t={t}
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
        <Badge variant={riskBadgeVariant(region.level)}>{t(`attackMap.risk.${region.level}`)}</Badge>
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
          <dd><Badge variant="warning">{displayCategory(region.top, t)}</Badge></dd>
        </div>
        <div>
          <dt>{t('attackMap.sources')}</dt>
          <dd>{region.sourcePrefixes.join(', ') || '-'}</dd>
        </div>
      </dl>
    </article>
  );
}

const REGION_PAGE_SIZE = 8;

function AttackRegionTable({
  regions,
  selectedRegionKey,
  onSelectRegion,
  loading,
  t,
}: {
  regions: AttackRegion[];
  selectedRegionKey: string | null;
  onSelectRegion: (key: string) => void;
  loading: boolean;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  const [page, setPage] = useState(1);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const totalPages = Math.max(1, Math.ceil(regions.length / REGION_PAGE_SIZE));
  const pageItems = regions.slice((page - 1) * REGION_PAGE_SIZE, page * REGION_PAGE_SIZE);
  const pageStart = regions.length === 0 ? 0 : (page - 1) * REGION_PAGE_SIZE + 1;
  const pageEnd = Math.min(page * REGION_PAGE_SIZE, regions.length);

  const regionsSignature = useMemo(
    () => (regions.length === 0 ? '0' : `${regions.length}:${regions[0]?.key ?? ''}:${regions[regions.length - 1]?.key ?? ''}`),
    [regions],
  );

  useEffect(() => {
    setPage(1);
  }, [regionsSignature]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  if (loading && regions.length === 0) {
    return (
      <div className="flex items-center justify-center py-10">
        <Spinner />
      </div>
    );
  }

  return (
    <div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead>{t('attackMap.country')}</TableHead>
            <TableHead>{t('attackMap.location')}</TableHead>
            <TableHead>{t('attackMap.precision')}</TableHead>
            <TableHead>{t('attackMap.accuracy')}</TableHead>
            <TableHead>{t('attackMap.locationSource')}</TableHead>
            <TableHead>{t('attackMap.attacks')}</TableHead>
            <TableHead>{t('attackMap.riskLabel')}</TableHead>
            <TableHead>{t('attackMap.top')}</TableHead>
            <TableHead>{t('attackMap.sources')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {pageItems.length === 0 ? (
            <TableRow>
              <TableCell colSpan={10} className="text-center text-muted-foreground">{t('common.noData')}</TableCell>
            </TableRow>
          ) : pageItems.map((record) => {
            const selected = record.key === selectedRegionKey;
            const expanded = record.key === expandedKey;
            return (
              <Fragment key={record.key}>
                <TableRow
                  className={selected ? 'attack-region-row-selected' : ''}
                  data-state={selected ? 'selected' : undefined}
                  tabIndex={0}
                  onClick={() => onSelectRegion(record.key)}
                  onKeyDown={(event: KeyboardEvent) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelectRegion(record.key);
                    }
                  }}
                >
                  <TableCell>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7"
                      aria-expanded={expanded}
                      aria-label={t('attackMap.locationDetails')}
                      onClick={(event) => {
                        event.stopPropagation();
                        setExpandedKey((current) => (current === record.key ? null : record.key));
                      }}
                    >
                      <ChevronDown size={14} className={expanded ? 'rotate-180 transition-transform' : 'transition-transform'} />
                    </Button>
                  </TableCell>
                  <TableCell>{displayCountry(record.countryCode, t)}</TableCell>
                  <TableCell>{formatRegionLocation(record, t)}</TableCell>
                  <TableCell>{t(`attackMap.precisionLevel.${record.precision as LocationPrecision}`)}</TableCell>
                  <TableCell>{formatAccuracy(record, t)}</TableCell>
                  <TableCell>{record.locationSource || '-'}</TableCell>
                  <TableCell>{record.attacks}</TableCell>
                  <TableCell>
                    <Badge variant={riskBadgeVariant(record.level)}>{t(`attackMap.risk.${record.level}`)}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="warning">{displayCategory(record.top, t)}</Badge>
                  </TableCell>
                  <TableCell>{record.sourcePrefixes.join(', ') || '-'}</TableCell>
                </TableRow>
                {expanded ? (
                  <TableRow>
                    <TableCell colSpan={10}>
                      <RegionEventDetails region={record} />
                    </TableCell>
                  </TableRow>
                ) : null}
              </Fragment>
            );
          })}
        </TableBody>
      </Table>
      {regions.length > REGION_PAGE_SIZE && (
        <footer className="security-events-pagination">
          <span>{pageStart}-{pageEnd} / {regions.length}</span>
          <div>
            <Button
              size="icon"
              variant="outline"
              aria-label={t('common.back')}
              disabled={page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
            >
              <ChevronLeft size={15} />
            </Button>
            <strong>{page}</strong>
            <Button
              size="icon"
              variant="outline"
              aria-label={t('common.next')}
              disabled={page >= totalPages}
              onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
            >
              <ChevronRight size={15} />
            </Button>
          </div>
        </footer>
      )}
    </div>
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
        {region.events.map((event, index) => (
          <div key={event.trace_id || event.id || `row-${index}`} className="attack-region-event">
            <code>{event.trace_id || event.id || '-'}</code>
            <span>{formatShortTime(event.timestamp)}</span>
            <span>{event.client_ip || '-'}</span>
            <span>{event.method || 'GET'} {event.uri || '/'}</span>
            <Badge variant={event.action === 'block' ? 'destructive' : 'warning'}>{displayAction(event.action, t)}</Badge>
            <Badge variant={riskBadgeVariant(threatLevelFor(1, severityRank(event.severity), 1))}>{displaySeverity(event.severity, t)}</Badge>
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

function renderGlobeFallback(regions: AttackRegion[], countryLevels: Map<string, ThreatLevel>, ariaLabel: string) {
  return (
    <div className="globe-stage globe-stage-fallback">
      <div className="flat-map-stage globe-fallback-flat" style={{ '--map-zoom': 1, '--map-pan-x': '0px', '--map-pan-y': '0px' } as CSSProperties}>
        <WorldMapSVG countryLevels={countryLevels} ariaLabel={ariaLabel} />
        {regions.map((region) => (
          <span
            key={region.key}
            className={`map-marker map-risk-${region.level}`}
            role="img"
            tabIndex={0}
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

function riskBadgeVariant(level: ThreatLevel): 'destructive' | 'warning' | 'default' {
  switch (level) {
    case 'critical':
    case 'high':
      return 'destructive';
    case 'medium':
      return 'warning';
    default:
      return 'default';
  }
}

function parseMapMode(value: string | null): MapMode {
  if (value === '3d' || value === 'china') {
    return value;
  }
  return '2d';
}

const EXTERNAL_BOUNDARY_MAX_FEATURES = 2000;
const EXTERNAL_BOUNDARY_MAX_BYTES = 5_000_000;

function isFeatureCollection(value: unknown): value is GeoFeatureCollection {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record.type === 'FeatureCollection' && Array.isArray(record.features);
}

/**
 * Shallow-validate externally provided China boundary GeoJSON before it reaches
 * the map / SVG layers. A crafted or malformed response is discarded and the
 * UI falls back to offline boundaries.
 */
function sanitizeExternalBoundary(value: unknown): GeoFeatureCollection | null {
  if (!isFeatureCollection(value)) {
    return null;
  }
  const features = (value as GeoFeatureCollection).features;
  if (features.length === 0) {
    return value as GeoFeatureCollection;
  }
  if (features.length > EXTERNAL_BOUNDARY_MAX_FEATURES) {
    return null;
  }
  if (JSON.stringify(value).length > EXTERNAL_BOUNDARY_MAX_BYTES) {
    return null;
  }
  for (const feature of features) {
    if (!validGeometryCoordinates(feature.geometry)) {
      return null;
    }
  }
  return value as GeoFeatureCollection;
}

function validGeometryCoordinates(geometry: unknown): boolean {
  if (!geometry || typeof geometry !== 'object') {
    return false;
  }
  const record = geometry as { type?: unknown; coordinates?: unknown };
  if (record.type === 'Point') {
    return isCoordinate(record.coordinates);
  }
  if (record.type === 'MultiPoint' || record.type === 'LineString') {
    return Array.isArray(record.coordinates) && record.coordinates.every(isCoordinate);
  }
  if (record.type === 'MultiLineString' || record.type === 'Polygon') {
    return Array.isArray(record.coordinates) && record.coordinates.every((ring: unknown) => Array.isArray(ring) && ring.every(isCoordinate));
  }
  if (record.type === 'MultiPolygon') {
    return Array.isArray(record.coordinates) && record.coordinates.every((polygon: unknown) => Array.isArray(polygon) && polygon.every((ring: unknown) => Array.isArray(ring) && ring.every(isCoordinate)));
  }
  return false;
}

function isCoordinate(value: unknown): boolean {
  if (!Array.isArray(value) || value.length < 2) {
    return false;
  }
  const lon = Number(value[0]);
  const lat = Number(value[1]);
  return Number.isFinite(lon) && Number.isFinite(lat) && lon >= -180 && lon <= 180 && lat >= -90 && lat <= 90;
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
