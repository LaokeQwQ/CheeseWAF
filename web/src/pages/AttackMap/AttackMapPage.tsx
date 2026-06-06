import { Button, Radio, Table, Tag } from '@arco-design/web-react';
import { useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent, type WheelEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Minus, Plus, RotateCcw } from 'lucide-react';
import { geoEquirectangular, geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { feature } from 'topojson-client';
import worldTopology from 'world-atlas/countries-50m.json';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';
import { displayCategory, displayContinent, displayCountry, displaySeverity, normalizeCountryCode } from '../../utils/display';

type MapMode = '2d' | '3d' | 'continent';
type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';
type LocationPrecision = 'district' | 'city' | 'region' | 'country' | 'ip-range';
type WorldFeature = {
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
type AttackRegion = {
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
};
type ContinentRegion = {
  key: string;
  name: string;
  attacks: number;
  top: string;
  severityRank: number;
  level: ThreatLevel;
  x: number;
  y: number;
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
};

const mapWidth = 1000;
const mapHeight = 500;
const topo = worldTopology as any;
const worldFeatureCollection = feature(topo, topo.objects.countries) as unknown as WorldFeatureCollection;
const worldFeatures = worldFeatureCollection.features.filter((item) => item.geometry);
const mapProjection = geoNaturalEarth1().fitExtent([[28, 28], [mapWidth - 28, mapHeight - 28]], worldFeatureCollection as any);
const mapPath = geoPath(mapProjection);
const graticulePath = mapPath(geoGraticule10() as any) ?? '';
const worldMapPaths = worldFeatures
  .map((item, index) => ({ id: normalizeWorldId(item.id ?? index), d: mapPath(item as any) ?? '' }))
  .filter((item) => item.d);

const countryCoordinates: Record<string, CountryCoordinate> = {
  AR: { lon: -63.6, lat: -38.4, continent: 'South America' },
  AU: { lon: 133.8, lat: -25.3, continent: 'Oceania' },
  BR: { lon: -51.9, lat: -14.2, continent: 'South America' },
  CA: { lon: -106.3, lat: 56.1, continent: 'North America' },
  CN: { lon: 104.2, lat: 35.9, continent: 'Asia' },
  DE: { lon: 10.5, lat: 51.1, continent: 'Europe' },
  ES: { lon: -3.7, lat: 40.4, continent: 'Europe' },
  FR: { lon: 2.2, lat: 46.2, continent: 'Europe' },
  GB: { lon: -3.4, lat: 55.4, continent: 'Europe' },
  HK: { lon: 114.2, lat: 22.3, continent: 'Asia' },
  ID: { lon: 113.9, lat: -0.8, continent: 'Asia' },
  IN: { lon: 78.9, lat: 20.6, continent: 'Asia' },
  IT: { lon: 12.6, lat: 42.8, continent: 'Europe' },
  JP: { lon: 138.2, lat: 36.2, continent: 'Asia' },
  KR: { lon: 127.8, lat: 35.9, continent: 'Asia' },
  MX: { lon: -102.6, lat: 23.6, continent: 'North America' },
  NL: { lon: 5.3, lat: 52.1, continent: 'Europe' },
  PL: { lon: 19.1, lat: 52.1, continent: 'Europe' },
  RU: { lon: 105.3, lat: 61.5, continent: 'Europe/Asia' },
  SE: { lon: 18.6, lat: 60.1, continent: 'Europe' },
  SG: { lon: 103.8, lat: 1.3, continent: 'Asia' },
  TH: { lon: 100.9, lat: 15.9, continent: 'Asia' },
  TR: { lon: 35.2, lat: 39.0, continent: 'Europe/Asia' },
  US: { lon: -95.7, lat: 37.1, continent: 'North America' },
  VN: { lon: 108.3, lat: 14.1, continent: 'Asia' },
  ZA: { lon: 22.9, lat: -30.6, continent: 'Africa' },
};

const countryNumericIds: Record<string, string> = {
  AR: '32',
  AU: '36',
  BR: '76',
  CA: '124',
  CN: '156',
  DE: '276',
  ES: '724',
  FR: '250',
  GB: '826',
  HK: '344',
  ID: '360',
  IN: '356',
  IT: '380',
  JP: '392',
  KR: '410',
  MX: '484',
  NL: '528',
  PL: '616',
  RU: '643',
  SE: '752',
  SG: '702',
  TH: '764',
  TR: '792',
  US: '840',
  VN: '704',
  ZA: '710',
};

const continentCoordinates: Record<string, { lon: number; lat: number }> = {
  Africa: { lon: 20, lat: 4 },
  Asia: { lon: 92, lat: 36 },
  Europe: { lon: 15, lat: 52 },
  'Europe/Asia': { lon: 62, lat: 50 },
  'North America': { lon: -102, lat: 47 },
  Oceania: { lon: 138, lat: -24 },
  'South America': { lon: -61, lat: -16 },
};

const globeLevelColors: Record<ThreatLevel, number> = {
  low: 0x2176d2,
  medium: 0xd98912,
  high: 0xf97316,
  critical: 0xdd3b3b,
};

export default function AttackMapPage() {
  const { t } = useTranslation();
  const [mode, setMode] = useState<MapMode>('2d');
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState<MapPan>({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragRef = useRef<DragState | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 5_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);
  const continents = useMemo(() => aggregateContinents(regions), [regions]);
  const mappedRegions = regions.filter((region) => region.mappable);
  const countryLevels = useMemo(() => buildCountryLevelMap(regions), [regions]);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);
  const showDetailedLabels = zoom >= 1.35;

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
          <Radio.Group type="button" value={mode} onChange={(value) => { setMode(value as MapMode); resetView(); }}>
            <Radio value="2d">{t('attackMap.mode2d')}</Radio>
            <Radio value="3d">{t('attackMap.mode3d')}</Radio>
            <Radio value="continent">{t('attackMap.modeContinent')}</Radio>
          </Radio.Group>
          <Button icon={<Minus size={14} />} onClick={() => updateZoom((current) => current - 0.15)} title={t('attackMap.zoomOut')} />
          <span>{Math.round(zoom * 100)}%</span>
          <Button icon={<Plus size={14} />} onClick={() => updateZoom((current) => current + 0.15)} title={t('attackMap.zoomIn')} />
          <Button icon={<RotateCcw size={14} />} onClick={resetView} title={t('attackMap.resetView')} />
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
          <strong>{total}</strong>
          <span>{t('attackMap.attacks')}</span>
        </div>
        <div className="map-risk-legend" aria-hidden="true">
          {(['low', 'medium', 'high', 'critical'] as ThreatLevel[]).map((level) => (
            <span key={level} className={`map-risk-dot map-risk-${level}`}>{t(`attackMap.risk.${level}`)}</span>
          ))}
        </div>
        {mode === '3d' ? (
          <GlobeView regions={mappedRegions} zoom={zoom} countryLevels={countryLevels} />
        ) : (
          <div
            className="flat-map-stage"
            style={{ '--map-zoom': zoom, '--map-pan-x': `${pan.x}px`, '--map-pan-y': `${pan.y}px` } as CSSProperties}
          >
            <WorldMapSVG countryLevels={countryLevels} />
            {mode === '2d' && mappedRegions.map((region) => (
              <span
                key={region.key}
                className={`map-marker map-risk-${region.level} ${showDetailedLabels ? 'map-marker-detailed' : ''}`}
                style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
                title={formatRegionTooltip(region, t)}
              >
                <i />
                <span>
                  <strong>{showDetailedLabels ? formatRegionLocation(region, t) : displayCountry(region.countryCode, t)}</strong>
                  <em>{region.attacks}</em>
                  {showDetailedLabels && <small>{formatRegionDetail(region, t)}</small>}
                </span>
              </span>
            ))}
            {mode === 'continent' && continents.map((continent) => (
              <span
                key={continent.name}
                className={`continent-badge map-risk-${continent.level}`}
                style={{ left: `${continent.x}%`, top: `${continent.y}%` }}
              >
                <strong>{displayContinent(continent.name, t)}</strong>
                <em>{continent.attacks}</em>
                <small>{displayCategory(continent.top, t)} · {displaySeverity(rankToSeverity(continent.severityRank), t)}</small>
              </span>
            ))}
          </div>
        )}
        {regions.length === 0 && <div className="map-empty">{isLoading ? 'Loading' : `${t('attackMap.attacks')}: 0`}</div>}
      </section>

      <section className="table-panel attack-map-table">
        {mode === 'continent' ? (
          <Table
            rowKey="key"
            pagination={false}
            loading={isLoading}
            data={continents}
            columns={[
              { title: t('attackMap.continent'), dataIndex: 'name', render: (value: string) => displayContinent(value, t) },
              { title: t('attackMap.attacks'), dataIndex: 'attacks' },
              { title: t('attackMap.riskLabel'), dataIndex: 'level', render: (level: ThreatLevel) => <Tag color={riskTagColor(level)}>{t(`attackMap.risk.${level}`)}</Tag> },
              { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{displayCategory(top, t)}</Tag> },
            ]}
          />
        ) : (
          <Table
            rowKey="key"
            pagination={false}
            loading={isLoading}
            data={regions}
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
        )}
      </section>
    </section>
  );
}

function GlobeView({ regions, zoom, countryLevels }: { regions: AttackRegion[]; zoom: number; countryLevels: Map<string, ThreatLevel> }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [webglError, setWebglError] = useState(false);

  useEffect(() => {
    if (webglError) {
      return undefined;
    }
    const host = hostRef.current;
    if (!host) {
      return undefined;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0.22, 3 / zoom);
    let renderer: any;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      setWebglError(true);
      return undefined;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    host.appendChild(renderer.domElement);

    const tooltip = document.createElement('div');
    tooltip.className = 'globe-tooltip';
    host.appendChild(tooltip);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.enablePan = false;
    controls.enableZoom = true;
    controls.minDistance = 1.55;
    controls.maxDistance = 4.4;
    controls.rotateSpeed = 0.62;
    controls.zoomSpeed = 0.78;

    const earthGroup = new THREE.Group();
    const texture = createWorldTexture(countryLevels);
    const globe = new THREE.Mesh(
      new THREE.SphereGeometry(1, 128, 128),
      new THREE.MeshStandardMaterial({
        map: texture,
        roughness: 0.82,
        metalness: 0.02,
      }),
    );
    earthGroup.add(globe);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.018, 96, 96),
      new THREE.MeshBasicMaterial({
        color: 0x2f8cff,
        transparent: true,
        opacity: 0.07,
        side: THREE.BackSide,
      }),
    );
    earthGroup.add(atmosphere);

    const markerGroup = new THREE.Group();
    const markerMeshes: any[] = [];
    for (const region of regions) {
      const marker = new THREE.Mesh(
        new THREE.SphereGeometry(Math.max(0.024, Math.min(0.08, region.size / 500)), 24, 24),
        new THREE.MeshBasicMaterial({ color: globeLevelColors[region.level] }),
      );
      marker.position.copy(latLonToVector(region.lat, region.lon, 1.038));
      marker.userData.region = region;
      markerMeshes.push(marker);
      markerGroup.add(marker);
    }
    earthGroup.add(markerGroup);
    earthGroup.rotation.y = -0.35;
    scene.add(earthGroup);

    scene.add(new THREE.AmbientLight(0xffffff, 1.18));
    const light = new THREE.DirectionalLight(0xffffff, 1.8);
    light.position.set(3, 2, 4);
    scene.add(light);

    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    const onPointerMove = (event: globalThis.PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(markerMeshes, false)[0];
      if (!hit) {
        tooltip.classList.remove('globe-tooltip-visible');
        return;
      }
      const region = hit.object.userData.region as AttackRegion;
      tooltip.textContent = `${region.locationName} · ${region.attacks}`;
      tooltip.style.left = `${event.clientX - rect.left + 12}px`;
      tooltip.style.top = `${event.clientY - rect.top + 12}px`;
      tooltip.classList.add('globe-tooltip-visible');
    };
    const onPointerLeave = () => tooltip.classList.remove('globe-tooltip-visible');
    renderer.domElement.addEventListener('pointermove', onPointerMove);
    renderer.domElement.addEventListener('pointerleave', onPointerLeave);

    const resize = () => {
      const rect = host.getBoundingClientRect();
      const width = Math.max(320, rect.width);
      const height = Math.max(320, rect.height);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.position.z = 3 / zoom;
      camera.updateProjectionMatrix();
      renderer.render(scene, camera);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    let frame = 0;
    const tick = () => {
      earthGroup.rotation.y += 0.0012;
      controls.update();
      renderer.render(scene, camera);
      frame = requestAnimationFrame(tick);
    };
    tick();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      controls.dispose();
      renderer.dispose();
      texture?.dispose();
      globe.geometry.dispose();
      atmosphere.geometry.dispose();
      markerGroup.children.forEach((child: any) => {
        if (child instanceof THREE.Mesh) {
          child.geometry.dispose();
          if (Array.isArray(child.material)) {
            child.material.forEach((material: any) => material.dispose());
          } else {
            child.material.dispose();
          }
        }
      });
      host.removeChild(renderer.domElement);
      host.removeChild(tooltip);
    };
  }, [regions, zoom, countryLevels, webglError]);

  if (webglError) {
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

  return <div ref={hostRef} className="globe-stage" />;
}

function WorldMapSVG({ countryLevels }: { countryLevels: Map<string, ThreatLevel> }) {
  return (
    <svg className="world-map-svg" viewBox="0 0 1000 500" aria-hidden="true">
      <path className="map-graticule" d={graticulePath} />
      <g className="map-land">
        {worldMapPaths.map((item) => <path key={item.id} className={`map-risk-${countryLevels.get(item.id) ?? 'neutral'}`} d={item.d} />)}
      </g>
    </svg>
  );
}

function aggregateRegions(entries: LogEntry[]): AttackRegion[] {
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
      };
    })
    .sort((a, b) => b.attacks - a.attacks);
}

function aggregateContinents(regions: AttackRegion[]): ContinentRegion[] {
  const byContinent = new Map<string, { attacks: number; categories: Map<string, number>; maxSeverity: number }>();
  for (const region of regions) {
    const current = byContinent.get(region.continent) ?? { attacks: 0, categories: new Map<string, number>(), maxSeverity: 0 };
    current.attacks += region.attacks;
    current.categories.set(region.top, (current.categories.get(region.top) ?? 0) + region.attacks);
    current.maxSeverity = Math.max(current.maxSeverity, region.severityRank);
    byContinent.set(region.continent, current);
  }
  const maxAttacks = Math.max(1, ...Array.from(byContinent.values()).map((item) => item.attacks));
  return Array.from(byContinent.entries()).map(([name, value]) => {
    const point = continentCoordinates[name] ? projectMapPoint(continentCoordinates[name].lon, continentCoordinates[name].lat) : null;
    return {
      key: name,
      name,
      attacks: value.attacks,
      top: topMapValue(value.categories) ?? '-',
      severityRank: value.maxSeverity,
      level: threatLevelFor(value.attacks, value.maxSeverity, maxAttacks),
      x: point?.x ?? 50,
      y: point?.y ?? 88,
    };
  }).sort((a, b) => b.attacks - a.attacks);
}

function buildCountryLevelMap(regions: AttackRegion[]) {
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

function resolveLocation(entry: LogEntry) {
  const metadata = entry.metadata ?? {};
  const countryCode = inferCountry(entry);
  const coord = countryCoordinates[countryCode];
  const lat = readMetadataNumber(metadata, ['lat', 'latitude', 'geo_lat', 'geo.latitude', 'location.lat']);
  const lon = readMetadataNumber(metadata, ['lon', 'lng', 'longitude', 'geo_lon', 'geo.longitude', 'location.lon', 'location.lng']);
  const region = readMetadataString(metadata, ['district', 'county', 'area', 'city', 'region', 'province', 'state', 'subdivision', 'geo.region', 'geo.city']);
  const precise = validCoordinate(lat, lon);
  const sourcePrefix = ipPrefix(entry.client_ip);
  const fallbackName = countryCode === 'UNLOCATED' ? (sourcePrefix || 'UNLOCATED') : countryCode;
  const locationName = region || (sourcePrefix && !coord ? sourcePrefix : fallbackName);
  const point = precise ? jitterCoordinate(lon, lat, entry.client_ip || locationName) : null;
  return {
    countryCode,
    continent: coord?.continent ?? countryCode,
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

function inferCountry(entry: LogEntry) {
  const metadataCountry = readMetadataString(entry.metadata ?? {}, ['country_code', 'countryCode', 'geo.country_code', 'geo.country']);
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
  if ([3, 4, 8, 13, 15, 18, 20, 23, 34, 35, 44, 52, 54, 63, 64, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 98, 99, 100, 104, 107, 108, 129, 130, 131, 132, 134, 135, 136, 137, 138, 144, 146, 147, 148, 152, 155, 156, 157, 158, 159, 160, 162, 164, 165, 166, 167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216].includes(a)) {
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

function latLonToVector(lat: number, lon: number, radius: number) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
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

function createWorldTexture(countryLevels: Map<string, ThreatLevel>) {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  ctx.fillStyle = '#0f766e';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  const textureProjection = geoEquirectangular()
    .scale(canvas.width / (2 * Math.PI))
    .translate([canvas.width / 2, canvas.height / 2]);
  const texturePath = geoPath(textureProjection, ctx);
  ctx.beginPath();
  texturePath(geoGraticule10() as any);
  ctx.strokeStyle = 'rgba(215,248,228,0.22)';
  ctx.lineWidth = 0.75;
  ctx.stroke();
  for (const item of worldFeatures) {
    ctx.beginPath();
    texturePath(item as any);
    ctx.fillStyle = globeFillForLevel(countryLevels.get(normalizeWorldId(item.id ?? '')));
    ctx.strokeStyle = '#0f513f';
    ctx.lineWidth = 0.72;
    ctx.fill();
    ctx.stroke();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function globeFillForLevel(level: ThreatLevel | undefined) {
  switch (level) {
    case 'critical':
      return '#ef4444';
    case 'high':
      return '#fb923c';
    case 'medium':
      return '#facc15';
    case 'low':
      return '#7dd3fc';
    default:
      return '#d7f8e4';
  }
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

function normalizeWorldId(id: string | number) {
  const value = String(id);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? String(parsed) : value;
}
