import { Button, Radio, Table, Tag } from '@arco-design/web-react';
import { useEffect, useMemo, useRef, useState, type CSSProperties, type WheelEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Minus, Plus } from 'lucide-react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';
import { displayCategory, displayContinent, displayCountry, normalizeCountryCode } from '../../utils/display';

type MapMode = '2d' | '3d' | 'continent';

const countryCoordinates: Record<string, { lon: number; lat: number; continent: string }> = {
  AR: { lon: -63.6, lat: -38.4, continent: 'South America' },
  AU: { lon: 133.8, lat: -25.3, continent: 'Oceania' },
  BR: { lon: -51.9, lat: -14.2, continent: 'South America' },
  CA: { lon: -106.3, lat: 56.1, continent: 'North America' },
  CN: { lon: 104.2, lat: 35.9, continent: 'Asia' },
  DE: { lon: 10.5, lat: 51.1, continent: 'Europe' },
  FR: { lon: 2.2, lat: 46.2, continent: 'Europe' },
  GB: { lon: -3.4, lat: 55.4, continent: 'Europe' },
  HK: { lon: 114.2, lat: 22.3, continent: 'Asia' },
  ID: { lon: 113.9, lat: -0.8, continent: 'Asia' },
  IN: { lon: 78.9, lat: 20.6, continent: 'Asia' },
  JP: { lon: 138.2, lat: 36.2, continent: 'Asia' },
  KR: { lon: 127.8, lat: 35.9, continent: 'Asia' },
  NL: { lon: 5.3, lat: 52.1, continent: 'Europe' },
  RU: { lon: 105.3, lat: 61.5, continent: 'Europe/Asia' },
  SG: { lon: 103.8, lat: 1.3, continent: 'Asia' },
  TH: { lon: 100.9, lat: 15.9, continent: 'Asia' },
  US: { lon: -95.7, lat: 37.1, continent: 'North America' },
  VN: { lon: 108.3, lat: 14.1, continent: 'Asia' },
  ZA: { lon: 22.9, lat: -30.6, continent: 'Africa' },
};

export default function AttackMapPage() {
  const { t } = useTranslation();
  const [mode, setMode] = useState<MapMode>('2d');
  const [zoom, setZoom] = useState(1);
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 5_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);
  const continents = useMemo(() => aggregateContinents(regions), [regions]);
  const mappedRegions = regions.filter((region) => region.mappable);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);

  function updateZoom(next: number) {
    setZoom(Math.max(0.75, Math.min(2.4, Number(next.toFixed(2)))));
  }

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
        <div className="map-controls">
          <Radio.Group type="button" value={mode} onChange={(value) => setMode(value as MapMode)}>
            <Radio value="2d">{t('attackMap.mode2d')}</Radio>
            <Radio value="3d">{t('attackMap.mode3d')}</Radio>
            <Radio value="continent">{t('attackMap.modeContinent')}</Radio>
          </Radio.Group>
          <Button icon={<Minus size={14} />} onClick={() => updateZoom(zoom - 0.15)} />
          <span>{Math.round(zoom * 100)}%</span>
          <Button icon={<Plus size={14} />} onClick={() => updateZoom(zoom + 0.15)} />
        </div>
      </header>

      <section
        className={`map-canvas map-mode-${mode}`}
        onWheel={(event: WheelEvent<HTMLElement>) => updateZoom(zoom + (event.deltaY > 0 ? -0.08 : 0.08))}
      >
        <div className="map-legend">
          <strong>{total}</strong>
          <span>{t('attackMap.attacks')}</span>
        </div>
        {mode === '3d' ? (
          <GlobeView regions={mappedRegions} zoom={zoom} />
        ) : (
          <div className="flat-map-stage" style={{ '--map-zoom': zoom } as CSSProperties}>
            <WorldMapSVG />
            {mode === '2d' && mappedRegions.map((region) => (
              <span
                key={region.key}
                className="map-marker"
                style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
                title={`${displayCountry(region.countryCode, t)} ${region.attacks}`}
              >
                <i />
                <strong>{displayCountry(region.countryCode, t)}</strong>
              </span>
            ))}
            {mode === 'continent' && continents.map((continent) => (
              <span
                key={continent.name}
                className="continent-badge"
                style={{ left: `${continent.x}%`, top: `${continent.y}%` }}
              >
                <strong>{displayContinent(continent.name, t)}</strong>
                <em>{continent.attacks}</em>
                <small>{displayCategory(continent.top, t)}</small>
              </span>
            ))}
          </div>
        )}
        {regions.length === 0 && <div className="map-empty">{isLoading ? 'Loading' : `${t('attackMap.attacks')}: 0`}</div>}
      </section>

      <section className="table-panel">
        {mode === 'continent' ? (
          <Table
            rowKey="key"
            pagination={false}
            loading={isLoading}
            data={continents}
            columns={[
              { title: t('attackMap.continent'), dataIndex: 'name' },
              { title: t('attackMap.attacks'), dataIndex: 'attacks' },
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
              { title: t('attackMap.continent'), dataIndex: 'continent', render: (value: string) => displayContinent(value, t) },
              { title: t('attackMap.attacks'), dataIndex: 'attacks' },
              { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{displayCategory(top, t)}</Tag> },
            ]}
          />
        )}
      </section>
    </section>
  );
}

function GlobeView({ regions, zoom }: { regions: ReturnType<typeof aggregateRegions>; zoom: number }) {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) {
      return undefined;
    }

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0.25, 3 / zoom);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    host.appendChild(renderer.domElement);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.enablePan = false;
    controls.minDistance = 1.7;
    controls.maxDistance = 4.2;
    controls.rotateSpeed = 0.55;
    controls.zoomSpeed = 0.7;

    const globe = new THREE.Mesh(
      new THREE.SphereGeometry(1, 96, 96),
      new THREE.MeshStandardMaterial({
        map: createWorldTexture(),
        roughness: 0.82,
        metalness: 0.03,
      }),
    );
    globe.rotation.y = -0.35;
    scene.add(globe);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.012, 96, 96),
      new THREE.MeshBasicMaterial({
        color: 0x2f8cff,
        transparent: true,
        opacity: 0.07,
        side: THREE.BackSide,
      }),
    );
    scene.add(atmosphere);

    const markerGroup = new THREE.Group();
    for (const region of regions) {
      const marker = new THREE.Mesh(
        new THREE.SphereGeometry(Math.max(0.024, Math.min(0.075, region.size / 520)), 20, 20),
        new THREE.MeshBasicMaterial({ color: 0xef4444 }),
      );
      marker.position.copy(latLonToVector(region.lat, region.lon, 1.035));
      markerGroup.add(marker);
    }
    scene.add(markerGroup);

    scene.add(new THREE.AmbientLight(0xffffff, 1.2));
    const light = new THREE.DirectionalLight(0xffffff, 1.8);
    light.position.set(3, 2, 4);
    scene.add(light);

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
      globe.rotation.y += 0.0016;
      markerGroup.rotation.copy(globe.rotation);
      controls.update();
      renderer.render(scene, camera);
      frame = requestAnimationFrame(tick);
    };
    tick();

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      controls.dispose();
      renderer.dispose();
      globe.geometry.dispose();
      atmosphere.geometry.dispose();
      markerGroup.children.forEach((child: any) => {
        if (child instanceof THREE.Mesh) {
          child.geometry.dispose();
        }
      });
      host.removeChild(renderer.domElement);
    };
  }, [regions, zoom]);

  return <div ref={hostRef} className="globe-stage" />;
}

function WorldMapSVG() {
  return (
    <svg className="world-map-svg" viewBox="0 0 1000 500" aria-hidden="true">
      <g className="map-graticule">
        {[125, 250, 375, 500, 625, 750, 875].map((x) => <line key={`v-${x}`} x1={x} y1="42" x2={x} y2="458" />)}
        {[100, 180, 250, 320, 400].map((y) => <line key={`h-${y}`} x1="48" y1={y} x2="952" y2={y} />)}
      </g>
      <g className="map-land">
        {worldMapPaths.map((item) => <path key={item} d={item} />)}
      </g>
    </svg>
  );
}

function aggregateRegions(entries: LogEntry[]) {
  const byCountry = new Map<string, { attacks: number; categories: Map<string, number> }>();
  for (const entry of entries) {
    if (!entry.category && entry.action !== 'block' && entry.action !== 'challenge') {
      continue;
    }
    const country = inferCountry(entry);
    const current = byCountry.get(country) ?? { attacks: 0, categories: new Map<string, number>() };
    current.attacks += 1;
    const category = entry.category || entry.action || 'unknown';
    current.categories.set(category, (current.categories.get(category) ?? 0) + 1);
    byCountry.set(country, current);
  }
  return Array.from(byCountry.entries())
    .map(([country, value]) => {
      const coord = countryCoordinates[country];
      const top = Array.from(value.categories.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '-';
      const mappable = Boolean(coord);
      return {
        key: country,
        countryCode: country,
        country,
        continent: coord?.continent ?? country,
        attacks: value.attacks,
        top,
        lon: coord?.lon ?? 0,
        lat: coord?.lat ?? 0,
        mappable,
        x: coord ? ((coord.lon + 180) / 360) * 100 : 50,
        y: coord ? ((90 - coord.lat) / 180) * 100 : 50,
        size: Math.max(14, Math.min(36, 10 + Math.sqrt(value.attacks) * 3)),
      };
    })
    .sort((a, b) => b.attacks - a.attacks);
}

function aggregateContinents(regions: ReturnType<typeof aggregateRegions>) {
  const positions: Record<string, { x: number; y: number }> = {
    'North America': { x: 20, y: 32 },
    'South America': { x: 30, y: 68 },
    Europe: { x: 50, y: 30 },
    Asia: { x: 70, y: 36 },
    'Europe/Asia': { x: 64, y: 24 },
    Oceania: { x: 80, y: 72 },
    LOCAL: { x: 50, y: 88 },
    UNLOCATED: { x: 50, y: 88 },
  };
  const byContinent = new Map<string, { attacks: number; categories: Map<string, number> }>();
  for (const region of regions) {
    const current = byContinent.get(region.continent) ?? { attacks: 0, categories: new Map<string, number>() };
    current.attacks += region.attacks;
    current.categories.set(region.top, (current.categories.get(region.top) ?? 0) + region.attacks);
    byContinent.set(region.continent, current);
  }
  return Array.from(byContinent.entries()).map(([name, value]) => ({
    key: name,
    name,
    attacks: value.attacks,
    top: Array.from(value.categories.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '-',
    x: positions[name]?.x ?? 50,
    y: positions[name]?.y ?? 50,
  })).sort((a, b) => b.attacks - a.attacks);
}

function inferCountry(entry: LogEntry) {
  const country = normalizeCountryCode(entry.country);
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

function latLonToVector(lat: number, lon: number, radius: number) {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function createWorldTexture() {
  const canvas = document.createElement('canvas');
  canvas.width = 1024;
  canvas.height = 512;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    return null;
  }
  ctx.fillStyle = '#0f766e';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = 'rgba(215,248,228,0.26)';
  ctx.lineWidth = 1;
  for (let x = 128; x < canvas.width; x += 128) {
    ctx.beginPath();
    ctx.moveTo(x, 24);
    ctx.lineTo(x, canvas.height - 24);
    ctx.stroke();
  }
  for (let y = 96; y < canvas.height; y += 80) {
    ctx.beginPath();
    ctx.moveTo(32, y);
    ctx.lineTo(canvas.width - 32, y);
    ctx.stroke();
  }
  ctx.fillStyle = '#d7f8e4';
  ctx.strokeStyle = '#0f513f';
  ctx.lineWidth = 3;
  ctx.save();
  ctx.scale(canvas.width / 1000, canvas.height / 500);
  for (const path of worldMapPaths) {
    const shape = new Path2D(path);
    ctx.fill(shape);
    ctx.stroke(shape);
  }
  ctx.restore();
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

const worldMapPaths = [
  'M74 150 132 108l82 8 58 38-6 58-70 28-42 62-72-20-32-74Z',
  'M238 270 310 304l44 66-24 92-56 22-40-64 14-70-42-42Z',
  'M430 118 504 94l62 20 12 54-46 30-84-8-54 34-52-18 22-58Z',
  'M560 140 690 96l122 44 86 78-36 82-104 22-70 86-92-14 28-96-74-58-42-88Z',
  'M486 278 542 312l54 86-22 74-68-16-34-86Z',
  'M764 346 840 358l50 58-40 48-82-22-30-54Z',
  'M650 64 740 44l78 16-28 36-104 18Z',
];
