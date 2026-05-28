import { Button, Radio, Table, Tag } from '@arco-design/web-react';
import { useMemo, useState, type CSSProperties, type PointerEvent, type WheelEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Minus, Plus } from 'lucide-react';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';

type MapMode = '2d' | '3d' | 'continent';

const countryCoordinates: Record<string, { lon: number; lat: number; continent: string }> = {
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
};

export default function AttackMapPage() {
  const { t } = useTranslation();
  const [mode, setMode] = useState<MapMode>('2d');
  const [zoom, setZoom] = useState(1);
  const [rotation, setRotation] = useState({ x: -10, y: -18 });
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 5_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);
  const continents = useMemo(() => aggregateContinents(regions), [regions]);
  const total = regions.reduce((sum, region) => sum + region.attacks, 0);

  function updateZoom(next: number) {
    setZoom(Math.max(0.75, Math.min(2.4, Number(next.toFixed(2)))));
  }

  function handleDrag(event: PointerEvent<HTMLElement>) {
    if (!drag || mode !== '3d') {
      return;
    }
    setRotation((current) => ({
      x: Math.max(-55, Math.min(55, current.x - (event.clientY - drag.y) * 0.25)),
      y: current.y + (event.clientX - drag.x) * 0.35,
    }));
    setDrag({ x: event.clientX, y: event.clientY });
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
        onPointerDown={(event) => setDrag({ x: event.clientX, y: event.clientY })}
        onPointerMove={handleDrag}
        onPointerUp={() => setDrag(null)}
        onPointerLeave={() => setDrag(null)}
      >
        <div className="map-legend">
          <strong>{total}</strong>
          <span>{t('attackMap.attacks')}</span>
        </div>
        {mode === '3d' ? (
          <div className="globe-stage" style={{ '--map-zoom': zoom, '--rotate-x': `${rotation.x}deg`, '--rotate-y': `${rotation.y}deg` } as CSSProperties}>
            <div className="globe-sphere">
              <WorldMapSVG />
              {regions.map((region) => (
                <span
                  key={region.key}
                  className="map-marker globe-marker"
                  style={{
                    left: `${region.x}%`,
                    top: `${region.y}%`,
                    '--marker-size': `${region.size}px`,
                  } as CSSProperties}
                  title={`${region.country} ${region.attacks}`}
                >
                  <i />
                  <strong>{region.country}</strong>
                </span>
              ))}
            </div>
          </div>
        ) : (
          <div className="flat-map-stage" style={{ '--map-zoom': zoom } as CSSProperties}>
            <WorldMapSVG />
            {mode === '2d' && regions.map((region) => (
              <span
                key={region.key}
                className="map-marker"
                style={{ left: `${region.x}%`, top: `${region.y}%`, '--marker-size': `${region.size}px` } as CSSProperties}
                title={`${region.country} ${region.attacks}`}
              >
                <i />
                <strong>{region.country}</strong>
              </span>
            ))}
            {mode === 'continent' && continents.map((continent) => (
              <span
                key={continent.name}
                className="continent-badge"
                style={{ left: `${continent.x}%`, top: `${continent.y}%` }}
              >
                <strong>{continent.name}</strong>
                <em>{continent.attacks}</em>
                <small>{continent.top}</small>
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
              { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{top}</Tag> },
            ]}
          />
        ) : (
          <Table
            rowKey="key"
            pagination={false}
            loading={isLoading}
            data={regions}
            columns={[
              { title: t('attackMap.country'), dataIndex: 'country' },
              { title: t('attackMap.continent'), dataIndex: 'continent' },
              { title: t('attackMap.attacks'), dataIndex: 'attacks' },
              { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{top}</Tag> },
            ]}
          />
        )}
      </section>
    </section>
  );
}

function WorldMapSVG() {
  return (
    <svg className="world-map-svg" viewBox="0 0 1000 500" aria-hidden="true">
      <path d="M74 150 132 108l82 8 58 38-6 58-70 28-42 62-72-20-32-74Z" />
      <path d="M238 270 310 304l44 66-24 92-56 22-40-64 14-70-42-42Z" />
      <path d="M430 118 504 94l62 20 12 54-46 30-84-8-54 34-52-18 22-58Z" />
      <path d="M560 140 690 96l122 44 86 78-36 82-104 22-70 86-92-14 28-96-74-58-42-88Z" />
      <path d="M486 278 542 312l54 86-22 74-68-16-34-86Z" />
      <path d="M764 346 840 358l50 58-40 48-82-22-30-54Z" />
      <path d="M650 64 740 44l78 16-28 36-104 18Z" />
    </svg>
  );
}

function aggregateRegions(entries: LogEntry[]) {
  const byCountry = new Map<string, { attacks: number; categories: Map<string, number> }>();
  for (const entry of entries) {
    if (!entry.category && entry.action !== 'block' && entry.action !== 'challenge') {
      continue;
    }
    const country = (entry.country || 'UNKNOWN').toUpperCase();
    const current = byCountry.get(country) ?? { attacks: 0, categories: new Map<string, number>() };
    current.attacks += 1;
    const category = (entry.category || entry.action || 'unknown').toUpperCase();
    current.categories.set(category, (current.categories.get(category) ?? 0) + 1);
    byCountry.set(country, current);
  }
  return Array.from(byCountry.entries())
    .map(([country, value]) => {
      const coord = countryCoordinates[country] ?? { lon: 0, lat: 0, continent: 'Unknown' };
      const top = Array.from(value.categories.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '-';
      return {
        key: country,
        country,
        continent: coord.continent,
        attacks: value.attacks,
        top,
        x: ((coord.lon + 180) / 360) * 100,
        y: ((90 - coord.lat) / 180) * 100,
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
    Unknown: { x: 50, y: 50 },
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
