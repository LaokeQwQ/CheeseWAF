import { Table, Tag } from '@arco-design/web-react';
import { useMemo, type CSSProperties } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchLogs } from '../../api/client';
import type { LogEntry } from '../../types/api';

const countryCoordinates: Record<string, { lon: number; lat: number }> = {
  AU: { lon: 133.8, lat: -25.3 },
  BR: { lon: -51.9, lat: -14.2 },
  CA: { lon: -106.3, lat: 56.1 },
  CN: { lon: 104.2, lat: 35.9 },
  DE: { lon: 10.5, lat: 51.1 },
  FR: { lon: 2.2, lat: 46.2 },
  GB: { lon: -3.4, lat: 55.4 },
  HK: { lon: 114.2, lat: 22.3 },
  ID: { lon: 113.9, lat: -0.8 },
  IN: { lon: 78.9, lat: 20.6 },
  JP: { lon: 138.2, lat: 36.2 },
  KR: { lon: 127.8, lat: 35.9 },
  NL: { lon: 5.3, lat: 52.1 },
  RU: { lon: 105.3, lat: 61.5 },
  SG: { lon: 103.8, lat: 1.3 },
  TH: { lon: 100.9, lat: 15.9 },
  US: { lon: -95.7, lat: 37.1 },
  VN: { lon: 108.3, lat: 14.1 },
};

export default function AttackMapPage() {
  const { t } = useTranslation();
  const { data, isLoading } = useQuery({ queryKey: ['attack-map-logs'], queryFn: () => fetchLogs({ limit: 1000 }), refetchInterval: 8_000, retry: false });
  const regions = useMemo(() => aggregateRegions(data?.items ?? []), [data?.items]);

  return (
    <section className="page-surface">
      <header className="page-header">
        <div>
          <h1>{t('attackMap.title')}</h1>
          <p>{t('attackMap.subtitle')}</p>
        </div>
      </header>
      <section className="map-canvas">
        <div className="map-grid-lines" />
        <div className="map-legend">
          <strong>{regions.reduce((sum, region) => sum + region.attacks, 0)}</strong>
          <span>{t('attackMap.attacks')}</span>
        </div>
        {regions.length === 0 && <div className="map-empty">{isLoading ? 'Loading' : `${t('attackMap.attacks')}: 0`}</div>}
        {regions.map((region) => (
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
      </section>
      <section className="table-panel">
        <Table
          rowKey="key"
          pagination={false}
          loading={isLoading}
          data={regions}
          columns={[
            { title: t('attackMap.country'), dataIndex: 'country' },
            { title: t('attackMap.attacks'), dataIndex: 'attacks' },
            { title: t('attackMap.top'), dataIndex: 'top', render: (top: string) => <Tag color="orange">{top}</Tag> },
          ]}
        />
      </section>
    </section>
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
      const coord = countryCoordinates[country] ?? { lon: 0, lat: 0 };
      const top = Array.from(value.categories.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '-';
      return {
        key: country,
        country,
        attacks: value.attacks,
        top,
        x: ((coord.lon + 180) / 360) * 100,
        y: ((90 - coord.lat) / 180) * 100,
        size: Math.max(14, Math.min(36, 10 + Math.sqrt(value.attacks) * 3)),
      };
    })
    .sort((a, b) => b.attacks - a.attacks);
}
