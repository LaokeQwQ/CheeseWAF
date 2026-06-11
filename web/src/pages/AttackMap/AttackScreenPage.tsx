import { Suspense, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Activity, ArrowLeft, Gauge, Globe2, ListFilter, RefreshCcw, Shield } from 'lucide-react';
import { fetchLogs, fetchMonitorSummary } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import type { LogEntry } from '../../types/api';
import { displayCategory, displayCountry } from '../../utils/display';
import GlobeMap from './GlobeMap';
import { aggregateRegions, buildCountryLevelMap, worldFeatures, type AttackRegion, type ProtectedTarget, type ThreatLevel } from './AttackMapPage';

const screenRefreshMs = 3_000;

export default function AttackScreenPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [railOpen, setRailOpen] = useState(false);
  const [timelinePercent, setTimelinePercent] = useState(100);
  const { data: logs, isFetching, refetch } = useQuery({
    queryKey: ['attack-screen-logs'],
    queryFn: () => fetchLogs({ limit: 1000 }),
    refetchInterval: screenRefreshMs,
    retry: false,
  });
  const { data: monitor } = useQuery({
    queryKey: ['attack-screen-monitor'],
    queryFn: fetchMonitorSummary,
    refetchInterval: screenRefreshMs,
    retry: false,
  });
  const entries = logs?.items ?? [];
  const attackEntries = useMemo(() => entries.filter(isAttackEntry), [entries]);
  const visibleEntries = useMemo(() => filterEntriesByTimeline(entries, timelinePercent), [entries, timelinePercent]);
  const visibleAttackEntries = useMemo(() => visibleEntries.filter(isAttackEntry), [visibleEntries]);
  const regions = useMemo(() => aggregateRegions(visibleEntries), [visibleEntries]);
  const mappedRegions = useMemo(() => regions.filter((region) => region.mappable), [regions]);
  const countryLevels = useMemo(() => buildCountryLevelMap(mappedRegions), [mappedRegions]);
  const attackTypes = useMemo(() => buildAttackTypes(visibleAttackEntries, t), [visibleAttackEntries, t]);
  const sourceCountries = useMemo(() => buildSourceCountries(mappedRegions), [mappedRegions]);
  const totalAttacks = regions.reduce((sum, region) => sum + region.attacks, 0);
  const blocked = visibleAttackEntries.filter((entry) => entry.action === 'block' || entry.status_code === 403).length;
  const critical = regions.reduce((sum, region) => sum + (region.level === 'critical' ? region.attacks : 0), 0);
  const perMinute = visibleAttackEntries.filter((entry) => Date.parse(entry.timestamp) >= Date.now() - 60_000).length;
  const level = overallThreatLevel(regions);
  const timeRange = formatTimeRange(entries);
  const protectedTarget = useMemo<ProtectedTarget>(() => {
    const host = window.location.hostname;
    return { lat: host.startsWith('38.') ? 37.1 : 35.9, lon: host.startsWith('38.') ? -95.7 : 104.2, label: t('attackMap.protectedTarget'), source: 'admin-host' };
  }, [t]);

  return (
    <main className="attack-screen">
      <aside className={railOpen ? 'attack-screen-rail attack-screen-rail-open' : 'attack-screen-rail'}>
        <div className="attack-screen-brand">
          <span><BrandLogo alt="" /></span>
          <strong>CheeseWAF</strong>
        </div>
        <nav>
          <button className="attack-screen-nav-active" type="button" onClick={() => setRailOpen((value) => !value)}>
            <Globe2 size={16} />
            <span>{t('attackMap.globalThreatMap')}</span>
          </button>
          <button type="button" onClick={() => navigate('/')}>
            <Gauge size={16} />
            <span>{t('nav.dashboard')}</span>
          </button>
          <button type="button" onClick={() => navigate('/logs')}>
            <ListFilter size={16} />
            <span>{t('nav.logs')}</span>
          </button>
        </nav>
        <button className="attack-screen-back" type="button" onClick={() => navigate('/attack-map')}>
          <ArrowLeft size={16} />
          <span>{t('attackMap.backToMap')}</span>
        </button>
      </aside>

      <section className="attack-screen-main">
        <header className="attack-screen-topbar">
          <span className="attack-screen-live"><i /> {t('attackMap.live')}</span>
          <strong>{new Date().toLocaleTimeString()}</strong>
          <span>{monitor?.alerts?.length ? monitor.alerts[0]?.severity ?? t('common.blocked') : t('common.healthy')}</span>
          <button type="button" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCcw size={15} />
            <span>{t('attackMap.refresh')}</span>
          </button>
        </header>

        <div className="attack-screen-grid">
          <div className="attack-screen-left attack-screen-overlay attack-screen-overlay-left">
            <section className="attack-screen-panel">
              <h2>{t('dashboard.threatMix')}</h2>
              <div className="attack-screen-stats">
                <Metric label={t('attackMap.attacks')} value={totalAttacks} />
                <Metric label={t('attackMap.perMinute')} value={perMinute} />
                <Metric label={t('attackMap.blocked')} value={blocked} />
                <Metric label={t('attackMap.critical')} value={critical} />
              </div>
            </section>
            <section className="attack-screen-panel">
              <h2>{t('attackMap.attackTypes')}</h2>
              <BarList items={attackTypes} />
            </section>
          </div>

          <section className="attack-screen-globe">
            <Suspense fallback={<div className="page-spinner" aria-label={t('attackMap.loading')} aria-busy="true" />}>
              <GlobeMap
                regions={mappedRegions}
                zoom={0.86}
                countryLevels={countryLevels}
                worldFeatures={worldFeatures}
                target={protectedTarget}
                fallback={<div className="attack-screen-globe-empty">{t('attackMap.attacks')}: 0</div>}
              />
            </Suspense>
          </section>

          <div className="attack-screen-right attack-screen-overlay attack-screen-overlay-right">
            <section className="attack-screen-panel">
              <h2>{t('attackMap.sourceCountries')}</h2>
              <CountryList regions={sourceCountries} t={t} />
            </section>
            <section className="attack-screen-panel attack-screen-level">
              <h2>{t('attackMap.threatLevel')}</h2>
              <strong className={`attack-screen-level-${level}`}>{t(`attackMap.risk.${level}`)}</strong>
              <span>{t('attackMap.currentLevel')}</span>
              <div className="attack-screen-level-meter"><i style={{ width: `${levelPercent(level)}%` }} /></div>
            </section>
            <section className="attack-screen-panel">
              <h2>{t('attackMap.timeline')}</h2>
              <div className="attack-screen-timeline">
                <input type="range" min={0} max={100} value={timelinePercent} onChange={(event) => setTimelinePercent(Number(event.currentTarget.value))} />
                <div>
                  <span>{timeRange.start}</span>
                  <strong>{timelinePercent}%</strong>
                  <span>{timeRange.end}</span>
                </div>
              </div>
            </section>
          </div>
        </div>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function BarList({ items }: { items: Array<{ label: string; value: number; percent: number }> }) {
  if (items.length === 0) {
    return <div className="attack-screen-empty">0</div>;
  }
  return (
    <div className="attack-screen-bars">
      {items.map((item) => (
        <div key={item.label}>
          <span>{item.label}</span>
          <i><b style={{ width: `${item.percent}%` }} /></i>
          <em>{item.value}</em>
        </div>
      ))}
    </div>
  );
}

function CountryList({ regions, t }: { regions: AttackRegion[]; t: (key: string, options?: Record<string, unknown>) => string }) {
  if (regions.length === 0) {
    return <div className="attack-screen-empty">0</div>;
  }
  const max = Math.max(...regions.map((region) => region.attacks), 1);
  return (
    <div className="attack-screen-countries">
      {regions.map((region, index) => (
        <div key={region.key}>
          <span>{index + 1}</span>
          <Shield size={13} />
          <strong>{displayCountry(region.countryCode, t)}</strong>
          <i><b style={{ width: `${Math.max(6, (region.attacks / max) * 100)}%` }} /></i>
          <em>{region.attacks}</em>
        </div>
      ))}
    </div>
  );
}

function buildSourceCountries(regions: AttackRegion[]) {
  const grouped = new Map<string, AttackRegion>();
  for (const region of regions) {
    const current = grouped.get(region.countryCode);
    if (!current) {
      grouped.set(region.countryCode, { ...region, key: `country-${region.countryCode}` });
      continue;
    }
    grouped.set(region.countryCode, {
      ...current,
      attacks: current.attacks + region.attacks,
      severityRank: Math.max(current.severityRank, region.severityRank),
      level: threatMax(current.level, region.level),
    });
  }
  return Array.from(grouped.values()).sort((a, b) => b.attacks - a.attacks).slice(0, 7);
}

function threatMax(a: ThreatLevel, b: ThreatLevel): ThreatLevel {
  const order: ThreatLevel[] = ['low', 'medium', 'high', 'critical'];
  return order[Math.max(order.indexOf(a), order.indexOf(b))] ?? a;
}

function buildAttackTypes(entries: LogEntry[], t: (key: string, options?: Record<string, unknown>) => string) {
  const counts = new Map<string, number>();
  for (const entry of entries) {
    const key = entry.category || entry.action || 'unknown';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const max = Math.max(...counts.values(), 1);
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([key, value]) => ({
      label: displayCategory(key, t),
      value,
      percent: Math.max(5, (value / max) * 100),
    }));
}

function filterEntriesByTimeline(entries: LogEntry[], percent: number) {
  if (percent >= 100 || entries.length === 0) {
    return entries;
  }
  const times = entries.map((entry) => Date.parse(entry.timestamp)).filter((time) => Number.isFinite(time));
  if (times.length === 0) {
    return entries;
  }
  const min = Math.min(...times);
  const max = Math.max(...times);
  const cutoff = min + ((max - min) * Math.max(0, Math.min(100, percent))) / 100;
  return entries.filter((entry) => {
    const time = Date.parse(entry.timestamp);
    return !Number.isFinite(time) || time <= cutoff;
  });
}

function isAttackEntry(entry: LogEntry) {
  const action = String(entry.action ?? '').toLowerCase();
  return Boolean(entry.category || action === 'block' || action === 'challenge' || entry.status_code === 403 || entry.status_code === 429);
}

function overallThreatLevel(regions: AttackRegion[]): ThreatLevel {
  if (regions.some((region) => region.level === 'critical')) {
    return 'critical';
  }
  if (regions.some((region) => region.level === 'high')) {
    return 'high';
  }
  if (regions.some((region) => region.level === 'medium')) {
    return 'medium';
  }
  return 'low';
}

function levelPercent(level: ThreatLevel) {
  switch (level) {
    case 'critical':
      return 100;
    case 'high':
      return 74;
    case 'medium':
      return 46;
    default:
      return 18;
  }
}

function formatTimeRange(entries: LogEntry[]) {
  const times = entries.map((entry) => Date.parse(entry.timestamp)).filter((time) => Number.isFinite(time));
  if (times.length === 0) {
    return { start: '-', end: '-' };
  }
  const options: Intl.DateTimeFormatOptions = { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' };
  return {
    start: new Date(Math.min(...times)).toLocaleString(undefined, options),
    end: new Date(Math.max(...times)).toLocaleString(undefined, options),
  };
}
