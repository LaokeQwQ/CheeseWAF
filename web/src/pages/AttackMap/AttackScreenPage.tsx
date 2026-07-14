import { lazy, Suspense, useEffect, useMemo, useRef, useState, type ChangeEvent, type PointerEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Activity, ArrowLeft, Gauge, Globe2, ListFilter, RefreshCcw, Shield } from 'lucide-react';
import { fetchLogs, fetchMonitorSummary } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import { useAppStore } from '../../stores';
import type { LogEntry } from '../../types/api';
import { displayCategory, displayCountry, displaySeverity } from '../../utils/display';
import { aggregateRegions, buildCountryLevelMap, worldFeatures, type AttackRegion, type ProtectedTarget, type ThreatLevel } from './attackMapData';
import '../../styles/attack-map.css';
import '../../styles/arco-components';

const GlobeMap = lazy(() => import('./GlobeMap'));

const screenRefreshMs = 3_000;
const maxGlobeRegions = 80;

export default function AttackScreenPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const appTheme = useAppStore((state) => state.theme);
  const visualTheme = appTheme === 'dark' || appTheme === 'blackGold' ? 'dark' : 'light';
  const [railOpen, setRailOpen] = useState(false);
  const [timelinePercent, setTimelinePercent] = useState(100);
  const [timelineInteracting, setTimelineInteracting] = useState(false);
  const timelineResumeTimer = useRef<number | null>(null);
  const timelinePointerActive = useRef(false);
  const timelinePaused = timelineInteracting || timelinePercent < 100;
  const refetchInterval = timelinePaused ? false : screenRefreshMs;
  const { data: logs, isFetching, refetch } = useQuery({
    queryKey: ['attack-screen-logs'],
    queryFn: () => fetchLogs({ limit: 1000 }),
    refetchInterval,
    enabled: !timelinePaused,
    retry: false,
    placeholderData: (previous) => previous,
  });
  const { data: monitor } = useQuery({
    queryKey: ['attack-screen-monitor'],
    queryFn: fetchMonitorSummary,
    refetchInterval,
    enabled: !timelinePaused,
    retry: false,
    placeholderData: (previous) => previous,
  });
  const entries = logs?.items ?? [];
  const initialLoading = !logs && isFetching;
  const attackEntries = useMemo(() => entries.filter(isAttackEntry), [entries]);
  const visibleAttackEntries = useMemo(() => filterEntriesByTimeline(attackEntries, timelinePercent), [attackEntries, timelinePercent]);
  const regions = useMemo(() => aggregateRegions(visibleAttackEntries), [visibleAttackEntries]);
  const mappedRegions = useMemo(() => regions.filter((region) => region.mappable), [regions]);
  const globeRegions = useMemo(() => mappedRegions.slice(0, maxGlobeRegions), [mappedRegions]);
  const countryLevels = useMemo(() => buildCountryLevelMap(mappedRegions), [mappedRegions]);
  const attackTypes = useMemo(() => buildAttackTypes(visibleAttackEntries, t), [visibleAttackEntries, t]);
  const sourceCountries = useMemo(() => buildSourceCountries(mappedRegions), [mappedRegions]);
  const totalAttacks = regions.reduce((sum, region) => sum + region.attacks, 0);
  const blocked = visibleAttackEntries.filter((entry) => entry.action === 'block' || entry.status_code === 403).length;
  const critical = regions.reduce((sum, region) => sum + (region.level === 'critical' ? region.attacks : 0), 0);
  const perMinute = visibleAttackEntries.filter((entry) => Date.parse(entry.timestamp) >= Date.now() - 60_000).length;
  const level = overallThreatLevel(regions);
  const timeRange = formatTimeRange(attackEntries);
  const protectedTarget = useMemo<ProtectedTarget>(() => {
    const host = window.location.hostname;
    return { lat: host.startsWith('38.') ? 37.1 : 35.9, lon: host.startsWith('38.') ? -95.7 : 104.2, label: t('attackMap.protectedTarget'), source: 'admin-host' };
  }, [t]);
  const beginTimelineInteraction = () => {
    if (timelineResumeTimer.current !== null) {
      window.clearTimeout(timelineResumeTimer.current);
      timelineResumeTimer.current = null;
    }
    setTimelineInteracting(true);
  };
  const endTimelineInteraction = () => {
    if (timelineResumeTimer.current !== null) {
      window.clearTimeout(timelineResumeTimer.current);
    }
    timelineResumeTimer.current = window.setTimeout(() => {
      setTimelineInteracting(false);
      timelineResumeTimer.current = null;
    }, 1200);
  };
  const handleTimelinePointerDown = (event: PointerEvent<HTMLInputElement>) => {
    timelinePointerActive.current = true;
    event.currentTarget.setPointerCapture?.(event.pointerId);
    beginTimelineInteraction();
  };
  const handleTimelinePointerEnd = (event: PointerEvent<HTMLInputElement>) => {
    timelinePointerActive.current = false;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
    endTimelineInteraction();
  };
  const handleTimelineChange = (event: ChangeEvent<HTMLInputElement>) => {
    setTimelinePercent(Number(event.currentTarget.value));
    if (!timelinePointerActive.current) {
      beginTimelineInteraction();
      endTimelineInteraction();
    }
  };

  useEffect(() => () => {
    if (timelineResumeTimer.current !== null) {
      window.clearTimeout(timelineResumeTimer.current);
    }
  }, []);

  return (
    <main className={['attack-screen', `attack-screen-${visualTheme}`, railOpen ? 'attack-screen-rail-expanded' : ''].filter(Boolean).join(' ')}>
      <aside className={railOpen ? 'attack-screen-rail attack-screen-rail-open' : 'attack-screen-rail'}>
        <div className="attack-screen-brand">
          <span><BrandLogo alt="" /></span>
          <strong>CheeseWAF</strong>
        </div>
        <nav>
          <button
            className="attack-screen-nav-active"
            type="button"
            aria-current="page"
            aria-expanded={railOpen}
            onClick={() => setRailOpen((value) => !value)}
          >
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
          <span className="attack-screen-live"><i /> {timelinePaused ? t('attackMap.historyView') : t('attackMap.live')}</span>
          <LiveClock />
          <span>{monitor?.alerts?.length ? displaySeverity(monitor.alerts[0]?.severity, t) : t('common.healthy')}</span>
          <button type="button" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCcw size={15} />
            <span>{t('attackMap.refresh')}</span>
          </button>
        </header>

        <div className="attack-screen-grid">
          <div className="attack-screen-left attack-screen-overlay attack-screen-overlay-left">
            <section className="attack-screen-panel">
              <h2>{t('dashboard.threatMix')}</h2>
              {initialLoading ? <PanelLoading label={t('common.loading')} /> : (
                <div className="attack-screen-stats">
                  <Metric label={t('attackMap.attacks')} value={totalAttacks} />
                  <Metric label={t('attackMap.perMinute')} value={perMinute} />
                  <Metric label={t('attackMap.blocked')} value={blocked} />
                  <Metric label={t('attackMap.critical')} value={critical} />
                </div>
              )}
            </section>
            <section className="attack-screen-panel">
              <h2>{t('attackMap.attackTypes')}</h2>
              {initialLoading ? <PanelLoading label={t('common.loading')} /> : <BarList items={attackTypes} emptyLabel={t('common.noData')} />}
            </section>
          </div>

          <section className="attack-screen-globe">
            <Suspense fallback={<div className="page-spinner" aria-label={t('attackMap.loading')} aria-busy="true" />}>
              <GlobeMap
                regions={globeRegions}
                zoom={0.68}
                countryLevels={countryLevels}
                worldFeatures={worldFeatures}
                target={protectedTarget}
                visualTheme={visualTheme}
                fallback={<div className="attack-screen-globe-empty">{t('attackMap.attacks')}: 0</div>}
              />
            </Suspense>
          </section>

          <div className="attack-screen-right attack-screen-overlay attack-screen-overlay-right">
            <section className="attack-screen-panel">
              <h2>{t('attackMap.sourceCountries')}</h2>
              {initialLoading ? <PanelLoading label={t('common.loading')} /> : <CountryList regions={sourceCountries} t={t} emptyLabel={t('common.noData')} />}
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
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={timelinePercent}
                  aria-label={t('attackMap.timelineRangeAria')}
                  onPointerDown={handleTimelinePointerDown}
                  onPointerUp={handleTimelinePointerEnd}
                  onPointerCancel={handleTimelinePointerEnd}
                  onBlur={endTimelineInteraction}
                  onChange={handleTimelineChange}
                />
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

function LiveClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return <strong>{now.toLocaleTimeString()}</strong>;
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function PanelLoading({ label }: { label: string }) {
  return (
    <div className="attack-screen-loading" aria-busy="true">
      <i />
      <span>{label}</span>
    </div>
  );
}

function BarList({ items, emptyLabel }: { items: Array<{ label: string; value: number; percent: number }>; emptyLabel: string }) {
  if (items.length === 0) {
    return <div className="attack-screen-empty">{emptyLabel}</div>;
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

function CountryList({ regions, t, emptyLabel }: { regions: AttackRegion[]; t: (key: string, options?: Record<string, unknown>) => string; emptyLabel: string }) {
  if (regions.length === 0) {
    return <div className="attack-screen-empty">{emptyLabel}</div>;
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
