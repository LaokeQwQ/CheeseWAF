import { apiClient, fetchLogs, unwrapAPIResponse } from './client';
import type { BotChallengeEvent, BotChallengeMetrics, BotChallengeOverview, BotChallengeOutcome, BotChallengeTrendPoint, BotChallengeTypeEffect, LogEntry } from '../types/api';

export type BotChallengeRange = '1h' | '6h' | '24h' | '7d' | '30d';

export function fetchBotChallengeMetrics(range: BotChallengeRange = '24h') {
  return unwrapAPIResponse<BotChallengeMetrics>(apiClient.get('/protection/bot/metrics', { params: { range } }));
}

export async function fetchBotChallengeOverview(hours = 24): Promise<BotChallengeOverview> {
  const periodEnd = new Date();
  const periodStart = new Date(periodEnd.getTime() - hours * 3_600_000);
  const response = await fetchLogs({ start: periodStart.toISOString(), end: periodEnd.toISOString(), limit: 1000 });
  return buildBotChallengeOverview(response.items, periodStart, periodEnd);
}

export function buildBotChallengeOverview(logs: LogEntry[], periodStart: Date, periodEnd: Date): BotChallengeOverview {
  const relevant = logs.filter(isBotChallengeLog);
  const events = relevant.map(toEvent).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const challenged = new Set(events.map((event) => event.clientIp).filter(Boolean));
  const blocked = new Set(events.filter((event) => event.outcome === 'blocked').map((event) => event.clientIp).filter(Boolean));
  const passed = events.filter((event) => event.outcome === 'passed').length;
  const decided = events.filter((event) => event.outcome === 'passed' || event.outcome === 'failed').length;
  return {
    periodStart: periodStart.toISOString(), periodEnd: periodEnd.toISOString(),
    challengedClients: challenged.size, blockedClients: blocked.size,
    captchaBlocked: events.filter((event) => event.outcome === 'blocked' || event.outcome === 'failed').length,
    passRate: decided > 0 ? passed / decided : undefined,
    totalChallenges: events.length,
    trend: buildTrend(events, periodStart, periodEnd), typeEffects: buildTypeEffects(events), events: events.slice(0, 100),
  };
}

function isBotChallengeLog(log: LogEntry) {
  const category = log.category.toLowerCase();
  const detector = log.detector_id.toLowerCase();
  return log.action === 'challenge' || category.includes('bot') || category.includes('captcha') || detector.includes('bot') || detector.includes('captcha') || typeof log.metadata?.captcha_type === 'string';
}

function toEvent(log: LogEntry): BotChallengeEvent {
  const rawOutcome = String(log.metadata?.captcha_outcome ?? '').toLowerCase();
  let outcome: BotChallengeOutcome = 'issued';
  if (rawOutcome === 'passed' || rawOutcome === 'success') outcome = 'passed';
  else if (rawOutcome === 'failed' || rawOutcome === 'failure') outcome = 'failed';
  else if (log.action === 'block') outcome = 'blocked';
  return { id: log.id, traceId: log.trace_id, timestamp: log.timestamp, clientIp: log.client_ip, siteId: log.site_id, country: log.country, challengeType: stringMetadata(log, 'captcha_type'), outcome, reason: log.message || log.category };
}

function stringMetadata(log: LogEntry, key: string) { const value = log.metadata?.[key]; return typeof value === 'string' && value ? value : undefined; }

function buildTypeEffects(events: BotChallengeEvent[]): BotChallengeTypeEffect[] {
  const map = new Map<string, BotChallengeTypeEffect>();
  for (const event of events) { const type = event.challengeType ?? 'unknown'; const item = map.get(type) ?? { type, issued: 0 }; item.issued += 1; if (event.outcome === 'passed') item.passed = (item.passed ?? 0) + 1; if (event.outcome === 'failed' || event.outcome === 'blocked') item.failed = (item.failed ?? 0) + 1; map.set(type, item); }
  return [...map.values()].map((item) => { const decided = (item.passed ?? 0) + (item.failed ?? 0); return { ...item, passRate: decided ? (item.passed ?? 0) / decided : undefined }; }).sort((a, b) => b.issued - a.issued);
}

function buildTrend(events: BotChallengeEvent[], start: Date, end: Date): BotChallengeTrendPoint[] {
  const bucketCount = 12; const bucketMs = Math.max(1, (end.getTime() - start.getTime()) / bucketCount);
  const points = Array.from({ length: bucketCount }, (_, index) => ({ timestamp: new Date(start.getTime() + index * bucketMs).toISOString(), challenged: 0, blocked: 0, passed: 0, failed: 0 }));
  for (const event of events) { const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((new Date(event.timestamp).getTime() - start.getTime()) / bucketMs))); const point = points[index]; if (!point) continue; point.challenged += 1; if (event.outcome === 'blocked') point.blocked += 1; if (event.outcome === 'failed') point.failed += 1; if (event.outcome === 'passed') point.passed += 1; }
  return points;
}
