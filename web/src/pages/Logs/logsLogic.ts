import type { LogEntry } from '../../types/api';

export type LogViewMode = 'security' | 'access' | 'all';

export function isSecurityEvent(entry: LogEntry) {
  const action = String(entry.action ?? '').toLowerCase();
  const status = Number(entry.status_code ?? 0);
  return Boolean(
    entry.category
      || entry.detector_id
      || entry.severity
      || action === 'block'
      || action === 'challenge'
      || action === 'log'
      || action === 'monitor'
      || status === 403
      || status === 429,
  );
}

export function isAccessLog(entry: LogEntry) {
  if (isSecurityEvent(entry)) {
    return false;
  }
  const action = String(entry.action ?? '').toLowerCase();
  return action === 'pass' || action === 'cache_hit' || action === 'redirect' || action === '';
}

export function matchViewMode(entry: LogEntry, mode: LogViewMode) {
  if (mode === 'all') {
    return true;
  }
  if (mode === 'access') {
    return isAccessLog(entry);
  }
  return isSecurityEvent(entry);
}

export function filterLogs(
  items: LogEntry[] | undefined,
  opts: { search: string; viewMode: LogViewMode; formatLocation?: (entry: LogEntry) => string },
) {
  const needle = opts.search.trim().toLowerCase();
  const entries = (items ?? []).filter((entry) => matchViewMode(entry, opts.viewMode));
  if (!needle) {
    return entries;
  }
  return entries.filter((entry) => [
    entry.trace_id,
    entry.client_ip,
    entry.uri,
    entry.category,
    entry.action,
    entry.message,
    entry.country,
    opts.formatLocation?.(entry) ?? '',
  ].some((value) => value?.toLowerCase().includes(needle)));
}

export function paginate<T>(items: T[], page: number, pageSize: number) {
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * pageSize;
  return {
    page: safePage,
    totalPages,
    pageItems: items.slice(start, start + pageSize),
    pageStart: items.length === 0 ? 0 : start + 1,
    pageEnd: Math.min(start + pageSize, items.length),
  };
}
