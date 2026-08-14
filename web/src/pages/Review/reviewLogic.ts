import type { ReviewItem } from '../../types/api';

export function parseReviewVerdict(raw?: string): { risk?: string; summary?: string; aiUsed?: boolean } {
  const text = String(raw ?? '').trim();
  if (!text) {
    return {};
  }
  try {
    const parsed = JSON.parse(text) as { risk?: string; summary?: string; ai_used?: boolean };
    return { risk: parsed.risk, summary: parsed.summary, aiUsed: parsed.ai_used };
  } catch {
    return { summary: text };
  }
}

export function shapeLabelKey(shape?: string) {
  switch (String(shape ?? '').toLowerCase()) {
    case 'isolated':
      return 'review.isolated';
    case 'embedded':
      return 'review.embedded';
    default:
      return 'review.unknownShape';
  }
}

export function statusLabelKey(status?: string) {
  switch (String(status ?? '').toLowerCase()) {
    case 'blocked':
      return 'review.blocked';
    case 'allowed':
      return 'review.allowed';
    default:
      return 'review.pending';
  }
}

export function formatReviewTime(value?: string, locale?: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(locale || undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

export function reviewSearchMatch(item: ReviewItem, search: string) {
  const needle = search.trim().toLowerCase();
  if (!needle) {
    return true;
  }
  return [
    item.trace_id,
    item.client_ip,
    item.uri,
    item.payload,
    item.category,
    item.site_id,
    item.param_name,
    item.fingerprint,
  ].some((value) => String(value ?? '').toLowerCase().includes(needle));
}
