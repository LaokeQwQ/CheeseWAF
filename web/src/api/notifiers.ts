import { apiClient, unwrap } from './client';
import type { NotifierProvider, NotifierTestResult } from '../types/api';

export function fetchNotifierProviders() {
  return unwrap<{ providers: NotifierProvider[]; count: number }>(apiClient.get('/monitor/notifiers'));
}

export function testNotifierProvider(id: string) {
  // Server delivery budget is 15s plus provider retries; don't cancel early.
  return unwrap<NotifierTestResult>(apiClient.post('/monitor/notifiers/test', { id }, { timeout: 30_000 }));
}
