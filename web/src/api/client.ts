import axios from 'axios';
import type { AIConfig, APISecSummary, AttackAnalysis, AuditEntry, BlockTemplate, EdgeConfig, IPRulesResponse, LogQuery, LogResponse, MonitorSummary, ProtectionConfig, Rule, ScheduledTask, Site, StorageStats, User } from '../types/api';

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cheesewaf-token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem('cheesewaf-token');
      const path = window.location.pathname;
      if (path !== '/login' && path !== '/setup') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(error);
  },
);

type Envelope<T> = {
  data?: T;
  error?: {
    code: string;
    message: string;
  };
};

async function unwrap<T>(promise: Promise<{ data: Envelope<T> }>): Promise<T> {
  const response = await promise;
  if (response.data.error) {
    throw new Error(response.data.error.message);
  }
  return response.data.data as T;
}

export function login(username: string, password: string) {
  return unwrap<{ token: string; user: { username: string; role: string } }>(
    apiClient.post('/auth/login', { username, password }),
  );
}

export function setupAdmin(username: string, password: string, adminListen: string) {
  return unwrap<{ user: { username: string; role: string } }>(
    apiClient.post('/setup', { username, password, admin_listen: adminListen }),
  );
}

export function fetchSites() {
  return unwrap<Site[]>(apiClient.get('/sites'));
}

export function createSite(site: Partial<Site>) {
  return unwrap<Site>(apiClient.post('/sites', site));
}

export function fetchStats() {
  return unwrap<Record<string, unknown>>(apiClient.get('/stats'));
}

export function fetchLogs(params: LogQuery = {}) {
  return unwrap<LogResponse>(apiClient.get('/logs', { params }));
}

export function fetchMonitorSummary() {
  return unwrap<MonitorSummary>(apiClient.get('/monitor'));
}

export function fetchAPISecEndpoints() {
  return unwrap<APISecSummary>(apiClient.get('/apisec/endpoints'));
}

export function validateAPIRequest(payload: Record<string, unknown>) {
  return unwrap<{ findings: Array<Record<string, unknown>> }>(apiClient.post('/apisec/validate', payload));
}

export function fetchAuditEntries() {
  return unwrap<AuditEntry[]>(apiClient.get('/audit'));
}

export function fetchUsers() {
  return unwrap<User[]>(apiClient.get('/users'));
}

export function createUser(user: Partial<User> & { password?: string }) {
  return unwrap<User>(apiClient.post('/users', user));
}

export function updateUser(id: string, user: Partial<User> & { password?: string }) {
  return unwrap<User>(apiClient.put(`/users/${id}`, user));
}

export function fetchRules(siteId?: string) {
  return unwrap<Rule[]>(apiClient.get('/rules', { params: { site_id: siteId } }));
}

export function createRule(rule: Partial<Rule>) {
  return unwrap<Rule>(apiClient.post('/rules', rule));
}

export function updateRule(id: string, rule: Partial<Rule>) {
  return unwrap<Rule>(apiClient.put(`/rules/${id}`, rule));
}

export function deleteRule(id: string) {
  return unwrap<{ deleted: boolean }>(apiClient.delete(`/rules/${id}`));
}

export function fetchProtection() {
  return unwrap<ProtectionConfig>(apiClient.get('/protection'));
}

export function updateIPProtection(ip: ProtectionConfig['ip']) {
  return unwrap<ProtectionConfig['ip']>(apiClient.put('/protection/ip', ip));
}

export function fetchIPRules() {
  return unwrap<IPRulesResponse>(apiClient.get('/ip'));
}

export function updateIPTags(tags: Record<string, string[]>) {
  return unwrap<Record<string, string[]>>(apiClient.put('/ip/tags', tags));
}

export async function exportThreatIntel(format: 'csv' | 'stix') {
  const response = await apiClient.get('/ip/threat-intel/export', {
    params: { format },
    responseType: 'blob',
  });
  return response.data as Blob;
}

export function updateACLProtection(acl: ProtectionConfig['acl']) {
  return unwrap<ProtectionConfig['acl']>(apiClient.put('/protection/acl', acl));
}

export function updateRateLimit(ratelimit: ProtectionConfig['ratelimit']) {
  return unwrap<ProtectionConfig['ratelimit']>(apiClient.put('/protection/ratelimit', ratelimit));
}

export function updateBotProtection(bot: ProtectionConfig['bot']) {
  return unwrap<ProtectionConfig['bot']>(apiClient.put('/protection/bot', bot));
}

export function fetchTasks() {
  return unwrap<ScheduledTask[]>(apiClient.get('/scheduler/tasks'));
}

export function updateTasks(tasks: ScheduledTask[]) {
  return unwrap<ScheduledTask[]>(apiClient.put('/scheduler/tasks', tasks));
}

export function fetchTaskHistory() {
  return unwrap<Array<Record<string, unknown>>>(apiClient.get('/scheduler/history'));
}

export function fetchStorageStats() {
  return unwrap<StorageStats>(apiClient.get('/storage'));
}

export function cleanupStorage() {
  return unwrap<{ cleaned: boolean }>(apiClient.post('/storage/cleanup'));
}

export function exportBackup() {
  return unwrap<Record<string, unknown>>(apiClient.post('/backup/export'));
}

export function restoreBackup(payload: unknown) {
  return unwrap<Record<string, unknown>>(apiClient.post('/backup/restore', payload));
}

export function fetchBlockTemplates() {
  return unwrap<BlockTemplate[]>(apiClient.get('/block-pages/templates'));
}

export function importNginx(contents: string) {
  return unwrap<Site[]>(apiClient.post('/nginx/import', contents, {
    headers: { 'Content-Type': 'text/plain' },
  }));
}

export function fetchEdgePolicy() {
  return unwrap<EdgeConfig>(apiClient.get('/edge'));
}

export function updateEdgePolicy(edge: EdgeConfig) {
  return unwrap<EdgeConfig>(apiClient.put('/edge', edge));
}

export function fetchAIConfig() {
  return unwrap<AIConfig>(apiClient.get('/ai/config'));
}

export function updateAIConfig(config: AIConfig) {
  return unwrap<AIConfig>(apiClient.put('/ai/config', config));
}

export function testAIConnection() {
  return unwrap<{ ok: boolean }>(apiClient.post('/ai/test'));
}

export function analyzeLog(entry: Record<string, unknown>) {
  return unwrap<AttackAnalysis>(apiClient.post('/ai/analyze', entry));
}
