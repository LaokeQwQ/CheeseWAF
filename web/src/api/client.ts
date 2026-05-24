import axios from 'axios';
import type { BlockTemplate, ProtectionConfig, Rule, ScheduledTask, Site, StorageStats } from '../types/api';

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

export function updateACLProtection(acl: ProtectionConfig['acl']) {
  return unwrap<ProtectionConfig['acl']>(apiClient.put('/protection/acl', acl));
}

export function updateRateLimit(ratelimit: ProtectionConfig['ratelimit']) {
  return unwrap<ProtectionConfig['ratelimit']>(apiClient.put('/protection/ratelimit', ratelimit));
}

export function fetchTasks() {
  return unwrap<ScheduledTask[]>(apiClient.get('/scheduler/tasks'));
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
