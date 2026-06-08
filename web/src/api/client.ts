import axios from 'axios';
import type { AIConfig, AIEventsAnalysisResponse, AIAssistantReply, APISecSummary, AttackAnalysis, AuditEntry, BlockTemplate, EdgeConfig, HealthStatus, IPReputationEntry, IPRulesResponse, LogQuery, LogResponse, MonitorSummary, ProtectionConfig, Rule, ScheduledTask, Site, StorageStats, SystemConfig, ThreatIntelIndicator, ThreatIntelProvider, TOTPSetup, User } from '../types/api';

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

const tokenStorageKey = 'cheesewaf-token';
const tokenRefreshWindowSeconds = 10 * 60;
let refreshPromise: Promise<string> | null = null;

type AuthResponse = { token: string; user: { username: string; role: string } };
type TokenClaims = { exp?: number };

apiClient.interceptors.request.use(async (config) => {
  const token = localStorage.getItem(tokenStorageKey);
  if (token) {
    const activeToken = await refreshTokenIfNeeded(token, String(config.url ?? ''));
    config.headers.Authorization = `Bearer ${activeToken}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      localStorage.removeItem(tokenStorageKey);
      const path = window.location.pathname;
      if (path !== '/login' && path !== '/setup') {
        window.location.assign('/login');
      }
    }
    return Promise.reject(error);
  },
);

async function refreshTokenIfNeeded(token: string, requestURL: string) {
  if (requestURL.includes('/auth/login') || requestURL.includes('/auth/refresh') || requestURL.includes('/auth/logout') || requestURL.includes('/setup')) {
    return token;
  }
  const claims = parseTokenClaims(token);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (!claims?.exp || claims.exp <= nowSeconds || claims.exp - nowSeconds > tokenRefreshWindowSeconds) {
    return token;
  }
  if (!refreshPromise) {
    refreshPromise = axios
      .post<Envelope<AuthResponse>>(
        '/api/auth/refresh',
        {},
        {
          timeout: 10_000,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
        },
      )
      .then((response) => {
        if (response.data.error || !response.data.data?.token) {
          throw new APIRequestError(response.data.error?.message ?? 'Unable to refresh token', response.data.error?.code);
        }
        localStorage.setItem(tokenStorageKey, response.data.data.token);
        return response.data.data.token;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }
  try {
    return await refreshPromise;
  } catch {
    return token;
  }
}

function parseTokenClaims(token: string): TokenClaims | null {
  const payload = token.split('.')[1];
  if (!payload) {
    return null;
  }
  try {
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return JSON.parse(atob(padded)) as TokenClaims;
  } catch {
    return null;
  }
}

type Envelope<T> = {
  data?: T;
  error?: {
    code: string;
    message: string;
  };
};

export class APIRequestError extends Error {
  code?: string;
  status?: number;

  constructor(message: string, code?: string, status?: number) {
    super(message);
    this.name = 'APIRequestError';
    this.code = code;
    this.status = status;
  }
}

async function unwrap<T>(promise: Promise<{ data: Envelope<T> }>): Promise<T> {
  try {
    const response = await promise;
    if (response.data.error) {
      throw new APIRequestError(response.data.error.message, response.data.error.code);
    }
    return response.data.data as T;
  } catch (error) {
    if (axios.isAxiosError<Envelope<unknown>>(error)) {
      const apiError = error.response?.data?.error;
      if (apiError) {
        throw new APIRequestError(apiError.message, apiError.code, error.response?.status);
      }
      if (error.response?.status) {
        throw new APIRequestError(error.message, undefined, error.response.status);
      }
    }
    throw error;
  }
}

export function login(username: string, password: string, totpCode?: string) {
  return unwrap<AuthResponse>(
    apiClient.post('/auth/login', { username, password, totp_code: totpCode }),
  );
}

export function logout() {
  return unwrap<{ revoked: boolean }>(apiClient.post('/auth/logout', {}));
}

export function setupAdmin(username: string, password: string, adminListen: string, adminStrategy = 'local') {
  return unwrap<{ user: { username: string; role: string } }>(
    apiClient.post('/setup', {
      username,
      password,
      admin_listen: adminListen,
      admin_strategy: adminStrategy,
      admin_public: adminStrategy === 'public_tls',
    }),
  );
}

export function fetchSites() {
  return unwrap<Site[]>(apiClient.get('/sites'));
}

export function fetchSite(id: string) {
  return unwrap<Site>(apiClient.get(`/sites/${id}`));
}

export function createSite(site: Partial<Site>) {
  return unwrap<Site>(apiClient.post('/sites', site));
}

export function updateSite(id: string, site: Partial<Site>) {
  return unwrap<Site>(apiClient.put(`/sites/${id}`, site));
}

export function deleteSite(id: string) {
  return unwrap<{ deleted: boolean }>(apiClient.delete(`/sites/${id}`));
}

export function fetchStats() {
  return unwrap<Record<string, unknown>>(apiClient.get('/stats'));
}

export async function fetchHealth() {
  const response = await axios.get<{ data?: HealthStatus }>('/health', { timeout: 5000 });
  return response.data.data as HealthStatus;
}

export function fetchLogs(params: LogQuery = {}) {
  return unwrap<LogResponse>(apiClient.get('/logs', { params }));
}

export async function fetchLogEvent(reference: string) {
  const byTrace = await fetchLogs({ limit: 10, trace_id: reference });
  const direct = byTrace.items.find((entry) => entry.trace_id === reference || entry.id === reference) ?? byTrace.items[0];
  if (direct) {
    return direct;
  }
  const recent = await fetchLogs({ limit: 250 });
  const fallback = recent.items.find((entry) => entry.trace_id === reference || entry.id === reference);
  if (!fallback) {
    throw new APIRequestError('Log event not found', 'LOG_NOT_FOUND', 404);
  }
  return fallback;
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

export function setupUser2FA(id: string) {
  return unwrap<TOTPSetup>(apiClient.post(`/users/${id}/2fa/setup`));
}

export function enableUser2FA(id: string, secret: string, code: string) {
  return unwrap<User>(apiClient.post(`/users/${id}/2fa/enable`, { secret, code }));
}

export function disableUser2FA(id: string) {
  return unwrap<User>(apiClient.post(`/users/${id}/2fa/disable`));
}

export function fetchSystemConfig() {
  return unwrap<SystemConfig>(apiClient.get('/system'));
}

export function updateSystemConfig(payload: Partial<SystemConfig>) {
  return unwrap<SystemConfig>(apiClient.put('/system', payload));
}

export function testStorageBackend(backend: string, storage: SystemConfig['storage']) {
  return unwrap<{ ok: boolean; backend: string }>(apiClient.post('/system/storage/test', { backend, storage }));
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

export function updateProtectionPolicy(policy: ProtectionConfig['policy']) {
  return unwrap<ProtectionConfig['policy']>(apiClient.put('/protection/policy', policy));
}

export async function fetchIPRules() {
  const response = await unwrap<IPRulesResponse>(apiClient.get('/ip'));
  return normalizeIPRulesResponse(response);
}

export function updateIPTags(tags: Record<string, string[]>) {
  return unwrap<Record<string, string[]>>(apiClient.put('/ip/tags', tags));
}

export function updateThreatIntelProviders(providers: ThreatIntelProvider[]) {
  return unwrap<ThreatIntelProvider[]>(apiClient.put('/ip/threat-intel/providers', providers));
}

export function importThreatIntel(payload: {
  format: string;
  contents: string;
  source: string;
  severity: string;
  action: string;
  confidence?: number;
  labels: string[];
  expires_at?: string;
}) {
  return unwrap<{ imported: number; total: number }>(apiClient.post('/ip/threat-intel/import', payload));
}

export function syncThreatIntel(providerId?: string) {
  return unwrap<{ imported: number; total: number; results: Array<Record<string, unknown>> }>(
    apiClient.post('/ip/threat-intel/sync', providerId ? { provider_id: providerId } : {}),
  );
}

export function testThreatIntelProvider(provider: ThreatIntelProvider) {
  return unwrap<{ ok: boolean; count: number }>(apiClient.post('/ip/threat-intel/test', provider));
}

export function lookupThreatIntel(providerId: string, ip: string) {
  return unwrap<{ ip: string; imported: number; items: Array<Record<string, unknown>> }>(
    apiClient.post('/ip/threat-intel/lookup', { provider_id: providerId, ip }),
  );
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

function normalizeIPRulesResponse(response: IPRulesResponse): IPRulesResponse {
  const raw = response as unknown as Partial<IPRulesResponse> | null | undefined;
  const entries = asArray(raw?.entries).map(normalizeIPEntry);
  return {
    whitelist: asStringArray(raw?.whitelist),
    blacklist: asStringArray(raw?.blacklist),
    tags: asStringArrayRecord(raw?.tags),
    threat_intel: asArray(raw?.threat_intel).map(normalizeThreatIntel),
    providers: asArray(raw?.providers).map(normalizeThreatIntelProvider),
    geoip: {
      enabled: Boolean(raw?.geoip?.enabled),
      database: raw?.geoip?.database ?? '',
      blocked_countries: asStringArray(raw?.geoip?.blocked_countries),
      country_cidrs: asStringArrayRecord(raw?.geoip?.country_cidrs),
    },
    entries,
  };
}

function normalizeIPEntry(entry: Partial<IPReputationEntry> | null | undefined): IPReputationEntry {
  const stats = entry?.stats;
  return {
    ip: entry?.ip ?? '',
    list: entry?.list ?? 'monitor',
    reputation: Number(entry?.reputation ?? 80),
    tags: asStringArray(entry?.tags),
    intel: asArray(entry?.intel).map(normalizeThreatIntel),
    stats: {
      total: Number(stats?.total ?? 0),
      blocked: Number(stats?.blocked ?? 0),
      by_type: asNumberRecord(stats?.by_type),
    },
  };
}

function normalizeThreatIntel(indicator: Partial<ThreatIntelIndicator> | null | undefined): ThreatIntelIndicator {
  return {
    id: indicator?.id ?? '',
    value: indicator?.value ?? '',
    type: indicator?.type ?? 'ip',
    severity: indicator?.severity ?? 'medium',
    source: indicator?.source ?? '',
    labels: asStringArray(indicator?.labels),
    action: indicator?.action,
    confidence: typeof indicator?.confidence === 'number' ? indicator.confidence : undefined,
    enabled: indicator?.enabled,
    expires_at: indicator?.expires_at,
  };
}

function normalizeThreatIntelProvider(provider: Partial<ThreatIntelProvider> | null | undefined): ThreatIntelProvider {
  return {
    id: provider?.id ?? '',
    name: provider?.name ?? '',
    type: provider?.type ?? 'generic',
    endpoint: provider?.endpoint ?? '',
    api_key: provider?.api_key ?? '',
    format: provider?.format ?? 'stix',
    action: provider?.action ?? 'challenge',
    min_severity: provider?.min_severity ?? 'high',
    interval: provider?.interval ?? 24 * 60 * 60 * 1_000_000_000,
    headers: provider?.headers ?? {},
    enabled: provider?.enabled ?? true,
  };
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function asStringArray(value: string[] | null | undefined): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function asStringArrayRecord(value: Record<string, string[]> | null | undefined): Record<string, string[]> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  return Object.fromEntries(Object.entries(value).map(([key, list]) => [key, asStringArray(list)]));
}

function asNumberRecord(value: Record<string, number> | null | undefined): Record<string, number> {
  if (!value || typeof value !== 'object') {
    return {};
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, Number(item ?? 0)]));
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

export function reclaimSystemResources(target: 'memory' | 'swap' | 'all') {
  return unwrap<{ ok: boolean; target: string; actions: Array<{ name: string; ok: boolean; message?: string }> }>(
    apiClient.post('/system/reclaim', { target }),
  );
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

export function analyzeEvents(payload: { limit?: number; action?: string; category?: string; client_ip?: string; trace_id?: string }) {
  return unwrap<AIEventsAnalysisResponse>(apiClient.post('/ai/events/analyze', payload));
}

export function askAIAssistant(message: string, limit = 30) {
  return unwrap<AIAssistantReply>(apiClient.post('/ai/assistant', { message, limit }));
}
