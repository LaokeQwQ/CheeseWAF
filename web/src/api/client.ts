import axios, { type AxiosResponse } from 'axios';
import type { ACMEIssueRequest, ACMEIssueResponse, ACMEDNSProvider, AIApprovalRequest, AIConfig, AIEventsAnalysisResponse, AIModelConfig, AIModelInfo, AISelfLearningReport, AIAssistantReply, AIAssistantTraceEvent, AIToolDefinition, AIToolExecution, APISecSummary, AttackAnalysis, AuditEntry, BlockPageConfig, BlockPagePreview, BlockTemplate, ClusterDeploymentCheckResult, ClusterDeploymentRequest, ClusterDeploymentRunResult, ClusterStatus, EdgeConfig, HealthStatus, IPAccessRule, IPReputationEntry, IPRulesResponse, LogQuery, LogResponse, LoginCAPTCHAPayload, LoginCAPTCHAResponse, LoginOptions, MapBoundaryResponse, MonitorSummary, ProtectionConfig, Rule, ScheduledTask, Site, StorageCleanupResult, StorageStats, SystemConfig, ThreatIntelIndicator, ThreatIntelProvider, TOTPSetup, User, VersionInfo } from '../types/api';

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10_000,
  headers: {
    'Content-Type': 'application/json',
  },
});

const AI_REQUEST_TIMEOUT_MS = 300_000;
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
          throw new APIRequestError(
            response.data.error?.message ?? 'Unable to refresh token',
            response.data.error?.code,
            response.status,
            errorLookupID(response.data.error, response),
          );
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
    trace_id?: string;
    event_id?: string;
  };
};

export class APIRequestError extends Error {
  code?: string;
  status?: number;
  traceID?: string;
  rawMessage: string;
  data?: unknown;

  constructor(message: string, code?: string, status?: number, traceID?: string, data?: unknown) {
    super(traceID ? `${message} · Event / Trace ID: ${traceID}` : message);
    this.name = 'APIRequestError';
    this.rawMessage = message;
    this.code = code;
    this.status = status;
    this.traceID = traceID;
    this.data = data;
  }
}

async function unwrap<T>(promise: Promise<AxiosResponse<Envelope<T>>>): Promise<T> {
  try {
    const response = await promise;
    if (response.data.error) {
      throw new APIRequestError(response.data.error.message, response.data.error.code, response.status, errorLookupID(response.data.error, response), response.data.data);
    }
    return response.data.data as T;
  } catch (error) {
    if (axios.isAxiosError<Envelope<unknown>>(error)) {
      const apiError = error.response?.data?.error;
      if (apiError) {
        throw new APIRequestError(apiError.message, apiError.code, error.response?.status, errorLookupID(apiError, error.response), error.response?.data?.data);
      }
      const traceID = responseLookupID(error.response);
      if (error.code === 'ECONNABORTED' || error.message.toLowerCase().includes('timeout')) {
        const timeout = Number(error.config?.timeout ?? apiClient.defaults.timeout ?? 0);
        const seconds = timeout > 0 ? Math.round(timeout / 1000) : 0;
        throw new APIRequestError(
          seconds > 0 ? `Request timed out after ${seconds}s. Check the upstream service or try again.` : 'Request timed out. Check the upstream service or try again.',
          'REQUEST_TIMEOUT',
          error.response?.status,
          traceID,
        );
      }
      if (!error.response) {
        throw new APIRequestError(
          'Network request failed. Check the API base URL, provider availability, firewall, or server-side proxy logs.',
          'NETWORK_ERROR',
          undefined,
          traceID,
        );
      }
      if (error.response?.status) {
        throw new APIRequestError(error.message, undefined, error.response.status, traceID);
      }
    }
    throw error;
  }
}

function errorLookupID(error?: Envelope<unknown>['error'], response?: AxiosResponse<unknown>) {
  return error?.event_id ?? error?.trace_id ?? responseLookupID(response);
}

function responseLookupID(response?: AxiosResponse<unknown>) {
  const headers = response?.headers as (AxiosResponse<unknown>['headers'] & { get?: (name: string) => unknown }) | undefined;
  const value = headers?.get?.('x-cheesewaf-event-id')
    ?? headers?.['x-cheesewaf-event-id']
    ?? headers?.get?.('x-cheesewaf-trace-id')
    ?? headers?.['x-cheesewaf-trace-id'];
  if (Array.isArray(value)) {
    return value[0];
  }
  return typeof value === 'string' ? value : undefined;
}

function fetchResponseTraceID(response?: Response) {
  return response?.headers.get('x-cheesewaf-event-id') ?? response?.headers.get('x-cheesewaf-trace-id') ?? undefined;
}

export function fetchLoginOptions() {
  return unwrap<LoginOptions>(apiClient.get('/auth/login-options'));
}

export function fetchLoginCaptcha(mode?: 'slider' | 'pow') {
  return unwrap<LoginCAPTCHAResponse>(apiClient.post('/auth/captcha', mode ? { mode } : {}));
}

export function verifyLoginCaptcha(captcha: LoginCAPTCHAPayload) {
  return unwrap<{ valid: boolean; receipt: string }>(apiClient.post('/auth/captcha/verify', captcha));
}

export function login(username: string, password: string, totpCode?: string, captcha?: LoginCAPTCHAPayload) {
  return unwrap<AuthResponse>(
    apiClient.post('/auth/login', { username, password, totp_code: totpCode, captcha }),
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

export function fetchACMEProviders() {
  return unwrap<ACMEDNSProvider[]>(apiClient.get('/acme/providers'));
}

export function issueSiteACMECertificate(siteId: string, payload: ACMEIssueRequest) {
  return unwrap<ACMEIssueResponse>(apiClient.post(`/sites/${siteId}/acme/issue`, payload, { timeout: 180_000 }));
}

export function fetchStats() {
  return unwrap<Record<string, unknown>>(apiClient.get('/stats'));
}

export async function fetchHealth() {
  const response = await axios.get<{ data?: HealthStatus }>('/health', { timeout: 2500 });
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

export function fetchClusterStatus() {
  return unwrap<ClusterStatus>(apiClient.get('/cluster/status'));
}

export function checkClusterDeployment(payload: ClusterDeploymentRequest) {
  return unwrap<ClusterDeploymentCheckResult>(apiClient.post('/cluster/deploy/check', payload, { timeout: 60_000 }));
}

export function runClusterDeployment(payload: ClusterDeploymentRequest) {
  return unwrap<ClusterDeploymentRunResult>(apiClient.post('/cluster/deploy/run', payload, { timeout: 180_000 }));
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

export function fetchVersion() {
  return unwrap<VersionInfo>(apiClient.get('/version'));
}

export function fetchChinaMapBoundary() {
  return unwrap<MapBoundaryResponse>(apiClient.get('/system/map/china-boundary'));
}

export function fetchChinaMapBoundaryByCode(adcode: string) {
  return unwrap<MapBoundaryResponse>(apiClient.get(`/system/map/china-boundary/${encodeURIComponent(adcode)}`));
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

export function updateIPAccessRules(rules: IPAccessRule[]) {
  return unwrap<IPAccessRule[]>(apiClient.put('/ip/access-rules', rules));
}

export function updateIPReputationOverrides(overrides: Record<string, number>) {
  return unwrap<Record<string, number>>(apiClient.put('/ip/reputation-overrides', overrides));
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
    access_rules: asArray(raw?.access_rules).map(normalizeIPAccessRule),
    reputation_overrides: asNumberRecord(raw?.reputation_overrides),
    tags: asStringArrayRecord(raw?.tags),
    threat_intel: asArray(raw?.threat_intel).map(normalizeThreatIntel),
    providers: asArray(raw?.providers).map(normalizeThreatIntelProvider),
    geoip: {
      enabled: Boolean(raw?.geoip?.enabled),
      database: raw?.geoip?.database ?? '',
      precision_database: raw?.geoip?.precision_database ?? '',
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
    reputation_override: typeof entry?.reputation_override === 'number' ? entry.reputation_override : undefined,
    tags: asStringArray(entry?.tags),
    intel: asArray(entry?.intel).map(normalizeThreatIntel),
    access_rules: asArray(entry?.access_rules).map(normalizeIPAccessRuleRef),
    stats: {
      total: Number(stats?.total ?? 0),
      blocked: Number(stats?.blocked ?? 0),
      by_type: asNumberRecord(stats?.by_type),
    },
  };
}

function normalizeIPAccessRule(rule: Partial<IPAccessRule> | null | undefined): IPAccessRule {
  return {
    id: rule?.id ?? '',
    name: rule?.name ?? '',
    description: rule?.description ?? '',
    action: rule?.action ?? 'allow',
    scope: rule?.scope ?? 'global',
    site_id: rule?.site_id ?? '',
    path_prefix: rule?.path_prefix ?? '',
    entries: asStringArray(rule?.entries),
    enabled: rule?.enabled ?? true,
  };
}

function normalizeIPAccessRuleRef(rule: Partial<IPAccessRule> | null | undefined) {
  return normalizeIPAccessRule(rule);
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
    auth_type: provider?.auth_type ?? 'bearer',
    format: provider?.format ?? 'stix',
    action: provider?.action ?? 'challenge',
    min_severity: provider?.min_severity ?? 'high',
    interval: provider?.interval ?? 24 * 60 * 60 * 1_000_000_000,
    headers: provider?.headers ?? {},
    notes: provider?.notes ?? '',
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
  return unwrap<StorageCleanupResult>(apiClient.post('/storage/cleanup'));
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

export function fetchBlockPageConfig() {
  return unwrap<BlockPageConfig>(apiClient.get('/block-pages/config'));
}

export function updateBlockPageConfig(payload: BlockPageConfig) {
  return unwrap<BlockPageConfig>(apiClient.put('/block-pages/config', payload));
}

export function previewBlockPageConfig(payload: BlockPageConfig) {
  return unwrap<BlockPagePreview>(apiClient.post('/block-pages/preview', payload));
}

export function uploadBlockPageHTML(file: File, templateID?: string) {
  const form = new FormData();
  form.append('file', file);
  if (templateID) {
    form.append('template_id', templateID);
  }
  return unwrap<{ config: BlockPageConfig; filename: string; bytes: number }>(
    apiClient.post('/block-pages/upload', form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  );
}

export function deleteCustomBlockPage() {
  return unwrap<BlockPageConfig>(apiClient.delete('/block-pages/custom'));
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

export function fetchAIModels(config?: Pick<AIModelConfig, 'provider' | 'api_base'> & { api_key?: string; allow_private_api_base?: boolean; target?: 'assistant' | 'reasoning' | string }) {
  if (config) {
    return unwrap<{ items: AIModelInfo[]; total: number }>(apiClient.post('/ai/models', config, { timeout: 60_000 }));
  }
  return unwrap<{ items: AIModelInfo[]; total: number }>(apiClient.get('/ai/models', { timeout: 60_000 }));
}

export function testAIConnection(config: Pick<AIModelConfig, 'provider' | 'api_base' | 'model'> & { api_key?: string; allow_private_api_base?: boolean; target?: 'assistant' | 'reasoning' | string }) {
  return unwrap<{ ok: boolean; target: string }>(apiClient.post('/ai/test', config, { timeout: 60_000 }));
}

export function analyzeLog(entry: Record<string, unknown>, language?: string) {
  return unwrap<AttackAnalysis>(apiClient.post('/ai/analyze', { ...entry, language }, { timeout: AI_REQUEST_TIMEOUT_MS }));
}

export function analyzeLogReference(reference: string, language?: string) {
  return unwrap<AttackAnalysis>(apiClient.post('/ai/analyze', { reference, language }, { timeout: AI_REQUEST_TIMEOUT_MS }));
}

export async function analyzeLogReferenceStream(
  reference: string,
  language = '',
  onTrace?: (event: AIAssistantTraceEvent) => void,
  signal?: AbortSignal,
) {
  const token = localStorage.getItem(tokenStorageKey);
  const activeToken = token ? await refreshTokenIfNeeded(token, '/ai/analyze/stream') : '';
  const response = await fetch('/api/ai/analyze/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      ...(activeToken ? { Authorization: `Bearer ${activeToken}` } : {}),
    },
    body: JSON.stringify({ reference, language }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, 'AI_ANALYSIS_STREAM_FAILED', response.status, errorBody.traceID ?? traceID);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json') || response.headers.get('x-cheesewaf-stream-fallback') === 'json') {
    const payload = await response.json() as Envelope<AttackAnalysis>;
    if (payload.error) {
      throw new APIRequestError(payload.error.message, payload.error.code, response.status, payload.error.event_id ?? payload.error.trace_id ?? traceID);
    }
    return payload.data as AttackAnalysis;
  }
  if (!response.body) {
    throw new APIRequestError('Streaming response body is not available.', 'AI_ANALYSIS_STREAM_UNAVAILABLE', response.status, traceID);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalAnalysis: AttackAnalysis | null = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split(/\n\n/);
      buffer = parts.pop() ?? '';
      for (const part of parts) {
        const event = parseSSEBlock(part);
        if (!event) continue;
        if (event.event === 'trace') {
          onTrace?.(event.data as AIAssistantTraceEvent);
        } else if (event.event === 'done') {
          finalAnalysis = event.data as AttackAnalysis;
        } else if (event.event === 'error') {
          const payload = event.data as { message?: string; code?: string; event_id?: string; trace_id?: string };
          throw new APIRequestError(payload.message || 'AI analysis stream failed.', payload.code || 'AI_ANALYSIS_STREAM_FAILED', response.status, payload.event_id ?? payload.trace_id ?? traceID);
        }
      }
    }
    if (buffer.trim()) {
      const event = parseSSEBlock(buffer);
      if (event?.event === 'done') {
        finalAnalysis = event.data as AttackAnalysis;
      }
    }
  } catch (error) {
    if (error instanceof APIRequestError) {
      throw error;
    }
    if ((error as DOMException)?.name === 'AbortError') {
      throw new APIRequestError('AI analysis request was cancelled.', 'AI_ANALYSIS_CANCELLED', response.status, traceID);
    }
    throw new APIRequestError(
      streamInterruptedMessage('AI analysis stream was interrupted before completion', error),
      'AI_ANALYSIS_STREAM_INTERRUPTED',
      response.status,
      traceID,
      error,
    );
  }
  if (!finalAnalysis) {
    throw new APIRequestError(
      streamInterruptedMessage('AI analysis stream ended without a final result', 'missing final done event'),
      'AI_ANALYSIS_STREAM_INCOMPLETE',
      response.status,
      traceID,
    );
  }
  return finalAnalysis;
}

export function analyzeEvents(payload: { limit?: number; action?: string; category?: string; client_ip?: string; trace_id?: string; start?: string; end?: string; language?: string }) {
  return unwrap<AIEventsAnalysisResponse>(apiClient.post('/ai/events/analyze', payload, { timeout: AI_REQUEST_TIMEOUT_MS }));
}

export function askAIAssistant(message: string, limit = 30, language?: string, deepThink = false) {
  return unwrap<AIAssistantReply>(apiClient.post('/ai/assistant', { message, limit, language, deep_think: deepThink }, { timeout: AI_REQUEST_TIMEOUT_MS }));
}

export async function askAIAssistantStream(
  message: string,
  limit = 30,
  language = '',
  deepThink = false,
  onTrace?: (event: AIAssistantTraceEvent) => void,
  signal?: AbortSignal,
) {
  const token = localStorage.getItem(tokenStorageKey);
  const activeToken = token ? await refreshTokenIfNeeded(token, '/ai/assistant/stream') : '';
  const response = await fetch('/api/ai/assistant/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      ...(activeToken ? { Authorization: `Bearer ${activeToken}` } : {}),
    },
    body: JSON.stringify({ message, limit, language, deep_think: deepThink }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, 'AI_ASSISTANT_STREAM_FAILED', response.status, errorBody.traceID ?? traceID);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json') || response.headers.get('x-cheesewaf-stream-fallback') === 'json') {
    const payload = await response.json() as Envelope<AIAssistantReply>;
    if (payload.error) {
      throw new APIRequestError(payload.error.message, payload.error.code, response.status, payload.error.event_id ?? payload.error.trace_id ?? traceID);
    }
    return payload.data as AIAssistantReply;
  }
  if (!response.body) {
    throw new APIRequestError('Streaming response body is not available.', 'AI_ASSISTANT_STREAM_UNAVAILABLE', response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalReply: AIAssistantReply | null = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split(/\n\n/);
      buffer = parts.pop() ?? '';
      for (const part of parts) {
        const event = parseSSEBlock(part);
        if (!event) {
          continue;
        }
        if (event.event === 'trace') {
          onTrace?.(event.data as AIAssistantTraceEvent);
        } else if (event.event === 'done') {
          finalReply = event.data as AIAssistantReply;
        } else if (event.event === 'error') {
          const payload = event.data as { message?: string; code?: string; event_id?: string; trace_id?: string };
          throw new APIRequestError(payload.message || 'AI assistant stream failed.', payload.code || 'AI_ASSISTANT_STREAM_FAILED', response.status, payload.event_id ?? payload.trace_id ?? traceID);
        }
      }
    }
    if (buffer.trim()) {
      const event = parseSSEBlock(buffer);
      if (event?.event === 'done') {
        finalReply = event.data as AIAssistantReply;
      }
    }
  } catch (error) {
    if (error instanceof APIRequestError) {
      throw error;
    }
    if ((error as DOMException)?.name === 'AbortError') {
      throw new APIRequestError('AI assistant request was cancelled.', 'AI_ASSISTANT_CANCELLED', response.status, traceID);
    }
    throw new APIRequestError(
      streamInterruptedMessage('AI assistant stream was interrupted before completion', error),
      'AI_ASSISTANT_STREAM_INTERRUPTED',
      response.status,
      traceID,
      error,
    );
  }
  if (!finalReply) {
    throw new APIRequestError(
      streamInterruptedMessage('AI assistant stream ended without a final answer', 'missing final done event'),
      'AI_ASSISTANT_STREAM_INCOMPLETE',
      response.status,
      traceID,
    );
  }
  return finalReply;
}

export async function continueAIApprovalStream(
  approvalID: string,
  message: string,
  limit = 30,
  language = '',
  deepThink = false,
  onTrace?: (event: AIAssistantTraceEvent) => void,
  signal?: AbortSignal,
) {
  const token = localStorage.getItem(tokenStorageKey);
  const activeToken = token ? await refreshTokenIfNeeded(token, '/ai/tools/approvals/continue/stream') : '';
  const response = await fetch(`/api/ai/tools/approvals/${encodeURIComponent(approvalID)}/continue/stream`, {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
      ...(activeToken ? { Authorization: `Bearer ${activeToken}` } : {}),
    },
    body: JSON.stringify({ message, limit, language, deep_think: deepThink }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, 'AI_APPROVAL_CONTINUE_FAILED', response.status, errorBody.traceID ?? traceID);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json') || response.headers.get('x-cheesewaf-stream-fallback') === 'json') {
    const payload = await response.json() as Envelope<AIAssistantReply>;
    if (payload.error) {
      throw new APIRequestError(payload.error.message, payload.error.code, response.status, payload.error.event_id ?? payload.error.trace_id ?? traceID);
    }
    return payload.data as AIAssistantReply;
  }
  if (!response.body) {
    throw new APIRequestError('AI approval continuation stream is not available.', 'AI_APPROVAL_CONTINUE_STREAM_UNAVAILABLE', response.status);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalReply: AIAssistantReply | null = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split(/\n\n/);
      buffer = parts.pop() ?? '';
      for (const part of parts) {
        const event = parseSSEBlock(part);
        if (!event) {
          continue;
        }
        if (event.event === 'trace') {
          onTrace?.(event.data as AIAssistantTraceEvent);
        } else if (event.event === 'done') {
          finalReply = event.data as AIAssistantReply;
        } else if (event.event === 'error') {
          const payload = event.data as { message?: string; code?: string; event_id?: string; trace_id?: string };
          throw new APIRequestError(payload.message || 'AI approval continuation failed.', payload.code || 'AI_APPROVAL_CONTINUE_FAILED', response.status, payload.event_id ?? payload.trace_id ?? traceID);
        }
      }
    }
    if (buffer.trim()) {
      const event = parseSSEBlock(buffer);
      if (event?.event === 'done') {
        finalReply = event.data as AIAssistantReply;
      }
    }
  } catch (error) {
    if (error instanceof APIRequestError) {
      throw error;
    }
    if ((error as DOMException)?.name === 'AbortError') {
      throw new APIRequestError('AI approval continuation was cancelled.', 'AI_APPROVAL_CONTINUE_CANCELLED', response.status, traceID);
    }
    throw new APIRequestError(
      streamInterruptedMessage('AI approval continuation stream was interrupted before completion', error),
      'AI_APPROVAL_CONTINUE_STREAM_INTERRUPTED',
      response.status,
      traceID,
      error,
    );
  }
  if (!finalReply) {
    throw new APIRequestError(
      streamInterruptedMessage('AI approval continuation stream ended without a final answer', 'missing final done event'),
      'AI_APPROVAL_CONTINUE_STREAM_INCOMPLETE',
      response.status,
      traceID,
    );
  }
  return finalReply;
}

export function runAISelfLearning(payload: { dry_run?: boolean; language?: string } = {}) {
  return unwrap<AISelfLearningReport>(apiClient.post('/ai/self-learning/run', payload, { timeout: AI_REQUEST_TIMEOUT_MS }));
}

export function fetchAITools() {
  return unwrap<AIToolDefinition[]>(apiClient.get('/ai/tools'));
}

export function executeAITool(name: string, args: Record<string, unknown> = {}, approvalID = '') {
  return unwrap<AIToolExecution>(apiClient.post('/ai/tools/execute', { name, args, approval_id: approvalID }));
}

export function approveAIApproval(id: string) {
  return unwrap<AIApprovalRequest>(apiClient.post(`/ai/tools/approvals/${encodeURIComponent(id)}/approve`, {}));
}

export function rejectAIApproval(id: string) {
  return unwrap<AIApprovalRequest>(apiClient.post(`/ai/tools/approvals/${encodeURIComponent(id)}/reject`, {}));
}

function parseSSEBlock(block: string) {
  const lines = block.split(/\r?\n/);
  let event = 'message';
  const data: string[] = [];
  for (const line of lines) {
    if (line.startsWith('event:')) {
      event = line.slice(6).trim();
    } else if (line.startsWith('data:')) {
      data.push(line.slice(5).trimStart());
    }
  }
  if (data.length === 0) {
    return null;
  }
  return { event, data: JSON.parse(data.join('\n')) as unknown };
}

async function readableFetchError(response: Response): Promise<{ message: string; traceID?: string }> {
  const text = await response.text().catch(() => '');
  if (!text) {
    return { message: `${response.status} ${response.statusText}`, traceID: fetchResponseTraceID(response) };
  }
  try {
    const parsed = JSON.parse(text) as Envelope<unknown>;
    return { message: parsed.error?.message || text, traceID: parsed.error?.event_id ?? parsed.error?.trace_id ?? fetchResponseTraceID(response) };
  } catch {
    return { message: text, traceID: fetchResponseTraceID(response) };
  }
}

function streamInterruptedMessage(prefix: string, error: unknown) {
  const cause = error instanceof Error ? error.message : String(error || '');
  const detail = cause.trim() ? ` Cause: ${cause.trim()}.` : '';
  return `${prefix}.${detail} The server keeps the stream alive with heartbeats; check provider latency, reverse proxy buffering, or network stability.`;
}
