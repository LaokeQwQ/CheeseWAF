import axios, { type AxiosResponse } from 'axios';
import type { CaptchaChallenge, CaptchaResponse, CaptchaType, CaptchaVerifyResult } from '../features/captcha/protocol';
import { queryClient } from '../queryClient';
import type { ACMEIssueRequest, ACMEIssueResponse, ACMEDNSProvider, AIApprovalList, AIApprovalRequest, AIConfig, AIEventsAnalysisResponse, AIModelConfig, AIModelInfo, AISelfLearningReport, AIAssistantReply, AIAssistantTraceEvent, AIToolDefinition, AIToolExecution, APISecSummary, AttackAnalysis, AttackMapAggregateQuery, AttackMapAggregateResponse, AuditEntry, BlockPageConfig, BlockPagePreview, BlockTemplate, ClusterAnsiblePackage, ClusterAnsiblePlan, ClusterAuditList, ClusterBootstrapPlan, ClusterBootstrapPlanRequest, ClusterConfigVersionRecord, ClusterConsensusSnapshot, ClusterDeploymentCheckResponse, ClusterDeploymentRequest, ClusterDeploymentRunResult, ClusterDeploymentTask, ClusterDeploymentTaskList, ClusterJoinTokenCreateRequest, ClusterJoinTokenList, ClusterNodeCertificateRotateRequest, ClusterNodeCertificateRotateResponse, ClusterNodeList, ClusterRollingJob, ClusterRollingUpgradeRequest, ClusterStatus, ClusterTrafficPeersResponse, CreateManagementAPITokenRequest, CreateManagementAPITokenResponse, EdgeConfig, HealthStatus, IPAccessRule, IPReputationEntry, IPRulesResponse, LogQuery, LogResponse, LoginCAPTCHAPayload, LoginCAPTCHAResponse, LoginOptions, ManagementAPITokenList, MapBoundaryResponse, MonitorSummary, Notification, NotificationFilter, NotificationList, ProtectionConfig, ReviewDecision, ReviewItem, ReviewQuery, ReviewResponse, Rule, ScheduledTask, Site, StorageCleanupResult, StorageStats, SystemConfig, ThreatIntelIndicator, ThreatIntelProvider, TOTPSetup, User, VersionInfo } from '../types/api';
import type { TimeSyncStatus } from '../types/api';

export const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10_000,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

const AI_REQUEST_TIMEOUT_MS = 300_000;
/** Legacy key cleared on logout; sessions use HttpOnly cookies, not localStorage. */
const tokenStorageKey = 'cheesewaf-token';
const authFlagKey = 'cheesewaf-authed';
const csrfCookieName = 'cheesewaf_csrf';
const csrfHeaderName = 'X-CSRF-Token';
const setupTokenStorageKey = 'cheesewaf-setup-token';
const sessionRefreshThrottleKey = 'cheesewaf-last-refresh';
const sessionRefreshThrottleMs = 10 * 60_000;
const setupTokenHeaderName = 'X-CheeseWAF-Setup-Token';
let refreshPromise: Promise<void> | null = null;
let authRedirectScheduled = false;
let authRedirectLocationForTest: AuthRedirectLocation | null = null;
let cachedCSRF = '';

type AuthResponse = {
  token?: string;
  csrf?: string;
  session_cookie?: boolean;
  user: { username: string; role: string };
};
type AuthRedirectLocation = Pick<Location, 'pathname' | 'assign'> & Partial<Pick<Location, 'search' | 'hash'>>;

function readCSRFCookie(): string {
  if (typeof document === 'undefined') {
    return cachedCSRF;
  }
  const parts = document.cookie.split(';');
  for (const part of parts) {
    const [name, ...rest] = part.trim().split('=');
    if (name === csrfCookieName) {
      return decodeURIComponent(rest.join('=') || '');
    }
  }
  return cachedCSRF;
}

export function getCSRFToken(): string {
  const fromCookie = readCSRFCookie();
  if (fromCookie) {
    cachedCSRF = fromCookie;
  }
  return cachedCSRF;
}

export function setCSRFToken(token: string) {
  cachedCSRF = token || '';
}

export function markAuthenticated(yes: boolean) {
  if (yes) {
    sessionStorage.setItem(authFlagKey, '1');
  } else {
    sessionStorage.removeItem(authFlagKey);
  }
}

export function isAuthenticatedFlag(): boolean {
  return sessionStorage.getItem(authFlagKey) === '1' || !!readCSRFCookie();
}

type SetupLocation = Pick<Location, 'hash' | 'pathname' | 'search'>;
type SetupHistory = Pick<History, 'replaceState' | 'state'>;

export async function hydrateSetupTokenFromStatus(
  fetcher: typeof fetch = fetch,
): Promise<string> {
  const existing = setupToken() || captureSetupTokenFromFragment();
  if (existing) {
    return existing;
  }
  try {
    const res = await fetcher('/api/setup/status', { credentials: 'same-origin' });
    if (!res.ok) {
      return '';
    }
    const body = (await res.json()) as { data?: { setup_url?: string } };
    const page = (body.data?.setup_url ?? '').trim();
    if (!page) {
      return '';
    }
    const hash = page.includes('#') ? page.slice(page.indexOf('#') + 1) : '';
    const token = (new URLSearchParams(hash).get('setup_token') ?? '').trim();
    if (!token) {
      return '';
    }
    try {
      sessionStorage.setItem(setupTokenStorageKey, token);
    } catch {
      return token;
    }
    return token;
  } catch {
    return '';
  }
}

export function captureSetupTokenFromFragment(
  locationRef: SetupLocation = window.location,
  historyRef: SetupHistory = window.history,
): string {
  const rawFragment = locationRef.hash.startsWith('#') ? locationRef.hash.slice(1) : locationRef.hash;
  const params = new URLSearchParams(rawFragment);
  const token = (params.get('setup_token') ?? '').trim();
  if (!token) {
    return '';
  }
  try {
    sessionStorage.setItem(setupTokenStorageKey, token);
  } catch {
    return '';
  }
  params.delete('setup_token');
  const remaining = params.toString();
  historyRef.replaceState(historyRef.state, '', `${locationRef.pathname}${locationRef.search}${remaining ? `#${remaining}` : ''}`);
  return token;
}

function setupToken(): string {
  try {
    return sessionStorage.getItem(setupTokenStorageKey)?.trim() ?? '';
  } catch {
    return '';
  }
}

function clearSetupToken() {
  try {
    sessionStorage.removeItem(setupTokenStorageKey);
  } catch {
    /* ignore */
  }
}

function isSetupMutation(method: string, requestURL: string): boolean {
  let path: string;
  try {
    path = new URL(requestURL, 'https://cheesewaf.invalid').pathname.replace(/^\/api/, '');
  } catch {
    return false;
  }
  return (method === 'post' && (path === '/setup' || path === '/setup/probe'))
    || (method === 'patch' && path === '/setup/draft');
}

function clearLegacyTokenStorage() {
  try {
    localStorage.removeItem(tokenStorageKey);
  } catch {
    /* ignore */
  }
}

apiClient.interceptors.request.use(async (config) => {
	const url = String(config.url ?? '');
	const method = String(config.method ?? 'get').toLowerCase();
	if (isSetupMutation(method, url)) {
		await hydrateSetupTokenFromStatus();
		const token = setupToken();
		if (token) {
			config.headers[setupTokenHeaderName] = token;
		}
	}
  // Cookie session: credentials already include HttpOnly JWT. Attach CSRF on mutations.
  if (['post', 'put', 'patch', 'delete'].includes(method) && !url.includes('/auth/login') && !url.includes('/setup') && !url.includes('/auth/captcha')) {
    const csrf = getCSRFToken();
    if (csrf) {
      config.headers[csrfHeaderName] = csrf;
    }
  }
  // Soft refresh via cookie when SPA is authed (no JWT in localStorage).
  if (isAuthenticatedFlag() && !url.includes('/auth/login') && !url.includes('/auth/refresh') && !url.includes('/auth/logout') && !url.includes('/setup') && !url.includes('/auth/session')) {
    await refreshSessionIfNeeded();
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (isSessionInvalidAuthFailure(error)) {
      handleUnauthorizedAuthFailure();
    }
    return Promise.reject(error);
  },
);

export function handleUnauthorizedAuthFailure(locationRef: AuthRedirectLocation = authRedirectLocationForTest ?? window.location) {
  clearLegacyTokenStorage();
  markAuthenticated(false);
  setCSRFToken('');
  queryClient.clear();
  const path = locationRef.pathname;
  if (path === '/login' || path === '/setup' || authRedirectScheduled) {
    return;
  }
  authRedirectScheduled = true;
  const returnTo = sanitizeInternalReturnPath(`${path}${locationRef.search || ''}${locationRef.hash || ''}`);
  locationRef.assign(`/login?returnTo=${encodeURIComponent(returnTo)}`);
}

export function sanitizeInternalReturnPath(value: string | null | undefined) {
  if (!value || !value.startsWith('/') || value.startsWith('//')) {
    return '/';
  }
  try {
    const parsed = new URL(value, 'https://cheesewaf.invalid');
    if (parsed.origin !== 'https://cheesewaf.invalid' || parsed.pathname === '/login' || parsed.pathname === '/setup') {
      return '/';
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return '/';
  }
}

export function setAuthRedirectLocationForTest(locationRef: AuthRedirectLocation | null) {
  authRedirectLocationForTest = locationRef;
}

export function resetAuthRedirectStateForTest() {
  authRedirectScheduled = false;
  authRedirectLocationForTest = null;
}

function isSessionRefreshDue(): boolean {
  try {
    const raw = sessionStorage.getItem(sessionRefreshThrottleKey);
    if (!raw) {
      return true;
    }
    const at = Number(raw);
    return Number.isFinite(at) && (Date.now() - at) > sessionRefreshThrottleMs;
  } catch {
    return true;
  }
}

function markSessionRefresh() {
  try {
    sessionStorage.setItem(sessionRefreshThrottleKey, String(Date.now()));
  } catch {
    /* ignore */
  }
}

async function refreshSessionIfNeeded() {
  // Cookie sessions are refreshed at most every 10 minutes via /auth/refresh
  // (HttpOnly cookie). Avoid hammering: only one in-flight refresh, and skip
  // entirely when a recent refresh already ran. Refresh failures are soft: the
  // originating request still proceeds so the response interceptor can handle 401.
  if (refreshPromise) {
    try {
      await refreshPromise;
    } catch {
      /* handled by caller path */
    }
    return;
  }
  if (!isSessionRefreshDue()) {
    return;
  }
  try {
    await refreshSession();
  } catch {
    // Best-effort: let the actual request run its course.
  }
}

export async function refreshSession() {
  if (!refreshPromise) {
    refreshPromise = apiClient
      .post<Envelope<AuthResponse>>('/auth/refresh', {})
      .then((response) => {
        if (response.data.error || !response.data.data) {
          throw new APIRequestError(
            response.data.error?.message ?? 'Unable to refresh session',
            response.data.error?.code,
            response.status,
            errorLookupID(response.data.error, response),
          );
        }
        if (response.data.data.csrf) {
          setCSRFToken(response.data.data.csrf);
        }
        markAuthenticated(true);
        markSessionRefresh();
        clearLegacyTokenStorage();
      })
      .finally(() => {
        refreshPromise = null;
      });
  }
  await refreshPromise;
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
  approval?: AIApprovalRequest;

  constructor(message: string, code?: string, status?: number, traceID?: string, data?: unknown) {
    super(traceID ? `${message} · Event / Trace ID: ${traceID}` : message);
    this.name = 'APIRequestError';
    this.rawMessage = message;
    this.code = code;
    this.status = status;
    this.traceID = traceID;
    this.data = data;
    if (code === 'AI_APPROVAL_CONTINUE_STATUS_RECONCILED') {
      this.approval = data as AIApprovalRequest;
    }
  }
}

const sessionInvalidErrorCodes = new Set(['UNAUTHORIZED', 'SESSION_EXPIRED', 'SESSION_INVALID']);

function apiErrorCode(payload: unknown): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const value = payload as { code?: unknown; error?: unknown };
  if (typeof value.code === 'string') {
    return value.code;
  }
  if (typeof value.error === 'string') {
    return value.error;
  }
  if (value.error && typeof value.error === 'object' && typeof (value.error as { code?: unknown }).code === 'string') {
    return (value.error as { code: string }).code;
  }
  return undefined;
}

export function isSessionInvalidAuthFailure(error: unknown): boolean {
  if (error instanceof APIRequestError) {
    return error.status === 401 && Boolean(error.code && sessionInvalidErrorCodes.has(error.code));
  }
  if (!axios.isAxiosError(error) || error.response?.status !== 401) {
    return false;
  }
  const code = apiErrorCode(error.response.data);
  return Boolean(code && sessionInvalidErrorCodes.has(code));
}

export async function unwrapAPIResponse<T>(promise: Promise<AxiosResponse<Envelope<T>>>): Promise<T> {
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

/** @deprecated Prefer unwrapAPIResponse; kept for call sites during migration. */
export const unwrap = unwrapAPIResponse;

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

export function issueCaptchaLabChallenge(type: CaptchaType, signal?: AbortSignal) {
  const request = signal
    ? apiClient.post('/captcha/lab/challenges', { type }, { signal })
    : apiClient.post('/captcha/lab/challenges', { type });
  return unwrap<CaptchaChallenge>(request);
}

export function verifyCaptchaLabChallenge(response: CaptchaResponse, signal?: AbortSignal) {
  const request = signal
    ? apiClient.post('/captcha/lab/verify', response, { signal })
    : apiClient.post('/captcha/lab/verify', response);
  return unwrap<CaptchaVerifyResult>(request);
}

export function fetchLoginCaptcha(mode?: 'slider' | 'pow', signal?: AbortSignal) {
  return unwrap<LoginCAPTCHAResponse>(apiClient.post('/auth/captcha', mode ? { mode } : {}, { signal }));
}

export function verifyLoginCaptcha(captcha: LoginCAPTCHAPayload, signal?: AbortSignal) {
  return unwrap<{ valid: boolean; receipt: string }>(apiClient.post('/auth/captcha/verify', captcha, { signal }));
}

export async function login(username: string, password: string, totpCode?: string, captcha?: LoginCAPTCHAPayload) {
  const result = await unwrap<AuthResponse>(
    apiClient.post('/auth/login', { username, password, totp_code: totpCode, captcha }),
  );
  if (result.csrf) {
    setCSRFToken(result.csrf);
  }
  markAuthenticated(true);
  clearLegacyTokenStorage();
  try {
    if (result.user) {
      sessionStorage.setItem('cheesewaf-account', JSON.stringify({ username: result.user.username, role: result.user.role }));
    }
  } catch {
    /* ignore */
  }
  return result;
}

export async function logout() {
  const result = await unwrap<{ revoked: boolean }>(apiClient.post('/auth/logout', {}));
  // Only clear local state after server confirms logout success
  markAuthenticated(false);
  setCSRFToken('');
  clearLegacyTokenStorage();
  try {
    sessionStorage.removeItem('cheesewaf-account');
  } catch {
    /* ignore */
  }
  return result;
}

export async function fetchSession() {
  const result = await unwrap<AuthResponse & { session_cookie?: boolean }>(apiClient.get('/auth/session'));
  if (result.csrf) {
    setCSRFToken(result.csrf);
  }
  markAuthenticated(true);
  clearLegacyTokenStorage();
  return result;
}

/** One-shot migration: legacy Bearer in localStorage → HttpOnly cookie session. */
export async function bootstrapSessionFromLegacyToken(): Promise<boolean> {
  const legacy = localStorage.getItem(tokenStorageKey);
  if (!legacy) {
    return false;
  }
  try {
    const response = await apiClient.post<Envelope<AuthResponse>>(
      '/auth/session/bootstrap',
      {},
      { headers: { Authorization: `Bearer ${legacy}` } },
    );
    if (response.data.error || !response.data.data) {
      clearLegacyTokenStorage();
      return false;
    }
    if (response.data.data.csrf) {
      setCSRFToken(response.data.data.csrf);
    }
    markAuthenticated(true);
    clearLegacyTokenStorage();
    return true;
  } catch {
    clearLegacyTokenStorage();
    return false;
  }
}

export async function setupAdmin(username: string, password: string, adminListen: string, adminStrategy = 'local') {
	const result = await unwrap<{ user: { username: string; role: string } }>(
		apiClient.post('/setup', {
      username,
      password,
      admin_listen: adminListen,
      admin_strategy: adminStrategy,
      admin_public: adminStrategy === 'public_tls',
		}),
	);
	clearSetupToken();
	return result;
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

export async function fetchHealth(): Promise<HealthStatus> {
  const response = await axios.get<{ data?: HealthStatus }>('/health', { timeout: 2500 });
  const health = response.data?.data;
  if (!health || typeof health.status !== 'string' || !Number.isFinite(health.uptime_seconds)) {
    throw new APIRequestError('Health endpoint returned an invalid response.', 'HEALTH_RESPONSE_INVALID', response.status);
  }
  return health;
}

export function fetchLogs(params: LogQuery = {}) {
  return unwrap<LogResponse>(apiClient.get('/logs', { params }));
}

export function fetchAttackMapAggregate(params: AttackMapAggregateQuery = {}) {
  return unwrap<AttackMapAggregateResponse>(apiClient.get('/attack-map/aggregate', { params }));
}

export function fetchReviewItems(params: ReviewQuery = {}) {
  return unwrap<ReviewResponse>(apiClient.get('/review', { params }));
}

export function decideReviewItem(id: string, decision: ReviewDecision) {
  return unwrap<ReviewItem>(apiClient.post(`/review/${encodeURIComponent(id)}/decide`, { decision }));
}

export async function fetchLogEvent(reference: string) {
  const byTrace = await fetchLogs({ limit: 10, trace_id: reference });
  const direct = byTrace.items.find((entry) => entry.trace_id === reference || entry.id === reference) ?? byTrace.items[0];
  if (direct) {
    return direct;
  }
  const byID = await fetchLogs({ limit: 1, id: reference });
  const fallback = byID.items.find((entry) => entry.id === reference || entry.trace_id === reference) ?? byID.items[0];
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

export function fetchClusterJoinTokens() {
  return unwrap<ClusterJoinTokenList>(apiClient.get('/cluster/join-tokens'));
}

export function createClusterJoinToken(payload: ClusterJoinTokenCreateRequest) {
  return unwrap<ClusterJoinTokenList['items'][number]>(apiClient.post('/cluster/join-tokens', payload));
}

export function revokeClusterJoinToken(id: string) {
  return unwrap<{ revoked: boolean; id: string }>(apiClient.delete(`/cluster/join-tokens/${encodeURIComponent(id)}`));
}

export function fetchClusterNodes() {
  return unwrap<ClusterNodeList>(apiClient.get('/cluster/nodes'));
}

export function rotateClusterNodeCertificate(nodeID: string, payload: ClusterNodeCertificateRotateRequest) {
  return unwrap<ClusterNodeCertificateRotateResponse>(apiClient.post(`/cluster/nodes/${encodeURIComponent(nodeID)}/rotate-certificate`, payload));
}

export function generateClusterAnsiblePackage(payload: ClusterAnsiblePlan) {
  return unwrap<ClusterAnsiblePackage>(apiClient.post('/cluster/deploy/ansible', payload));
}

export function checkClusterDeployment(payload: ClusterDeploymentRequest) {
  return unwrap<ClusterDeploymentCheckResponse>(apiClient.post('/cluster/deploy/check', payload, { timeout: 60_000 }));
}

export function runClusterDeployment(payload: ClusterDeploymentRequest) {
  return unwrap<ClusterDeploymentRunResult>(apiClient.post('/cluster/deploy/run', payload, { timeout: 180_000 }));
}

export function startClusterDeploymentTask(payload: ClusterDeploymentRequest) {
  return unwrap<ClusterDeploymentTask>(apiClient.post('/cluster/deploy/tasks', payload, { timeout: 15_000 }));
}

export function fetchClusterDeploymentTask(id: string) {
  return unwrap<ClusterDeploymentTask>(apiClient.get(`/cluster/deploy/tasks/${encodeURIComponent(id)}`));
}

export function fetchClusterDeploymentTasks() {
  return unwrap<ClusterDeploymentTaskList>(apiClient.get('/cluster/deploy/tasks'));
}

export function fetchClusterAudit() {
  return unwrap<ClusterAuditList>(apiClient.get('/cluster/audit'));
}

export function createClusterBootstrapPlan(payload: ClusterBootstrapPlanRequest) {
  return unwrap<ClusterBootstrapPlan>(apiClient.post('/cluster/orchestrate/bootstrap', payload));
}

export function startClusterRollingUpgrade(payload: ClusterRollingUpgradeRequest) {
  return unwrap<ClusterRollingJob>(apiClient.post('/cluster/orchestrate/rolling-upgrade', payload, { timeout: 15_000 }));
}

export function fetchClusterRollingUpgrade(id: string) {
  return unwrap<ClusterRollingJob>(apiClient.get(`/cluster/orchestrate/rolling-upgrade/${encodeURIComponent(id)}`));
}

export function fetchClusterRollingUpgrades() {
  return unwrap<{ items: ClusterRollingJob[]; total: number }>(apiClient.get('/cluster/orchestrate/rolling-upgrade'));
}

export function fetchClusterTrafficPeers(mode?: string, region?: string, stickyKey?: string) {
  const params = new URLSearchParams();
  if (mode) params.set('mode', mode);
  if (region) params.set('region', region);
  if (stickyKey) params.set('sticky_key', stickyKey);
  const query = params.toString();
  return unwrap<ClusterTrafficPeersResponse>(apiClient.get(`/cluster/traffic/peers${query ? `?${query}` : ''}`));
}

export function fetchClusterConsensus() {
  return unwrap<ClusterConsensusSnapshot>(apiClient.get('/cluster/consensus'));
}

export function proposeClusterConfigVersion(payload: { version: string; message?: string }) {
  return unwrap<ClusterConfigVersionRecord>(apiClient.post('/cluster/consensus/config-version', payload));
}

export function startClusterRollingRollback(id: string) {
  return unwrap<ClusterRollingJob>(apiClient.post(`/cluster/orchestrate/rolling-upgrade/${encodeURIComponent(id)}/rollback`, {}));
}

export function reportClusterTrafficPeer(nodeId: string, report: 'failure' | 'success') {
  return unwrap<{ ok: boolean; node_id: string; report: string }>(
    apiClient.post('/cluster/traffic/peers/report', { node_id: nodeId, report }),
  );
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

export function fetchNotifications(params: { page?: number; limit?: number; filter?: NotificationFilter } = {}) {
  return unwrap<NotificationList>(apiClient.get('/notifications', { params }));
}

export function updateNotification(id: string, patch: { read?: boolean; pinned?: boolean }) {
  return unwrap<Notification>(apiClient.patch(`/notifications/${encodeURIComponent(id)}`, patch));
}

export function markAllNotificationsRead() {
  return unwrap<{ updated: number }>(apiClient.post('/notifications/read-all', {}));
}

export function clearNotifications() {
  return unwrap<{ deleted: number }>(apiClient.delete('/notifications'));
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

export function disableUser2FA(id: string, password: string, code: string) {
	return unwrap<User>(apiClient.post(`/users/${id}/2fa/disable`, { password, code }));
}

export function recoverUser2FA(id: string, password: string, confirmUsername: string) {
	return unwrap<User>(apiClient.post(`/users/${id}/2fa/recover`, { password, confirm_username: confirmUsername }));
}

export function fetchSystemConfig() {
  return unwrap<SystemConfig>(apiClient.get('/system'));
}

export function fetchTimeSyncStatus() {
  return unwrap<TimeSyncStatus>(apiClient.get('/system/time-sync'));
}

export function reselectTimeSync() {
  return unwrap<TimeSyncStatus>(apiClient.post('/system/time-sync/reselect', {}));
}

export function syncTimeNow() {
  return unwrap<TimeSyncStatus>(apiClient.post('/system/time-sync/sync', {}));
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

export function fetchManagementAPITokens() {
  return unwrap<ManagementAPITokenList>(apiClient.get('/system/api-tokens'));
}

export function createManagementAPIToken(payload: CreateManagementAPITokenRequest) {
  return unwrap<CreateManagementAPITokenResponse>(apiClient.post('/system/api-tokens', payload));
}

export function revokeManagementAPIToken(id: string) {
  return unwrap<{ revoked: boolean }>(apiClient.delete(`/system/api-tokens/${encodeURIComponent(id)}`));
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
  return unwrap<{ ok: boolean; count: number }>(apiClient.post('/ip/threat-intel/test', {
    ...provider,
    provider_id: provider.id,
  }));
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

export function previewBlockPageConfig(payload: BlockPageConfig, signal?: AbortSignal) {
  return unwrap<BlockPagePreview>(apiClient.post('/block-pages/preview', payload, { signal }));
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
  const response = await authenticatedFetch('/api/ai/analyze/stream', '/ai/analyze/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reference, language }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, errorBody.code ?? 'AI_ANALYSIS_STREAM_FAILED', response.status, errorBody.traceID ?? traceID);
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

export async function analyzeEventsStream(
  payload: { limit?: number; action?: string; category?: string; client_ip?: string; trace_id?: string; start?: string; end?: string; language?: string },
  onItem?: (analysis: AttackAnalysis) => void,
  onTrace?: (event: AIAssistantTraceEvent) => void,
  signal?: AbortSignal,
) {
  const response = await authenticatedFetch('/api/ai/events/analyze/stream', '/ai/events/analyze/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, errorBody.code ?? 'AI_EVENTS_ANALYSIS_STREAM_FAILED', response.status, errorBody.traceID ?? traceID);
  }
  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json') || response.headers.get('x-cheesewaf-stream-fallback') === 'json') {
    const envelope = await response.json() as Envelope<AIEventsAnalysisResponse>;
    if (envelope.error) {
      throw new APIRequestError(envelope.error.message, envelope.error.code, response.status, envelope.error.event_id ?? envelope.error.trace_id ?? traceID);
    }
    return envelope.data as AIEventsAnalysisResponse;
  }
  if (!response.body) {
    throw new APIRequestError('AI events analysis stream is not available.', 'AI_EVENTS_ANALYSIS_STREAM_UNAVAILABLE', response.status, traceID);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalResult: AIEventsAnalysisResponse | null = null;
  const pendingItems: AttackAnalysis[] = [];
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
        } else if (event.event === 'item') {
          pendingItems.push(event.data as AttackAnalysis);
        } else if (event.event === 'done') {
          finalResult = event.data as AIEventsAnalysisResponse;
        } else if (event.event === 'error') {
          const errorPayload = event.data as { message?: string; code?: string; event_id?: string; trace_id?: string };
          throw new APIRequestError(errorPayload.message || 'AI events analysis stream failed.', errorPayload.code || 'AI_EVENTS_ANALYSIS_STREAM_FAILED', response.status, errorPayload.event_id ?? errorPayload.trace_id ?? traceID);
        }
      }
    }
    if (buffer.trim()) {
      const event = parseSSEBlock(buffer);
      if (event?.event === 'done') {
        finalResult = event.data as AIEventsAnalysisResponse;
      }
    }
  } catch (error) {
    if (error instanceof APIRequestError) {
      throw error;
    }
    if ((error as DOMException)?.name === 'AbortError') {
      throw new APIRequestError('AI events analysis was cancelled.', 'AI_EVENTS_ANALYSIS_CANCELLED', response.status, traceID);
    }
    throw new APIRequestError(
      streamInterruptedMessage('AI events analysis stream was interrupted before completion', error),
      'AI_EVENTS_ANALYSIS_STREAM_INTERRUPTED',
      response.status,
      traceID,
      error,
    );
  }
  if (!finalResult) {
    throw new APIRequestError(
      streamInterruptedMessage('AI events analysis stream ended without a final result', 'missing final done event'),
      'AI_EVENTS_ANALYSIS_STREAM_INCOMPLETE',
      response.status,
      traceID,
    );
  }
  for (const item of pendingItems) {
    onItem?.(item);
  }
  return finalResult;
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
  const response = await authenticatedFetch('/api/ai/assistant/stream', '/ai/assistant/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message, limit, language, deep_think: deepThink }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, errorBody.code ?? 'AI_ASSISTANT_STREAM_FAILED', response.status, errorBody.traceID ?? traceID);
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
    buffer += decoder.decode();
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
  const response = await authenticatedFetch(`/api/ai/tools/approvals/${encodeURIComponent(approvalID)}/continue/stream`, '/ai/tools/approvals/continue/stream', {
    method: 'POST',
    signal,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message, limit, language, deep_think: deepThink }),
  });
  const traceID = fetchResponseTraceID(response);
  if (!response.ok) {
    const errorBody = await readableFetchError(response);
    throw new APIRequestError(errorBody.message, errorBody.code ?? 'AI_APPROVAL_CONTINUE_FAILED', response.status, errorBody.traceID ?? traceID);
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
    buffer += decoder.decode();
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
    throw await reconcileApprovalStreamFailure(approvalID, response, traceID, error);
  }
  if (!finalReply) {
    throw await reconcileApprovalStreamFailure(approvalID, response, traceID, 'missing final done event');
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

export function fetchAIApprovals(params?: { status?: string }) {
  return unwrap<AIApprovalList | AIApprovalRequest[]>(apiClient.get('/ai/tools/approvals', { params })).then((data) => (
    Array.isArray(data) ? { items: data, total: data.length } : data
  ));
}

export function fetchAIApproval(id: string) {
  return unwrap<AIApprovalRequest>(apiClient.get(`/ai/tools/approvals/${encodeURIComponent(id)}`));
}

export function rejectAIApproval(id: string) {
  return unwrap<AIApprovalRequest>(apiClient.post(`/ai/tools/approvals/${encodeURIComponent(id)}/reject`, {}));
}

async function authenticatedFetch(input: RequestInfo | URL, requestURL: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  const method = String(init.method ?? 'GET').toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrf = getCSRFToken();
    if (csrf) {
      headers.set(csrfHeaderName, csrf);
    }
  }
  const response = await fetch(input, { ...init, headers, credentials: 'same-origin' });
  if (response.status === 401) {
    try {
      const payload = await response.clone().json();
      const code = apiErrorCode(payload);
      if (code && sessionInvalidErrorCodes.has(code)) {
        handleUnauthorizedAuthFailure();
      }
    } catch {
      // A 401 without the canonical API error contract is not enough to destroy local session state.
    }
  }
  return response;
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

async function reconcileApprovalStreamFailure(approvalID: string, response: Response, traceID: string | undefined, cause: unknown) {
  try {
    const approval = await fetchAIApproval(approvalID);
    return new APIRequestError(
      streamInterruptedMessage(`AI approval continuation stream ended while the server reports ${approval.status}`, cause),
      'AI_APPROVAL_CONTINUE_STATUS_RECONCILED',
      response.status,
      traceID,
      approval,
    );
  } catch (lookupError) {
    if (lookupError instanceof APIRequestError && lookupError.code === 'AI_APPROVAL_CONTINUE_STATUS_RECONCILED') {
      return lookupError;
    }
    return new APIRequestError(
      streamInterruptedMessage('AI approval continuation status could not be confirmed', cause),
      'AI_APPROVAL_CONTINUE_STATUS_UNKNOWN',
      response.status,
      traceID,
      lookupError,
    );
  }
}

async function readableFetchError(response: Response): Promise<{ message: string; code?: string; traceID?: string }> {
  const text = await response.text().catch(() => '');
  if (!text) {
    return { message: `${response.status} ${response.statusText}`, traceID: fetchResponseTraceID(response) };
  }
  try {
    const parsed = JSON.parse(text) as Envelope<unknown>;
    return {
      message: parsed.error?.message || text,
      code: apiErrorCode(parsed),
      traceID: parsed.error?.event_id ?? parsed.error?.trace_id ?? fetchResponseTraceID(response),
    };
  } catch {
    return { message: text, traceID: fetchResponseTraceID(response) };
  }
}

function streamInterruptedMessage(prefix: string, error: unknown) {
  const cause = error instanceof Error ? error.message : String(error || '');
  const detail = cause.trim() ? ` Cause: ${cause.trim()}.` : '';
  return `${prefix}.${detail} The server keeps the stream alive with heartbeats; check provider latency, reverse proxy buffering, or network stability.`;
}
