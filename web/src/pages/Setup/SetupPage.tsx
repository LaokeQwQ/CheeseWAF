import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  Cpu,
  Database,
  Eye,
  EyeOff,
  Gauge,
  Languages,
  LockKeyhole,
  Logs,
  ShieldCheck,
  Settings2,
  SunMoon,
  UserRound,
  XCircle,
} from 'lucide-react';
import {
  Badge,
  Button,
  Checkbox,
  Input,
  Label,
  RadioGroup,
  RadioGroupItem,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  toast,
} from '@/components/ui';
import { APIRequestError, apiClient, captureSetupTokenFromFragment, hasSetupToken, setSetupTokenForSession, setupAdmin, unwrapAPIResponse } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import i18n, { ensureLanguage, readPersistedLanguage } from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { themeOptions, type ThemeName } from '../../themes/tokens';
import { classifyPassword, passwordClassCount, passwordPolicyErrorKey } from '../../utils/passwordPolicy';
import { USERNAME_MAX, USERNAME_MIN, usernameErrorKey } from '../../utils/username';

/**
 * Admin listener / access strategy are operator-level knobs. The wizard is
 * served from that very listener, so exposing them here lets a first-time user
 * lock themselves out before the console ever loads. Both stay on backend
 * defaults and are documented in the review step instead.
 */
const DEFAULT_ADMIN_LISTEN = '127.0.0.1:9443';
const DEFAULT_ADMIN_STRATEGY = 'local';

const TYPING_INTERVAL_MS = 70;
const DELETING_INTERVAL_MS = 34;
const TYPEWRITER_HOLD_MS = 1500;

const STEP_LANGUAGE = 0;
const STEP_ENVIRONMENT = 1;
const STEP_PROFILE = 2;
const STEP_ACCOUNT = 3;
const STEP_INTEGRATIONS = 4;
const STEP_REVIEW = 5;
const STEP_DONE = 6;

type ProfileKey = 'smart' | 'low' | 'medium' | 'high' | 'custom';

type SuggestedConfig = {
  web_attack_level?: string;
  pipeline_budget_ms?: number;
  semantic_depth?: number;
};

type ProbeResult = {
  profile: ProfileKey;
  incomplete?: boolean;
  cpu_logical?: number;
  memory_total_mb?: number;
  memory_avail_mb?: number;
  disk_write_mbps?: number;
  disk_ok?: boolean;
  notes?: string[];
  suggested_config?: SuggestedConfig;
};

type CheckStatus = 'pass' | 'warn' | 'fail';

type SetupAccessState = 'checking' | 'probing' | 'required' | 'ready';
type SetupTokenErrorKey = 'setup.tokenRequired' | 'setup.tokenInvalid';

function initialSetupAccessState(): SetupAccessState {
  if (typeof window === 'undefined') return 'checking';
  const rawFragment = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  const fragmentToken = (new URLSearchParams(rawFragment).get('setup_token') ?? '').trim();
  return fragmentToken || hasSetupToken() ? 'probing' : 'required';
}

type EnvironmentCheck = {
  id: string;
  label: string;
  value: string;
  status: CheckStatus;
};

type ProfileOption = {
  value: ProfileKey;
  titleKey: string;
  descKey: string;
  overheadKey: string;
  webAttackLevel: string;
};

const PROFILE_OPTIONS: readonly ProfileOption[] = [
  {
    value: 'smart',
    titleKey: 'setup.profileSmart',
    descKey: 'setup.profileSmartDesc',
    overheadKey: 'setup.profileOverheadMinimal',
    webAttackLevel: 'smart',
  },
  {
    value: 'low',
    titleKey: 'setup.profileLow',
    descKey: 'setup.profileLowDesc',
    overheadKey: 'setup.profileOverheadLow',
    webAttackLevel: 'smart',
  },
  {
    value: 'medium',
    titleKey: 'setup.profileMedium',
    descKey: 'setup.profileMediumDesc',
    overheadKey: 'setup.profileOverheadMedium',
    webAttackLevel: 'smart',
  },
  {
    value: 'high',
    titleKey: 'setup.profileHigh',
    descKey: 'setup.profileHighDesc',
    overheadKey: 'setup.profileOverheadHigh',
    webAttackLevel: 'high',
  },
  {
    value: 'custom',
    titleKey: 'setup.profileCustom',
    descKey: 'setup.profileCustomDesc',
    overheadKey: 'setup.profileOverheadCustom',
    webAttackLevel: 'smart',
  },
];

const PROFILE_PRESET_OPTIONS = PROFILE_OPTIONS.filter((option) => option.value !== 'custom');

const PROFILE_RANK: Partial<Record<ProfileKey, number>> = {
  low: 0,
  smart: 1,
  medium: 2,
  high: 3,
};

const WEB_ATTACK_LEVEL_KEYS: Record<string, string> = {
  off: 'sites.levelOff',
  low: 'sites.levelLow',
  smart: 'sites.levelSmart',
  high: 'sites.levelHigh',
  strict: 'sites.levelStrict',
};

const LANGUAGE_OPTIONS = [
  { value: 'zh-CN', titleKey: 'setup.languageZh', noteKey: 'setup.languageZhNote' },
  { value: 'en-US', titleKey: 'setup.languageEn', noteKey: 'setup.languageEnNote' },
] as const;

const STATUS_KEYS: Record<CheckStatus, string> = {
  pass: 'setup.probeStatusPass',
  warn: 'setup.probeStatusWarn',
  fail: 'setup.probeStatusFail',
};

const STATUS_STYLES: Record<CheckStatus, string> = {
  pass: 'text-emerald-600 dark:text-emerald-400',
  warn: 'text-amber-600 dark:text-amber-400',
  fail: 'text-red-600 dark:text-red-400',
};

/**
 * Optional external integrations. None of them gate the install — the operator
 * can skip this step entirely.
 *
 * Backend facts a future maintainer needs (verified against the Go code, which
 * the wizard is not allowed to change):
 * - `setupDraftPatch` stores only non-secret checklist fields. Connection
 *   passwords and composed DSNs stay in this browser tab and only travel to
 *   the one-shot test endpoint.
 * - `dto.SetupRequest` only carries the administrator credentials, so the
 *   integrations step remains a checklist and does not claim to activate the
 *   runtime sinks during first install.
 * - Defaults below mirror configs/cheesewaf.yaml: postgresql.enabled=false,
 *   table=cheesewaf_logs (the wizard composes a DSN from separate fields);
 *   monitor.prometheus.path=/metrics, public=false;
 *   storage.victorialogs.enabled=false, endpoint="".
 */
type IntegrationsState = {
  postgresEnabled: boolean;
  postgresUsername: string;
  postgresPassword: string;
  postgresHost: string;
  postgresPort: string;
  postgresDatabase: string;
  postgresSSL: boolean;
  postgresTable: string;
  prometheusEnabled: boolean;
  prometheusPath: string;
  prometheusPublic: boolean;
  victoriaEnabled: boolean;
  victoriaEndpoint: string;
};

const DEFAULT_INTEGRATIONS: IntegrationsState = {
  postgresEnabled: false,
  postgresUsername: '',
  postgresPassword: '',
  postgresHost: '127.0.0.1',
  postgresPort: '5432',
  postgresDatabase: 'cheesewaf',
  postgresSSL: false,
  postgresTable: 'cheesewaf_logs',
  prometheusEnabled: false,
  prometheusPath: '/metrics',
  prometheusPublic: false,
  victoriaEnabled: false,
  victoriaEndpoint: '',
};

const HTTP_ENDPOINT_RE = /^https?:\/\//i;

type ConnectionTestStatus = 'idle' | 'testing' | 'success' | 'error';

type ConnectionTestState = {
  postgres: ConnectionTestStatus;
  victoria: ConnectionTestStatus;
};

function buildPostgresDSN(state: IntegrationsState): string {
  const username = encodeURIComponent(state.postgresUsername.trim());
  const password = encodeURIComponent(state.postgresPassword);
  const database = encodeURIComponent(state.postgresDatabase.trim());
  const rawHost = state.postgresHost.trim();
  const host = rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost;
  const sslmode = state.postgresSSL ? 'require' : 'disable';
  return `postgresql://${username}:${password}@${host}:${state.postgresPort.trim()}/${database}?sslmode=${sslmode}`;
}

/** Keep connection secrets and composed DSNs out of the setup draft API. */
function integrationsDraftPayload(state: IntegrationsState) {
  return {
    postgresEnabled: state.postgresEnabled,
    postgresDsn: '',
    postgresTable: state.postgresTable,
    prometheusEnabled: state.prometheusEnabled,
    prometheusPath: state.prometheusPath,
    prometheusPublic: state.prometheusPublic,
    victoriaEnabled: state.victoriaEnabled,
    victoriaEndpoint: state.victoriaEndpoint,
  };
}

/** Returns a resolved message when an enabled integration is filled in wrong. */
function validateIntegrations(state: IntegrationsState, t: TFunction): string | null {
  if (state.postgresEnabled) {
    if (!state.postgresUsername.trim() || !state.postgresHost.trim() || !state.postgresPort.trim() || !state.postgresDatabase.trim()) {
      return t('setup.integrationsPostgresFieldsRequired');
    }
    const port = Number(state.postgresPort.trim());
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return t('setup.integrationsPostgresPortInvalid');
    }
  }
  if (state.prometheusEnabled) {
    const path = state.prometheusPath.trim();
    if (!path) return t('setup.integrationsPathRequired');
    if (!path.startsWith('/')) return t('setup.integrationsPathInvalid');
  }
  if (state.victoriaEnabled) {
    const endpoint = state.victoriaEndpoint.trim();
    if (!endpoint) return t('setup.integrationsEndpointRequired');
    if (!HTTP_ENDPOINT_RE.test(endpoint)) return t('setup.integrationsEndpointInvalid');
  }
  return null;
}

type TouchedFields = { username: boolean; password: boolean; confirm: boolean };

function detectBrowserLanguage(): Language {
  const raw = typeof navigator === 'undefined' ? '' : navigator.language ?? '';
  return raw.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
}

function formatCount(value: number): string {
  return Number.isFinite(value) ? value.toLocaleString() : '—';
}

/** `usernameTooShort` / `usernameTooLong` interpolate {{min}} / {{max}}. */
function usernameError(raw: string, t: TFunction): string | null {
  const key = usernameErrorKey(raw);
  if (!key) return null;
  return t(key, { min: USERNAME_MIN, max: USERNAME_MAX });
}

/** 0 = empty, 1 = too short, 2 = too few character classes, 3 = good, 4 = strong. */
function passwordScore(password: string): number {
  if (!password) return 0;
  const length = [...password].length;
  if (length < 10) return 1;
  if (passwordClassCount(classifyPassword(password)) < 3) return 2;
  return length >= 16 ? 4 : 3;
}

const STRENGTH_KEYS = ['setup.strengthWeak', 'setup.strengthWeak', 'setup.strengthFair', 'setup.strengthGood', 'setup.strengthStrong'];

const STRENGTH_BAR_STYLES = ['bg-muted', 'bg-red-500', 'bg-orange-500', 'bg-yellow-400', 'bg-emerald-500'];

function buildEnvironmentChecks(probe: ProbeResult, t: TFunction): EnvironmentCheck[] {
  const cpu = probe.cpu_logical ?? 0;
  const totalMemory = probe.memory_total_mb ?? 0;
  const availableMemory = probe.memory_avail_mb ?? 0;
  const writeMbps = probe.disk_write_mbps ?? 0;
  const diskOk = probe.disk_ok === true;
  return [
    {
      id: 'cpu',
      label: t('setup.probeCpu'),
      value: t('setup.probeUnitCores', { value: formatCount(cpu) }),
      status: cpu >= 4 ? 'pass' : cpu >= 2 ? 'warn' : 'fail',
    },
    {
      id: 'memory_total',
      label: t('setup.probeMemoryTotal'),
      value: t('setup.probeUnitMB', { value: formatCount(totalMemory) }),
      status: totalMemory >= 8192 ? 'pass' : totalMemory >= 2048 ? 'warn' : 'fail',
    },
    {
      id: 'memory_avail',
      label: t('setup.probeMemoryAvail'),
      value: t('setup.probeUnitMB', { value: formatCount(availableMemory) }),
      status: availableMemory >= 4096 ? 'pass' : availableMemory >= 1024 ? 'warn' : 'fail',
    },
    {
      id: 'disk_write',
      label: t('setup.probeDiskWrite'),
      value: t('setup.probeUnitMBps', { value: writeMbps.toFixed(1) }),
      status: writeMbps >= 50 ? 'pass' : writeMbps >= 20 ? 'warn' : 'fail',
    },
    {
      id: 'disk_ok',
      label: t('setup.probeDiskOk'),
      value: diskOk ? t('setup.probeValueOk') : t('setup.probeValueFailed'),
      status: diskOk ? 'pass' : 'fail',
    },
    {
      id: 'integrity',
      label: t('setup.probeIntegrity'),
      value: probe.incomplete ? t('setup.probeIntegrityIncomplete') : t('setup.probeIntegrityComplete'),
      status: probe.incomplete ? 'warn' : 'pass',
    },
  ];
}

/**
 * Types `phrases` one after another, erasing between them. Used for the
 * language step so both languages are shown without ever mixing them on screen.
 */
function useTypewriter(phrases: string[], active: boolean) {
  const [index, setIndex] = useState(0);
  const [length, setLength] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    // Only tick on the language step; otherwise the timer re-renders the whole
    // wizard every few milliseconds while the operator is filling in forms.
    if (!active || phrases.length === 0) return;
    const text = phrases[index] ?? '';
    if (!deleting && length >= text.length) {
      if (phrases.length < 2) return;
      const timer = window.setTimeout(() => setDeleting(true), TYPEWRITER_HOLD_MS);
      return () => window.clearTimeout(timer);
    }
    if (deleting && length <= 0) {
      setDeleting(false);
      setIndex((current) => (current + 1) % phrases.length);
      return;
    }
    const timer = window.setTimeout(
      () => setLength((current) => Math.max(0, current + (deleting ? -1 : 1))),
      deleting ? DELETING_INTERVAL_MS : TYPING_INTERVAL_MS,
    );
    return () => window.clearTimeout(timer);
  }, [active, deleting, index, length, phrases]);

  const text = phrases[index] ?? '';
  return text.slice(0, Math.max(0, length));
}

export default function SetupPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const language = useAppStore((state) => state.language);
  const setLanguage = useAppStore((state) => state.setLanguage);
  const theme = useAppStore((state) => state.theme);
  const setTheme = useAppStore((state) => state.setTheme);
  const [step, setStep] = useState(STEP_LANGUAGE);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [done, setDone] = useState(false);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [profile, setProfile] = useState<ProfileKey>('smart');
  const [profileWarning, setProfileWarning] = useState('');
  const warnedProfileRef = useRef('');
  const [confirmed, setConfirmed] = useState(false);
  const [account, setAccount] = useState({ username: '', password: '', confirm: '' });
  const [touched, setTouched] = useState<TouchedFields>({ username: false, password: false, confirm: false });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [accountError, setAccountError] = useState('');
  const [integrations, setIntegrations] = useState<IntegrationsState>(DEFAULT_INTEGRATIONS);
  const [integrationsError, setIntegrationsError] = useState('');
  const [expandedIntegration, setExpandedIntegration] = useState<string | null>(null);
  const [showPostgresPassword, setShowPostgresPassword] = useState(false);
  const [connectionTests, setConnectionTests] = useState<ConnectionTestState>({ postgres: 'idle', victoria: 'idle' });
  // Keep the wizard and token gate hidden until the one-time token has been
  // captured and the server has accepted it. Rendering either surface before
  // that handshake caused a valid URL to briefly show the token-missing state,
  // and an invalid URL to briefly show the wizard before probe rejected it.
  // Resolve the first view synchronously. Deferring this to an effect made a
  // bare /setup visit briefly render a loading card before the token form.
  const [setupAccessState, setSetupAccessState] = useState<SetupAccessState>(initialSetupAccessState);
  const [setupTokenInput, setSetupTokenInput] = useState('');
  const [setupTokenError, setSetupTokenError] = useState<SetupTokenErrorKey | ''>('');
  const probeProfileInitializedRef = useRef(false);
  const setupProbeRequestRef = useRef<Promise<{ probe: ProbeResult }> | null>(null);
  const setupAccessReady = setupAccessState === 'ready';

  const typewriterPhrases = useMemo(
    () => [t('setup.languageTitleZh'), t('setup.languageTitleEn')],
    [t],
  );
  const typedTitle = useTypewriter(typewriterPhrases, step === STEP_LANGUAGE);
  const widestTypewriterPhrase = useMemo(
    () => typewriterPhrases.reduce((a, b) => (a.length > b.length ? a : b), ''),
    [typewriterPhrases],
  );

  /** Clears stale toasts/errors before showing the next wizard step. */
  const goToStep = (nextStep: number) => {
    toast.dismiss();
    setErrorMessage('');
    setAccountError('');
    setIntegrationsError('');
    setProfileWarning('');
    setStep(nextStep);
  };

  // First run only: follow the browser unless the operator already picked one.
  useEffect(() => {
    if (readPersistedLanguage()) return;
    const detected = detectBrowserLanguage();
    if (detected !== language) setLanguage(detected);
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      await ensureLanguage(language);
      if (cancelled) return;
      await i18n.changeLanguage(language);
      if (cancelled) return;
      document.documentElement.lang = language === 'zh-CN' ? 'zh-CN' : 'en';
    })();
    return () => {
      cancelled = true;
    };
  }, [language]);

  // Accept the one-time URL fragment without ever retaining it in the address
  // bar. A direct /setup visit stays at this gate until the operator pastes the
  // token; the value is kept only in the API client's process memory.
  useEffect(() => {
    const fragmentToken = captureSetupTokenFromFragment();
    setSetupAccessState((current) => {
      if (current === 'ready') return current;
      return fragmentToken || hasSetupToken() ? 'probing' : 'required';
    });
  }, []);

  function handleSetupTokenSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const token = setupTokenInput.trim();
    if (!token) {
      setSetupTokenError('setup.tokenRequired');
      return;
    }
    setSetupTokenForSession(token);
    setSetupTokenInput('');
    setSetupTokenError('');
    setSetupAccessState('probing');
  }

  useEffect(() => {
    if (setupAccessState !== 'probing') return;
    let cancelled = false;
    const probeRequest = setupProbeRequestRef.current ?? (setupProbeRequestRef.current = unwrapAPIResponse<{ probe: ProbeResult }>(apiClient.post('/setup/probe', {})));
    probeRequest
      .then((data) => {
        if (!cancelled) {
          setProbe(data.probe);
          setSetupTokenInput('');
          if (!probeProfileInitializedRef.current && data.probe?.profile && data.probe.profile !== 'custom') {
            setProfile(data.probe.profile);
            probeProfileInitializedRef.current = true;
          }
          setSetupAccessState('ready');
        }
      })
      .catch((err) => {
        if (err instanceof APIRequestError && err.code === 'SETUP_TOKEN_REQUIRED') {
          if (!cancelled) {
            setSetupAccessState('required');
            setSetupTokenError('setup.tokenInvalid');
            setProbe(null);
          }
          return;
        }
        // Probe is best-effort; operator can still complete setup with conservative defaults.
        if (!cancelled) {
          setProbe({ profile: 'low', incomplete: true, notes: ['probe unavailable'] });
          if (!probeProfileInitializedRef.current) {
            setProfile('low');
            probeProfileInitializedRef.current = true;
          }
          setSetupTokenInput('');
          setSetupAccessState('ready');
        }
      })
      .finally(() => {
        if (setupProbeRequestRef.current === probeRequest) {
          setupProbeRequestRef.current = null;
        }
      });
    return () => {
      cancelled = true;
    };
  }, [setupAccessState]);

  // Clear stale integration errors as soon as the operator edits any value.
  useEffect(() => {
    setIntegrationsError('');
    setConnectionTests({ postgres: 'idle', victoria: 'idle' });
  }, [integrations]);

  async function persistDraft(patch: Record<string, unknown>) {
    try {
      await unwrapAPIResponse(apiClient.patch('/setup/draft', patch));
    } catch {
      /* draft optional when probe failed */
    }
  }

  async function handleAccountSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccountError('');
    setTouched({ username: true, password: true, confirm: true });

    const username = account.username;
    // Client-side field errors are shown inline (and as a toast for visibility);
    // the form-level banner is reserved for server/API failures.
    const usernameMessage = usernameError(username, t);
    if (usernameMessage) {
      toast.error(usernameMessage);
      return;
    }
    if (!account.password) {
      toast.error(t('setup.passwordRequired'));
      return;
    }
    const policyKey = passwordPolicyErrorKey(account.password, username);
    if (policyKey) {
      toast.error(t(`passwordPolicy.${policyKey}`));
      return;
    }
    if (!account.confirm) {
      toast.error(t('setup.passwordConfirmRequired'));
      return;
    }
    if (account.confirm !== account.password) {
      toast.error(t('setup.passwordMismatch'));
      return;
    }

    setAccount((prev) => ({ ...prev, username }));
    await persistDraft({ username, password: account.password });
    goToStep(STEP_INTEGRATIONS);
  }

  async function handleIntegrationsNext() {
    const message = validateIntegrations(integrations, t);
    if (message) {
      setIntegrationsError(message);
      toast.error(message);
      return;
    }
    setIntegrationsError('');
    await persistDraft({ integrations: integrationsDraftPayload(integrations) });
    goToStep(STEP_REVIEW);
  }

  async function testPostgresConnection() {
    const message = validateIntegrations({ ...integrations, postgresEnabled: true }, t);
    if (message) {
      setIntegrationsError(message);
      toast.error(message);
      return;
    }
    setConnectionTests((prev) => ({ ...prev, postgres: 'testing' }));
    try {
      await unwrapAPIResponse(apiClient.post('/setup/integrations/postgres/test', {
        username: integrations.postgresUsername,
        password: integrations.postgresPassword,
        host: integrations.postgresHost,
        port: integrations.postgresPort,
        database: integrations.postgresDatabase,
        ssl: integrations.postgresSSL,
      }));
      setConnectionTests((prev) => ({ ...prev, postgres: 'success' }));
    } catch (err) {
      setConnectionTests((prev) => ({ ...prev, postgres: 'error' }));
      const message = err instanceof Error ? err.message : t('setup.integrationsTestFailed');
      setIntegrationsError(message);
      toast.error(message);
    }
  }

  async function testVictoriaConnection() {
    const endpoint = integrations.victoriaEndpoint.trim();
    if (!endpoint) {
      const message = t('setup.integrationsEndpointRequired');
      setIntegrationsError(message);
      toast.error(message);
      return;
    }
    if (!HTTP_ENDPOINT_RE.test(endpoint)) {
      const message = t('setup.integrationsEndpointInvalid');
      setIntegrationsError(message);
      toast.error(message);
      return;
    }
    setConnectionTests((prev) => ({ ...prev, victoria: 'testing' }));
    try {
      await unwrapAPIResponse(apiClient.post('/setup/integrations/victoria/test', { endpoint }));
      setConnectionTests((prev) => ({ ...prev, victoria: 'success' }));
    } catch (err) {
      setConnectionTests((prev) => ({ ...prev, victoria: 'error' }));
      const message = err instanceof Error ? err.message : t('setup.integrationsTestFailed');
      setIntegrationsError(message);
      toast.error(message);
    }
  }

  /** Skipping only turns the toggles off; typed values survive a later revisit. */
  function handleIntegrationsSkip() {
    setIntegrations((prev) => ({
      ...prev,
      postgresEnabled: false,
      prometheusEnabled: false,
      victoriaEnabled: false,
    }));
    goToStep(STEP_REVIEW);
  }

  async function handleComplete() {
    if (!confirmed) {
      const message = t('setup.confirmRequired');
      setErrorMessage(message);
      toast.error(message);
      return;
    }
    setLoading(true);
    setErrorMessage('');
    try {
      await persistDraft({
        profile,
        username: account.username,
        password: account.password,
        admin_listen: DEFAULT_ADMIN_LISTEN,
        admin_strategy: DEFAULT_ADMIN_STRATEGY,
        confirmed: true,
        integrations: integrationsDraftPayload(integrations),
      });
      await setupAdmin(account.username, account.password, DEFAULT_ADMIN_LISTEN, DEFAULT_ADMIN_STRATEGY);
      setDone(true);
      goToStep(STEP_DONE);
      window.setTimeout(() => navigate('/login', { replace: true }), 800);
    } catch (err) {
      const message = err instanceof Error ? err.message : t('setup.failed');
      setErrorMessage(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }

  const steps = [
    { title: t('setup.stepLanguage'), icon: <Languages size={16} /> },
    { title: t('setup.stepEnvironment'), icon: <Cpu size={16} /> },
    { title: t('setup.stepProfile'), icon: <ShieldCheck size={16} /> },
    { title: t('setup.stepAccount'), icon: <UserRound size={16} /> },
    { title: t('setup.stepIntegrations'), icon: <Database size={16} /> },
    { title: t('setup.stepReview'), icon: <CheckCircle2 size={16} /> },
    { title: t('setup.stepComplete'), icon: <LockKeyhole size={16} /> },
  ];

  const checks = useMemo(
    () => (probe ? buildEnvironmentChecks(probe, t) : []),
    [probe, t],
  );
  const passedChecks = checks.filter((check) => check.status === 'pass').length;
  const notes = probe?.notes ?? [];
  const recommendedProfile = probe?.profile && probe.profile !== 'custom' ? probe.profile : null;
  const recommendedOption = PROFILE_OPTIONS.find((option) => option.value === recommendedProfile) ?? null;
  const selectedOption = PROFILE_OPTIONS.find((option) => option.value === profile) ?? PROFILE_OPTIONS[0];
  const browserLanguage = detectBrowserLanguage();

  const usernameVisibleError = touched.username ? usernameError(account.username, t) : null;
  const passwordPolicyKey = passwordPolicyErrorKey(account.password, account.username);
  const passwordVisibleError = touched.password
    ? account.password === ''
      ? t('setup.passwordRequired')
      : passwordPolicyKey
        ? `passwordPolicy.${passwordPolicyKey}`
        : null
    : null;
  const confirmVisibleError =
    account.confirm === ''
      ? touched.confirm
        ? t('setup.passwordConfirmRequired')
        : null
      : account.confirm !== account.password
        ? t('setup.passwordMismatch')
        : t('setup.passwordMatch');

  const score = passwordScore(account.password);

  const enabledIntegrations = [
    integrations.postgresEnabled ? t('setup.integrationsPostgresTitle') : null,
    integrations.prometheusEnabled ? t('setup.integrationsPrometheusTitle') : null,
    integrations.victoriaEnabled ? t('setup.integrationsVictoriaTitle') : null,
  ].filter((value): value is string => value !== null);
  const integrationsSummary = enabledIntegrations.length
    ? enabledIntegrations.join(' · ')
    : t('setup.integrationsSummaryNone');

  function handleProfileSelect(nextProfile: ProfileKey) {
    setProfile(nextProfile);
  }

  useEffect(() => {
    if (step !== STEP_PROFILE || !recommendedProfile || profile === recommendedProfile) {
      warnedProfileRef.current = '';
      setProfileWarning('');
      return;
    }
    const warningID = `${recommendedProfile}:${profile}`;
    if (warnedProfileRef.current === warningID) return;
    warnedProfileRef.current = warningID;

    const recommendedRank = PROFILE_RANK[recommendedProfile];
    const selectedRank = PROFILE_RANK[profile];
    const recommendedTitle = t(
      PROFILE_OPTIONS.find((option) => option.value === recommendedProfile)?.titleKey ?? 'setup.profileCustom',
    );
    const selectedTitle = t(
      PROFILE_OPTIONS.find((option) => option.value === profile)?.titleKey ?? 'setup.profileCustom',
    );
    const warningKey = profile === 'custom'
      ? 'setup.profileWarningCustom'
      : recommendedRank != null && selectedRank != null
        ? selectedRank > recommendedRank
          ? 'setup.profileWarningHigher'
          : 'setup.profileWarningLower'
        : 'setup.profileWarningDifferent';
    const message = t(warningKey, { selected: selectedTitle, recommended: recommendedTitle });
    setProfileWarning(message);
    toast.warning(message);
  }, [profile, recommendedProfile, step]);

  function renderStatusIcon(status: CheckStatus) {
    if (status === 'pass') return <Check size={14} aria-hidden="true" />;
    if (status === 'warn') return <AlertTriangle size={14} aria-hidden="true" />;
    return <XCircle size={14} aria-hidden="true" />;
  }

  function renderPasswordField(
    id: string,
    field: 'password' | 'confirm',
    shown: boolean,
    onToggle: () => void,
  ) {
    return (
      <div className="relative">
        <Input
          id={id}
          type={shown ? 'text' : 'password'}
          autoComplete="new-password"
          placeholder="********"
          className="setup-input pr-10"
          value={account[field]}
          onChange={(event) => setAccount((prev) => ({ ...prev, [field]: event.target.value }))}
          onBlur={() => setTouched((prev) => ({ ...prev, [field]: true }))}
        />
        <button
          type="button"
          className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
          aria-label={shown ? t('setup.hidePassword') : t('setup.showPassword')}
          title={shown ? t('setup.hidePassword') : t('setup.showPassword')}
          onClick={onToggle}
        >
          {shown ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
        </button>
      </div>
    );
  }

  /** One collapsible integration row with a dedicated expand control and switch. */
  function renderIntegrationCard(
    id: string,
    title: string,
    desc: string,
    icon: ReactNode,
    enabled: boolean,
    onToggle: (value: boolean) => void,
    expanded: boolean,
    onExpand: () => void,
    fields: ReactNode,
  ) {
    return (
      <section className="setup-card rounded-2xl p-5" data-testid={`setup-integration-${id}`}>
        <div className="setup-integration-header">
          <button
            type="button"
            className="setup-integration-summary"
            aria-expanded={enabled && expanded}
            onClick={() => {
              if (!enabled) onToggle(true);
              onExpand();
            }}
          >
            <span className="mt-0.5 text-muted-foreground" aria-hidden="true">{icon}</span>
            <span className="min-w-0 text-left">
              <span className="block text-sm font-medium">{title}</span>
              <span className="mt-0.5 block text-xs text-muted-foreground">{desc}</span>
            </span>
          </button>
          <div className="setup-integration-controls">
            <button
              type="button"
              className="setup-integration-expand-button"
              aria-expanded={enabled && expanded}
              aria-label={`${title} · ${expanded ? t('setup.integrationsCollapse') : t('setup.integrationsExpand')}`}
              onClick={() => {
                if (!enabled) onToggle(true);
                onExpand();
              }}
            >
              <span className={`setup-integration-chevron${expanded ? ' is-open' : ''}`} aria-hidden="true">
                <ChevronDown size={17} />
              </span>
            </button>
            <Switch
              checked={enabled}
              onCheckedChange={onToggle}
              className="setup-integration-switch"
              aria-label={title}
              data-testid={`setup-integration-${id}-toggle`}
            />
          </div>
        </div>
        {enabled ? (
          <div className={`setup-integration-panel${expanded ? ' is-open' : ''}`} aria-hidden={!expanded}>
            <div className="setup-integration-fields grid gap-3">{fields}</div>
          </div>
        ) : null}
      </section>
    );
  }

  return (
    <main className="auth-screen setup-screen">
      <section className="auth-panel setup-panel">
        <div className="auth-brand setup-brand">
          <span className="setup-brand-mark"><BrandLogo className="setup-brand-logo" /></span>
          <div className="setup-brand-copy">
            <h1>{t('setup.title')}</h1>
            <p>{t('setup.subtitle')}</p>
          </div>
        </div>

        {setupAccessState === 'checking' || setupAccessState === 'probing' || setupAccessState === 'required' ? (
          <section
            className={`setup-card setup-token-card rounded-2xl p-5${setupAccessState === 'probing' || setupAccessState === 'checking' ? ' setup-token-checking' : ''}`}
            aria-live="polite"
            aria-busy={setupAccessState === 'probing' || setupAccessState === 'checking' ? true : undefined}
            role={setupAccessState === 'probing' || setupAccessState === 'checking' ? 'status' : undefined}
          >
            {setupAccessState === 'checking' || setupAccessState === 'probing' ? (
              <div className="setup-token-state-content">
                <span className="setup-token-checking-icon" aria-hidden="true"><Activity size={18} /></span>
                <div>
                  <h2 className="m-0 text-base font-semibold">{t('setup.tokenCheckingTitle')}</h2>
                  <p className="mt-1 text-sm text-muted-foreground">{t('setup.tokenCheckingHint')}</p>
                </div>
              </div>
            ) : (
              <div className="setup-token-state-content">
                <h2 className="m-0 text-base font-semibold">{t('setup.tokenTitle')}</h2>
                <p className="mt-1 text-sm text-muted-foreground">{t('setup.tokenHint')}</p>
                <form className="mt-3 grid gap-2" onSubmit={handleSetupTokenSubmit} noValidate>
                  <Label htmlFor="setup-token">{t('setup.tokenLabel')}</Label>
                  <Input
                    id="setup-token"
                    className="setup-input"
                    type="password"
                    inputMode="text"
                    autoComplete="off"
                    spellCheck={false}
                    value={setupTokenInput}
                    // Keep a rejected-token notice visible until the next
                    // verification attempt. Clearing it on every keystroke
                    // made the only actionable feedback flash away while an
                    // operator was correcting the value (and browser
                    // autofill/input events could make that look random).
                    onChange={(event) => { setSetupTokenInput(event.target.value); }}
                    placeholder={t('setup.tokenPlaceholder')}
                    aria-invalid={setupTokenError ? true : undefined}
                  />
                  {setupTokenError ? (
                    <div className="setup-token-error" role="alert" aria-live="assertive">
                      <AlertTriangle size={15} aria-hidden="true" />
                      <span>{t(setupTokenError)}</span>
                    </div>
                  ) : null}
                  <p className="m-0 text-xs text-muted-foreground">{t('setup.tokenSecurity')}</p>
                  <Button className="setup-btn-primary mt-1 w-full" type="submit">{t('setup.tokenContinue')}</Button>
                </form>
              </div>
            )}
          </section>
        ) : null}

        {setupAccessReady && step > STEP_LANGUAGE && (
          <>
            <ol className="setup-steps setup-stepper" aria-label={t('setup.progressLabel')}>
              {steps.map((item, index) => {
                const state = index < step ? 'complete' : index === step ? 'current' : 'upcoming';
                return (
                  <li
                    key={item.title}
                    data-state={state}
                    aria-current={index === step ? 'step' : undefined}
                    aria-label={t('setup.progressStep', {
                      current: index + 1,
                      total: steps.length,
                      title: item.title,
                    })}
                  >
                    <span className="setup-step-marker" aria-hidden="true">
                      <span className="setup-step-icon">
                        {state === 'complete' ? <Check size={16} /> : item.icon}
                      </span>
                    </span>
                    <span className="setup-step-label">{item.title}</span>
                  </li>
                );
              })}
            </ol>
            <p className="setup-progress-mobile" aria-live="polite">
              <span className="setup-progress-mobile-label">
                {t('setup.progressCurrent', {
                  current: step + 1,
                  total: steps.length,
                  title: steps[step]?.title ?? '',
                })}
              </span>
              <span className="setup-progress-mobile-track" aria-hidden="true">
                <span style={{ width: `${((step + 1) / steps.length) * 100}%` }} />
              </span>
            </p>
          </>
        )}

        {setupAccessReady && step === STEP_LANGUAGE && (
          <div className="auth-form setup-step-content">
            <div className="relative">
              {/* Invisible placeholder reserves the width/height of the longest
                  phrase so the typewriter does not reflow the language cards
                  while it types, deletes, or switches languages. */}
              <span
                className="invisible select-none text-xl font-semibold"
                aria-hidden="true"
              >
                {widestTypewriterPhrase}
              </span>
              <h2
                className="absolute left-0 top-0 m-0 text-xl font-semibold"
                data-testid="setup-language-typewriter"
                aria-label={typewriterPhrases.join(' / ')}
              >
                <span aria-hidden="true">{typedTitle}</span>
                <span className="ml-0.5 animate-pulse font-normal text-muted-foreground" aria-hidden="true">|</span>
              </h2>
            </div>
            <p className="text-sm text-muted-foreground">{t('setup.languageHint')}</p>
            <RadioGroup
              value={language}
              onValueChange={(value) => setLanguage(value as Language)}
              className="mt-2 grid gap-2"
            >
              {LANGUAGE_OPTIONS.map((option) => {
                const id = `setup-language-${option.value}`;
                return (
                  <div
                    key={option.value}
                    className={[
                      'setup-card-radio flex items-start gap-3 p-5',
                      language === option.value ? 'setup-card-radio-selected' : '',
                    ].join(' ')}
                    onClick={() => setLanguage(option.value)}
                  >
                    <RadioGroupItem value={option.value} id={id} className="mt-0.5" />
                    <Label htmlFor={id} className="grid cursor-pointer gap-0.5 font-normal leading-snug">
                      <span className="setup-language-title flex items-center gap-2 text-sm font-medium">
                        {t(option.titleKey)}
                        {browserLanguage === option.value ? (
                          <Badge variant="secondary">{t('setup.languageBrowserDefault')}</Badge>
                        ) : null}
                      </span>
                      <span className="setup-language-note text-xs text-muted-foreground" title={t(option.noteKey)}>{t(option.noteKey)}</span>
                    </Label>
                  </div>
                );
              })}
            </RadioGroup>
            <section className="setup-card setup-appearance-card mt-3 rounded-2xl p-4" aria-labelledby="setup-appearance-title">
              <div className="setup-appearance-copy">
                <span className="setup-appearance-icon" aria-hidden="true"><SunMoon size={17} /></span>
                <div className="min-w-0">
                  <h3 id="setup-appearance-title" className="m-0 text-sm font-semibold">{t('setup.appearanceTitle')}</h3>
                  <p className="m-0 mt-1 text-xs text-muted-foreground">{t('setup.appearanceHint')}</p>
                </div>
              </div>
              <Select value={theme} onValueChange={(value) => setTheme(value as ThemeName)}>
                <SelectTrigger className="setup-theme-select" aria-label={t('setup.appearanceTitle')}>
                  <span className="setup-theme-select-value">
                    <SunMoon size={15} aria-hidden="true" />
                    <SelectValue />
                  </span>
                </SelectTrigger>
                <SelectContent className="setup-theme-select-content">
                  {themeOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>{t(option.labelKey)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </section>
            <Button className="setup-btn-primary mt-3 w-full" onClick={() => goToStep(STEP_ENVIRONMENT)}>
              {t('common.next')}
            </Button>
          </div>
        )}

        {setupAccessReady && step === STEP_ENVIRONMENT && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.probeHint')}</p>
            {probe ? (
              <>
                <section className="setup-card mt-2 rounded-2xl bg-muted/20 p-4">
                  <h3 className="m-0 mb-2 text-sm font-semibold">{t('setup.probeChecklistTitle')}</h3>
                  <ul className="m-0 grid list-none gap-1.5 p-0">
                    {checks.map((check) => (
                      <li key={check.id} className="setup-check-row text-sm">
                        <span className={`setup-check-status inline-flex items-center gap-1 font-medium ${STATUS_STYLES[check.status]}`}>
                          {renderStatusIcon(check.status)}
                          {t(STATUS_KEYS[check.status])}
                        </span>
                        <span className="setup-check-label text-muted-foreground" title={check.label}>{check.label}</span>
                        <span className="setup-check-value font-medium tabular-nums">{check.value}</span>
                      </li>
                    ))}
                  </ul>
                </section>

                {probe.incomplete ? <p className="form-error" role="alert">{t('setup.probeIncomplete')}</p> : null}

                <section className="setup-card setup-recommendation-card mt-2 p-4" aria-label={t('setup.probeRecommendationTitle')}>
                  <div className="setup-recommendation-head">
                    <div className="setup-recommendation-title">
                      <span className="setup-recommendation-icon" aria-hidden="true"><Gauge size={18} /></span>
                      <div className="min-w-0">
                        <p className="setup-recommendation-eyebrow">{t('setup.probeRecommendationTitle')}</p>
                        <h3 className="m-0 text-lg font-semibold">
                          {recommendedOption ? t(recommendedOption.titleKey) : t('setup.profileCustom')}
                        </h3>
                      </div>
                    </div>
                    {recommendedOption ? <Badge variant="success">{t('setup.profileRecommended')}</Badge> : null}
                  </div>
                  <p className="setup-recommendation-copy">{t('setup.probeRecommendationReason')}</p>
                  <dl className="setup-recommendation-stats">
                    <div>
                      <dt>{t('setup.recommendationHost')}</dt>
                      <dd>
                        {probe.cpu_logical != null && probe.memory_total_mb != null
                          ? t('setup.recommendationHostValue', {
                            cpu: formatCount(probe.cpu_logical),
                            memory: formatCount(probe.memory_total_mb),
                          })
                          : t('setup.recommendationUnavailable')}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('setup.recommendationDepth')}</dt>
                      <dd>
                        {probe.suggested_config?.semantic_depth != null
                          ? t('setup.recommendationDepthValue', {
                            value: formatCount(probe.suggested_config.semantic_depth),
                          })
                          : t('setup.recommendationUnavailable')}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('setup.recommendationBudget')}</dt>
                      <dd>
                        {probe.suggested_config?.pipeline_budget_ms != null
                          ? t('setup.recommendationBudgetValue', {
                            value: formatCount(probe.suggested_config.pipeline_budget_ms),
                          })
                          : t('setup.recommendationUnavailable')}
                      </dd>
                    </div>
                  </dl>
                </section>

                {notes.length > 0 ? (
                  <section className="mt-2">
                    <h3 className="m-0 mb-1 text-sm font-semibold">{t('setup.probeNotesTitle')}</h3>
                    <ul className="m-0 grid list-none gap-1 p-0 text-xs text-muted-foreground">
                      {notes.map((note) => <li key={note}>{note}</li>)}
                    </ul>
                  </section>
                ) : null}
              </>
            ) : (
              <p>{t('common.loading')}</p>
            )}
            <div className="setup-action-row mt-3">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_LANGUAGE)}>{t('common.back')}</Button>
              <Button className="setup-btn-primary flex-1" disabled={!probe} onClick={() => goToStep(STEP_PROFILE)}>
                {t('common.next')}
              </Button>
            </div>
          </div>
        )}

        {setupAccessReady && step === STEP_PROFILE && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.profileHint')}</p>
            <RadioGroup
              value={profile}
              onValueChange={(value) => handleProfileSelect(value as ProfileKey)}
              className="mt-2 grid gap-2"
            >
              {PROFILE_PRESET_OPTIONS.map((option) => {
                const id = `setup-profile-${option.value}`;
                const isRecommended = option.value === recommendedProfile;
                return (
                  <div
                    key={option.value}
                    className={[
                      'setup-card-radio setup-profile-card flex items-start gap-3 p-5',
                      profile === option.value ? 'setup-card-radio-selected' : '',
                      isRecommended ? 'setup-profile-card-recommended' : '',
                    ].join(' ')}
                    data-recommended={isRecommended ? 'true' : undefined}
                    onClick={() => handleProfileSelect(option.value)}
                  >
                    <RadioGroupItem value={option.value} id={id} className="mt-0.5" />
                    <Label htmlFor={id} className="grid cursor-pointer gap-1 font-normal leading-snug">
                      <span className="setup-profile-option-title flex flex-wrap items-center gap-2 text-sm font-medium">
                        {t(option.titleKey)}
                        {isRecommended ? <Badge variant="success">{t('setup.profileRecommended')}</Badge> : null}
                      </span>
                      <span className="setup-profile-option-description text-xs text-muted-foreground">{t(option.descKey)}</span>
                      <span className="setup-profile-option-meta text-xs text-muted-foreground">
                        {t('setup.profileWebAttack')}: {t(WEB_ATTACK_LEVEL_KEYS[option.webAttackLevel] ?? 'sites.levelSmart')}
                        {' · '}
                        {t('setup.profileOverhead')}: {t(option.overheadKey)}
                      </span>
                    </Label>
                  </div>
                );
              })}
            </RadioGroup>
            <button
              type="button"
              className={[
                'setup-profile-advanced',
                profile === 'custom' ? 'setup-profile-advanced-selected' : '',
              ].join(' ')}
              aria-pressed={profile === 'custom'}
              data-testid="setup-profile-custom"
              onClick={() => handleProfileSelect('custom')}
            >
              <span className="setup-profile-advanced-icon" aria-hidden="true"><Settings2 size={17} /></span>
              <span className="setup-profile-advanced-copy">
                <span className="setup-profile-option-title text-sm font-medium">{t('setup.profileCustom')}</span>
                <span className="setup-profile-option-description text-xs text-muted-foreground">{t('setup.profileCustomDesc')}</span>
              </span>
              <span className="setup-profile-advanced-state" aria-hidden="true">{profile === 'custom' ? '✓' : '↗'}</span>
            </button>
            {profileWarning ? (
              <div className="setup-profile-warning" role="alert">
                <AlertTriangle size={15} aria-hidden="true" />
                <span>{profileWarning}</span>
              </div>
            ) : null}
            {recommendedOption ? (
              <p className="mt-2 text-xs text-muted-foreground">{t('setup.profileRecommendedReason')}</p>
            ) : null}
            <div className="setup-action-row mt-3">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_ENVIRONMENT)}>{t('common.back')}</Button>
              <Button
                className="setup-btn-primary flex-1"
                onClick={async () => { await persistDraft({ profile }); goToStep(STEP_ACCOUNT); }}
              >
                {t('setup.chooseProfile')}
              </Button>
            </div>
          </div>
        )}

        {setupAccessReady && step === STEP_ACCOUNT && (
          <form className="auth-form setup-step-content" onSubmit={handleAccountSubmit} noValidate>
            <div className="grid gap-1.5">
              <Label htmlFor="setup-username">{t('setup.username')}</Label>
              <Input
                id="setup-username"
                className="setup-input"
                placeholder={t('setup.usernamePlaceholder')}
                autoComplete="username"
                value={account.username}
                onChange={(event) => setAccount((prev) => ({ ...prev, username: event.target.value }))}
                onBlur={() => setTouched((prev) => ({ ...prev, username: true }))}
                aria-invalid={usernameVisibleError ? true : undefined}
              />
              <p className="text-xs text-muted-foreground">{t('setup.usernameFormat')}</p>
              {usernameVisibleError ? (
                <p className="text-xs text-destructive" role="alert">
                  {usernameVisibleError}
                </p>
              ) : null}
            </div>

            <div className="grid gap-1.5">
              <Label htmlFor="setup-password">{t('setup.password')}</Label>
              {renderPasswordField('setup-password', 'password', showPassword, () => setShowPassword((v) => !v))}
              <div
                className="setup-password-strength"
                role="progressbar"
                aria-label={t('setup.strengthLabel')}
                aria-valuemin={0}
                aria-valuemax={4}
                aria-valuenow={score}
              >
                <span
                  className={`setup-password-strength-fill ${STRENGTH_BAR_STYLES[score] ?? 'bg-muted'}`}
                  style={{ width: `${score * 25}%` }}
                  aria-hidden="true"
                />
              </div>
              <p className="text-xs text-muted-foreground">
                <span>{t('setup.strengthLabel')}</span>
                {': '}
                <span className="font-medium">{t(STRENGTH_KEYS[score])}</span>
              </p>
              <p className="text-xs text-muted-foreground">{t('users.passwordHint')}</p>
              {passwordVisibleError ? (
                <p className="text-xs text-destructive" role="alert">{t(passwordVisibleError)}</p>
              ) : null}
            </div>

            <div className="grid gap-1.5">
              <Label htmlFor="setup-password-confirm">{t('setup.passwordConfirm')}</Label>
              {renderPasswordField('setup-password-confirm', 'confirm', showConfirm, () => setShowConfirm((v) => !v))}
              {confirmVisibleError ? (
                <p
                  className={
                    confirmVisibleError === t('setup.passwordMatch')
                      ? 'text-xs text-emerald-600 dark:text-emerald-400'
                      : 'text-xs text-destructive'
                  }
                  role={confirmVisibleError === t('setup.passwordMatch') ? undefined : 'alert'}
                >
                  {confirmVisibleError}
                </p>
              ) : null}
            </div>

            {accountError ? <p className="form-error" role="alert">{accountError}</p> : null}
            <div className="setup-action-row mt-2">
              <Button type="button" className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_PROFILE)}>{t('common.back')}</Button>
              <Button type="submit" className="setup-btn-primary flex-1">{t('common.next')}</Button>
            </div>
          </form>
        )}

        {setupAccessReady && step === STEP_INTEGRATIONS && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.integrationsHint')}</p>
            <p className="m-0 text-xs text-muted-foreground">{t('setup.integrationsPostponed')}</p>

            {renderIntegrationCard(
              'postgres',
              t('setup.integrationsPostgresTitle'),
              t('setup.integrationsPostgresDesc'),
              <Database size={16} />,
              integrations.postgresEnabled,
              (value) => {
                setIntegrations((prev) => ({ ...prev, postgresEnabled: value }));
                if (value) setExpandedIntegration('postgres');
                else if (expandedIntegration === 'postgres') setExpandedIntegration(null);
              },
              expandedIntegration === 'postgres',
              () => setExpandedIntegration((current) => current === 'postgres' ? null : 'postgres'),
              <>
                <div className="setup-integration-grid">
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-username">{t('setup.integrationsPostgresUsername')}</Label>
                    <Input
                      id="setup-postgres-username"
                      className="setup-input"
                      value={integrations.postgresUsername}
                      placeholder={t('setup.integrationsPostgresUsernamePlaceholder')}
                      autoComplete="username"
                      onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresUsername: event.target.value }))}
                    />
                  </div>
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-password">{t('setup.integrationsPostgresPassword')}</Label>
                    <div className="relative">
                      <Input
                        id="setup-postgres-password"
                        className="setup-input pr-10"
                        type={showPostgresPassword ? 'text' : 'password'}
                        value={integrations.postgresPassword}
                        placeholder={t('setup.integrationsPostgresPasswordPlaceholder')}
                        autoComplete="current-password"
                        onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresPassword: event.target.value }))}
                      />
                      <button
                        type="button"
                        className="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
                        aria-label={showPostgresPassword ? t('setup.hidePassword') : t('setup.showPassword')}
                        title={showPostgresPassword ? t('setup.hidePassword') : t('setup.showPassword')}
                        onClick={() => setShowPostgresPassword((visible) => !visible)}
                      >
                        {showPostgresPassword ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
                      </button>
                    </div>
                  </div>
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-host">{t('setup.integrationsPostgresHost')}</Label>
                    <Input
                      id="setup-postgres-host"
                      className="setup-input"
                      value={integrations.postgresHost}
                      placeholder={t('setup.integrationsPostgresHostPlaceholder')}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresHost: event.target.value }))}
                    />
                  </div>
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-port">{t('setup.integrationsPostgresPort')}</Label>
                    <Input
                      id="setup-postgres-port"
                      className="setup-input"
                      inputMode="numeric"
                      value={integrations.postgresPort}
                      placeholder={t('setup.integrationsPostgresPortPlaceholder')}
                      autoComplete="off"
                      onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresPort: event.target.value }))}
                    />
                  </div>
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-database">{t('setup.integrationsPostgresDatabase')}</Label>
                    <Input
                      id="setup-postgres-database"
                      className="setup-input"
                      value={integrations.postgresDatabase}
                      placeholder={t('setup.integrationsPostgresDatabasePlaceholder')}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresDatabase: event.target.value }))}
                    />
                  </div>
                  <div className="grid gap-1.5">
                    <Label htmlFor="setup-postgres-table">{t('setup.integrationsPostgresTable')}</Label>
                    <Input
                      id="setup-postgres-table"
                      className="setup-input"
                      value={integrations.postgresTable}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresTable: event.target.value }))}
                    />
                  </div>
                </div>
                <div className="setup-checkbox-row">
                  <Checkbox
                    id="setup-postgres-ssl"
                    checked={integrations.postgresSSL}
                    onCheckedChange={(value) => setIntegrations((prev) => ({ ...prev, postgresSSL: value === true }))}
                  />
                  <Label htmlFor="setup-postgres-ssl" className="setup-checkbox-label font-normal leading-snug">
                    {t('setup.integrationsPostgresSSL')}
                  </Label>
                </div>
                <div className="setup-integration-actions">
                  <Button
                    type="button"
                    className="setup-btn-secondary setup-integration-test"
                    variant="outline"
                    disabled={connectionTests.postgres === 'testing'}
                    onClick={testPostgresConnection}
                  >
                    {connectionTests.postgres === 'testing' ? t('setup.integrationsTesting') : t('setup.integrationsTestConnection')}
                  </Button>
                  {connectionTests.postgres === 'success' ? <span className="setup-connection-status is-success" role="status"><CheckCircle2 size={15} />{t('setup.integrationsConnected')}</span> : null}
                  {connectionTests.postgres === 'error' ? <span className="setup-connection-status is-error" role="status"><AlertTriangle size={15} />{t('setup.integrationsTestFailed')}</span> : null}
                </div>
              </>,
            )}

            {renderIntegrationCard(
              'prometheus',
              t('setup.integrationsPrometheusTitle'),
              t('setup.integrationsPrometheusDesc'),
              <Activity size={16} />,
              integrations.prometheusEnabled,
              (value) => {
                setIntegrations((prev) => ({ ...prev, prometheusEnabled: value }));
                if (value) setExpandedIntegration('prometheus');
                else if (expandedIntegration === 'prometheus') setExpandedIntegration(null);
              },
              expandedIntegration === 'prometheus',
              () => setExpandedIntegration((current) => current === 'prometheus' ? null : 'prometheus'),
              <>
                <div className="grid gap-1.5">
                  <Label htmlFor="setup-prometheus-path">{t('setup.integrationsPrometheusPath')}</Label>
                  <Input
                    id="setup-prometheus-path"
                    className="setup-input"
                    value={integrations.prometheusPath}
                    placeholder={t('setup.integrationsPrometheusPathPlaceholder')}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(event) => setIntegrations((prev) => ({ ...prev, prometheusPath: event.target.value }))}
                  />
                </div>
                <div className="setup-checkbox-row">
                  <Checkbox
                    id="setup-prometheus-public"
                    checked={integrations.prometheusPublic}
                    onCheckedChange={(value) => setIntegrations((prev) => ({ ...prev, prometheusPublic: value === true }))}
                  />
                  <Label htmlFor="setup-prometheus-public" className="setup-checkbox-label font-normal leading-snug">
                    {t('setup.integrationsPrometheusPublic')}
                  </Label>
                </div>
              </>,
            )}

            {renderIntegrationCard(
              'victoria',
              t('setup.integrationsVictoriaTitle'),
              t('setup.integrationsVictoriaDesc'),
              <Logs size={16} />,
              integrations.victoriaEnabled,
              (value) => {
                setIntegrations((prev) => ({ ...prev, victoriaEnabled: value }));
                if (value) setExpandedIntegration('victoria');
                else if (expandedIntegration === 'victoria') setExpandedIntegration(null);
              },
              expandedIntegration === 'victoria',
              () => setExpandedIntegration((current) => current === 'victoria' ? null : 'victoria'),
              <>
                <div className="grid gap-1.5">
                  <Label htmlFor="setup-victoria-endpoint">{t('setup.integrationsVictoriaEndpoint')}</Label>
                  <Input
                    id="setup-victoria-endpoint"
                    className="setup-input"
                    value={integrations.victoriaEndpoint}
                    placeholder={t('setup.integrationsVictoriaEndpointPlaceholder')}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(event) => setIntegrations((prev) => ({ ...prev, victoriaEndpoint: event.target.value }))}
                  />
                </div>
                <div className="setup-integration-actions">
                  <Button
                    type="button"
                    className="setup-btn-secondary setup-integration-test"
                    variant="outline"
                    disabled={connectionTests.victoria === 'testing'}
                    onClick={testVictoriaConnection}
                  >
                    {connectionTests.victoria === 'testing' ? t('setup.integrationsTesting') : t('setup.integrationsTestConnection')}
                  </Button>
                  {connectionTests.victoria === 'success' ? <span className="setup-connection-status is-success" role="status"><CheckCircle2 size={15} />{t('setup.integrationsConnected')}</span> : null}
                  {connectionTests.victoria === 'error' ? <span className="setup-connection-status is-error" role="status"><AlertTriangle size={15} />{t('setup.integrationsTestFailed')}</span> : null}
                </div>
              </>,
            )}

            {integrationsError ? <p className="form-error" role="alert">{integrationsError}</p> : null}

            <div className="setup-action-row setup-action-row-three mt-3">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_ACCOUNT)}>{t('common.back')}</Button>
              <Button className="setup-btn-secondary" variant="outline" onClick={handleIntegrationsSkip}>{t('setup.integrationsSkip')}</Button>
              <Button className="setup-btn-primary flex-1" onClick={handleIntegrationsNext}>{t('common.next')}</Button>
            </div>
          </div>
        )}

        {setupAccessReady && step === STEP_REVIEW && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.reviewHint')}</p>
            <section className="setup-card mt-2 rounded-2xl p-4">
              <h3 className="m-0 mb-2 text-sm font-semibold">{t('setup.summaryTitle')}</h3>
              <dl className="m-0 grid gap-1.5 text-sm">
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryLanguage')}</dt>
                  <dd className="m-0 ml-auto font-medium">
                    {t(language === 'zh-CN' ? 'setup.languageZh' : 'setup.languageEn')}
                  </dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryAppearance')}</dt>
                  <dd className="m-0 ml-auto font-medium">{t(themeOptions.find((option) => option.value === theme)?.labelKey ?? 'themes.system')}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryProfile')}</dt>
                  <dd className="m-0 ml-auto font-medium">{t(selectedOption.titleKey)}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryWebAttack')}</dt>
                  <dd className="m-0 ml-auto font-medium">
                    {t(WEB_ATTACK_LEVEL_KEYS[selectedOption.webAttackLevel] ?? 'sites.levelSmart')}
                  </dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryUsername')}</dt>
                  <dd className="m-0 ml-auto font-medium">{account.username}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryPassword')}</dt>
                  <dd className="m-0 ml-auto font-medium">{t('setup.summaryPasswordSet')}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryEnvironment')}</dt>
                  <dd className="m-0 ml-auto font-medium">
                    {t('setup.summaryEnvironmentValue', { passed: passedChecks, total: checks.length })}
                  </dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.summaryIntegrations')}</dt>
                  <dd className="m-0 ml-auto text-right font-medium">{integrationsSummary}</dd>
                </div>
              </dl>
              {enabledIntegrations.length > 0 ? (
                <p className="m-0 mt-2 text-xs text-muted-foreground">{t('setup.integrationsDeferred')}</p>
              ) : null}
            </section>

            <section className="setup-card mt-2 rounded-2xl border-dashed p-4">
              <h3 className="m-0 mb-1 text-sm font-semibold">{t('setup.advancedTitle')}</h3>
              <p className="m-0 text-xs text-muted-foreground">
                {t('setup.advancedHint', { listen: DEFAULT_ADMIN_LISTEN, strategy: t('setup.strategyLocal') })}
              </p>
              <dl className="m-0 mt-2 grid gap-1 text-xs">
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.adminListen')}</dt>
                  <dd className="m-0 ml-auto font-medium">{DEFAULT_ADMIN_LISTEN}</dd>
                </div>
                <div className="flex gap-3">
                  <dt className="text-muted-foreground">{t('setup.adminStrategy')}</dt>
                  <dd className="m-0 ml-auto font-medium">{t('setup.strategyLocal')}</dd>
                </div>
              </dl>
            </section>

            <div className="mt-3 flex items-start gap-2">
              <Checkbox
                id="setup-confirm"
                checked={confirmed}
                onCheckedChange={(value) => setConfirmed(value === true)}
              />
              <Label htmlFor="setup-confirm" className="font-normal leading-snug">
                {t('setup.confirmCheck')}
              </Label>
            </div>
            <div className="setup-action-row mt-3">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_INTEGRATIONS)}>{t('common.back')}</Button>
              <Button className="setup-btn-primary flex-1" loading={loading} disabled={!confirmed || done} onClick={handleComplete}>
                {t('setup.complete')}
              </Button>
            </div>
          </div>
        )}

        {setupAccessReady && step === STEP_DONE && done && (
          <div className="auth-form setup-step-content justify-items-center gap-2 py-2 text-center" role="status">
            <CheckCircle2 className="setup-success-mark text-emerald-600 dark:text-emerald-400" size={30} aria-hidden="true" />
            <h2 className="m-0 text-lg font-semibold">{t('setup.completeTitle')}</h2>
            <p className="form-success">{t('setup.success')}</p>
          </div>
        )}

        {errorMessage && <p className="form-error" role="alert">{errorMessage}</p>}
      </section>
    </main>
  );
}
