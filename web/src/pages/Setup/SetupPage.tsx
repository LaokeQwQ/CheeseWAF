import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Cpu,
  Database,
  Eye,
  EyeOff,
  Languages,
  LockKeyhole,
  Logs,
  ShieldCheck,
  UserRound,
  XCircle,
} from 'lucide-react';
import {
  Badge,
  Button,
  Checkbox,
  Input,
  Label,
  Progress,
  RadioGroup,
  RadioGroupItem,
  Switch,
  toast,
} from '@/components/ui';
import { apiClient, setupAdmin, unwrapAPIResponse } from '../../api/client';
import BrandLogo from '../../components/BrandLogo';
import i18n, { ensureLanguage, readPersistedLanguage } from '../../i18n';
import { useAppStore, type Language } from '../../stores';
import { classifyPassword, passwordClassCount, passwordPolicyErrorKey } from '../../utils/passwordPolicy';

/**
 * Admin listener / access strategy are operator-level knobs. The wizard is
 * served from that very listener, so exposing them here lets a first-time user
 * lock themselves out before the console ever loads. Both stay on backend
 * defaults and are documented in the review step instead.
 */
const DEFAULT_ADMIN_LISTEN = '127.0.0.1:9443';
const DEFAULT_ADMIN_STRATEGY = 'local';

const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const USERNAME_ALLOWED = /^[A-Za-z][A-Za-z0-9._-]*$/;

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
 * - `setupDraftPatch` (internal/api/handler/setup_wizard.go) only accepts
 *   profile / custom / username / password / admin_listen / admin_strategy /
 *   confirmed, and `dto.SetupRequest` only carries the admin credentials. So
 *   these values are *not* persisted server-side today.
 * - `decode()` (internal/api/handler/handler.go) uses a plain
 *   `json.Decoder` without `DisallowUnknownFields`, so sending `integrations`
 *   in the draft PATCH is safe — it is simply ignored until the backend grows
 *   the field. That is why the step labels itself as "recorded, applied later"
 *   instead of promising the config takes effect here.
 * - Defaults below mirror configs/cheesewaf.yaml: postgresql.enabled=false,
 *   table=cheesewaf_logs; monitor.prometheus.path=/metrics, public=false;
 *   storage.victorialogs.enabled=false, endpoint="".
 */
type IntegrationsState = {
  postgresEnabled: boolean;
  postgresDsn: string;
  postgresTable: string;
  prometheusEnabled: boolean;
  prometheusPath: string;
  prometheusPublic: boolean;
  victoriaEnabled: boolean;
  victoriaEndpoint: string;
};

const DEFAULT_INTEGRATIONS: IntegrationsState = {
  postgresEnabled: false,
  postgresDsn: '',
  postgresTable: 'cheesewaf_logs',
  prometheusEnabled: false,
  prometheusPath: '/metrics',
  prometheusPublic: false,
  victoriaEnabled: false,
  victoriaEndpoint: '',
};

const POSTGRES_DSN_RE = /^postgres(ql)?:\/\//i;
const HTTP_ENDPOINT_RE = /^https?:\/\//i;

/** Returns a resolved message when an enabled integration is filled in wrong. */
function validateIntegrations(state: IntegrationsState, t: TFunction): string | null {
  if (state.postgresEnabled) {
    const dsn = state.postgresDsn.trim();
    if (!dsn) return t('setup.integrationsDsnRequired');
    if (!POSTGRES_DSN_RE.test(dsn)) return t('setup.integrationsDsnInvalid');
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

/** Returns an i18n key under `setup.*`, or null when the username is usable. */
function usernameErrorKey(raw: string): string | null {
  const value = raw.trim();
  if (!value) return 'setup.usernameRequired';
  if (!/^[A-Za-z]/.test(value)) return 'setup.usernameMustStartWithLetter';
  if (!USERNAME_ALLOWED.test(value)) return 'setup.usernameInvalidChars';
  if ([...value].length < USERNAME_MIN) return 'setup.usernameTooShort';
  if ([...value].length > USERNAME_MAX) return 'setup.usernameTooLong';
  if (!/[A-Za-z0-9]$/.test(value)) return 'setup.usernameMustEndAlnum';
  return null;
}

/**
 * `usernameTooShort` / `usernameTooLong` interpolate {{min}} / {{max}}, so the
 * key has to be resolved with the bounds or the operator reads a raw
 * placeholder.
 */
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

const STRENGTH_BAR_STYLES = ['bg-muted', 'bg-red-500', 'bg-amber-500', 'bg-sky-500', 'bg-emerald-500'];

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
  const [step, setStep] = useState(STEP_LANGUAGE);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [done, setDone] = useState(false);
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [profile, setProfile] = useState<ProfileKey>('smart');
  const [confirmed, setConfirmed] = useState(false);
  const [account, setAccount] = useState({ username: '', password: '', confirm: '' });
  const [touched, setTouched] = useState<TouchedFields>({ username: false, password: false, confirm: false });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [accountError, setAccountError] = useState('');
  const [integrations, setIntegrations] = useState<IntegrationsState>(DEFAULT_INTEGRATIONS);
  const [integrationsError, setIntegrationsError] = useState('');

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

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await unwrapAPIResponse<{ probe: ProbeResult }>(apiClient.post('/setup/probe', {}));
        if (!cancelled) {
          setProbe(data.probe);
          if (data.probe?.profile && data.probe.profile !== 'custom') {
            setProfile(data.probe.profile);
          }
        }
      } catch {
        // Probe is best-effort; operator can still complete setup with conservative defaults.
        if (!cancelled) {
          setProbe({ profile: 'low', incomplete: true, notes: ['probe unavailable'] });
          setProfile('low');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Clear stale integration errors as soon as the operator edits any value.
  useEffect(() => {
    setIntegrationsError('');
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

    const username = account.username.trim();
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
    await persistDraft({ integrations });
    goToStep(STEP_REVIEW);
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
        integrations,
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
  const passwordPolicyKey = passwordPolicyErrorKey(account.password, account.username.trim());
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

  /** One collapsible integration row: header + toggle, fields only when on. */
  function renderIntegrationCard(
    id: string,
    title: string,
    desc: string,
    icon: ReactNode,
    enabled: boolean,
    onToggle: (value: boolean) => void,
    fields: ReactNode,
  ) {
    return (
      <section className="setup-card rounded-2xl p-5" data-testid={`setup-integration-${id}`}>
        <div className="flex items-start gap-3">
          <span className="mt-0.5 text-muted-foreground" aria-hidden="true">{icon}</span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-medium">{title}</span>
              <Switch
                checked={enabled}
                onCheckedChange={onToggle}
                aria-label={title}
                data-testid={`setup-integration-${id}-toggle`}
              />
            </div>
            <p className="m-0 mt-0.5 text-xs text-muted-foreground">{desc}</p>
          </div>
        </div>
        {enabled ? <div className="mt-2.5 grid gap-2">{fields}</div> : null}
      </section>
    );
  }

  return (
    <main className="auth-screen setup-screen">
      <section className="auth-panel setup-panel">
        <div className="auth-brand">
          <span><BrandLogo /></span>
          <div>
            <h1>{t('setup.title')}</h1>
            <p>{t('setup.subtitle')}</p>
          </div>
        </div>

        {step > STEP_LANGUAGE && (
          <ol className="setup-steps flex flex-wrap items-center gap-3 text-sm">
            {steps.map((item, index) => (
              <li
                key={item.title}
                className={[
                  'inline-flex items-center gap-1.5',
                  index === step ? 'font-semibold text-foreground' : 'text-muted-foreground',
                  index < step ? 'opacity-80' : '',
                ].filter(Boolean).join(' ')}
                aria-current={index === step ? 'step' : undefined}
              >
                <span aria-hidden="true">{item.icon}</span>
                <span>{item.title}</span>
                {index < steps.length - 1 ? <span className="ml-1 text-muted-foreground/60" aria-hidden="true">/</span> : null}
              </li>
            ))}
          </ol>
        )}

        {step === STEP_LANGUAGE && (
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
                  >
                    <RadioGroupItem value={option.value} id={id} className="mt-0.5" />
                    <Label htmlFor={id} className="grid cursor-pointer gap-0.5 font-normal leading-snug">
                      <span className="flex items-center gap-2 text-sm font-medium">
                        {t(option.titleKey)}
                        {browserLanguage === option.value ? (
                          <Badge variant="secondary">{t('setup.languageBrowserDefault')}</Badge>
                        ) : null}
                      </span>
                      <span className="text-xs text-muted-foreground">{t(option.noteKey)}</span>
                    </Label>
                  </div>
                );
              })}
            </RadioGroup>
            <Button className="setup-btn-primary mt-3 w-full" onClick={() => goToStep(STEP_ENVIRONMENT)}>
              {t('common.next')}
            </Button>
          </div>
        )}

        {step === STEP_ENVIRONMENT && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.probeHint')}</p>
            {probe ? (
              <>
                <section className="setup-card mt-2 rounded-2xl bg-muted/20 p-4">
                  <h3 className="m-0 mb-2 text-sm font-semibold">{t('setup.probeChecklistTitle')}</h3>
                  <ul className="m-0 grid list-none gap-1.5 p-0">
                    {checks.map((check) => (
                      <li key={check.id} className="flex items-center gap-2 text-sm">
                        <span className={`inline-flex items-center gap-1 font-medium ${STATUS_STYLES[check.status]}`}>
                          {renderStatusIcon(check.status)}
                          {t(STATUS_KEYS[check.status])}
                        </span>
                        <span className="text-muted-foreground">{check.label}</span>
                        <span className="ml-auto font-medium tabular-nums">{check.value}</span>
                      </li>
                    ))}
                  </ul>
                </section>

                {probe.incomplete ? <p className="form-error" role="alert">{t('setup.probeIncomplete')}</p> : null}

                <section className="setup-card mt-2 rounded-2xl bg-muted/30 p-4">
                  <h3 className="m-0 mb-1 text-sm font-semibold">{t('setup.probeRecommendationTitle')}</h3>
                  <p className="m-0 text-sm">
                    {recommendedOption ? t(recommendedOption.titleKey) : t('setup.profileCustom')}
                  </p>
                  <p className="m-0 text-xs text-muted-foreground">{t('setup.probeRecommendationReason')}</p>
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
            <div className="mt-3 flex gap-2">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_LANGUAGE)}>{t('common.back')}</Button>
              <Button className="setup-btn-primary flex-1" disabled={!probe} onClick={() => goToStep(STEP_PROFILE)}>
                {t('common.next')}
              </Button>
            </div>
          </div>
        )}

        {step === STEP_PROFILE && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.profileHint')}</p>
            <RadioGroup
              value={profile}
              onValueChange={(value) => setProfile(value as ProfileKey)}
              className="mt-2 grid gap-2"
            >
              {PROFILE_OPTIONS.map((option) => {
                const id = `setup-profile-${option.value}`;
                const isRecommended = option.value === recommendedProfile;
                return (
                  <div
                    key={option.value}
                    className={[
                      'setup-card-radio flex items-start gap-3 p-5',
                      profile === option.value ? 'setup-card-radio-selected' : '',
                    ].join(' ')}
                  >
                    <RadioGroupItem value={option.value} id={id} className="mt-0.5" />
                    <Label htmlFor={id} className="grid cursor-pointer gap-1 font-normal leading-snug">
                      <span className="flex flex-wrap items-center gap-2 text-sm font-medium">
                        {t(option.titleKey)}
                        {isRecommended ? <Badge variant="success">{t('setup.profileRecommended')}</Badge> : null}
                      </span>
                      <span className="text-xs text-muted-foreground">{t(option.descKey)}</span>
                      <span className="text-xs text-muted-foreground">
                        {t('setup.profileWebAttack')}: {t(WEB_ATTACK_LEVEL_KEYS[option.webAttackLevel] ?? 'sites.levelSmart')}
                        {' · '}
                        {t('setup.profileOverhead')}: {t(option.overheadKey)}
                      </span>
                    </Label>
                  </div>
                );
              })}
            </RadioGroup>
            {recommendedOption ? (
              <p className="mt-2 text-xs text-muted-foreground">{t('setup.profileRecommendedReason')}</p>
            ) : null}
            <div className="mt-3 flex gap-2">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_ENVIRONMENT)}>{t('common.back')}</Button>
              <Button
                className="setup-btn-primary flex-1"
                onClick={async () => { await persistDraft({ profile }); goToStep(STEP_ACCOUNT); }}
              >
                {t('common.next')}
              </Button>
            </div>
          </div>
        )}

        {step === STEP_ACCOUNT && (
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
              <Progress value={score * 25} className="h-1.5" aria-hidden="true" />
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
            <div className="mt-2 flex gap-2">
              <Button type="button" className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_PROFILE)}>{t('common.back')}</Button>
              <Button type="submit" className="setup-btn-primary flex-1">{t('common.next')}</Button>
            </div>
          </form>
        )}

        {step === STEP_INTEGRATIONS && (
          <div className="auth-form setup-step-content">
            <p>{t('setup.integrationsHint')}</p>
            <p className="m-0 text-xs text-muted-foreground">{t('setup.integrationsPostponed')}</p>

            {renderIntegrationCard(
              'postgres',
              t('setup.integrationsPostgresTitle'),
              t('setup.integrationsPostgresDesc'),
              <Database size={16} />,
              integrations.postgresEnabled,
              (value) => setIntegrations((prev) => ({ ...prev, postgresEnabled: value })),
              <>
                <div className="grid gap-1.5">
                  <Label htmlFor="setup-postgres-dsn">{t('setup.integrationsPostgresDsn')}</Label>
                  <Input
                    id="setup-postgres-dsn"
                    className="setup-input"
                    value={integrations.postgresDsn}
                    placeholder={t('setup.integrationsPostgresDsnPlaceholder')}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(event) => setIntegrations((prev) => ({ ...prev, postgresDsn: event.target.value }))}
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
              </>,
            )}

            {renderIntegrationCard(
              'prometheus',
              t('setup.integrationsPrometheusTitle'),
              t('setup.integrationsPrometheusDesc'),
              <Activity size={16} />,
              integrations.prometheusEnabled,
              (value) => setIntegrations((prev) => ({ ...prev, prometheusEnabled: value })),
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
                <div className="flex items-start gap-2">
                  <Checkbox
                    id="setup-prometheus-public"
                    checked={integrations.prometheusPublic}
                    onCheckedChange={(value) => setIntegrations((prev) => ({ ...prev, prometheusPublic: value === true }))}
                  />
                  <Label htmlFor="setup-prometheus-public" className="font-normal leading-snug">
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
              (value) => setIntegrations((prev) => ({ ...prev, victoriaEnabled: value })),
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
              </div>,
            )}

            {integrationsError ? <p className="form-error" role="alert">{integrationsError}</p> : null}

            <div className="mt-3 flex flex-wrap gap-2">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_ACCOUNT)}>{t('common.back')}</Button>
              <Button className="setup-btn-secondary" variant="outline" onClick={handleIntegrationsSkip}>{t('setup.integrationsSkip')}</Button>
              <Button className="setup-btn-primary flex-1" onClick={handleIntegrationsNext}>{t('common.next')}</Button>
            </div>
          </div>
        )}

        {step === STEP_REVIEW && (
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
            <div className="mt-3 flex gap-2">
              <Button className="setup-btn-secondary" variant="outline" onClick={() => goToStep(STEP_INTEGRATIONS)}>{t('common.back')}</Button>
              <Button className="setup-btn-primary flex-1" loading={loading} disabled={!confirmed || done} onClick={handleComplete}>
                {t('setup.complete')}
              </Button>
            </div>
          </div>
        )}

        {step === STEP_DONE && done && (
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
