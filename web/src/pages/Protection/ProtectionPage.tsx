import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Bot, ExternalLink, Globe2, Pencil, Plus, ShieldAlert, TimerReset, Trash2 } from 'lucide-react';
import {
  Badge,
  Button,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Spinner,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  toast,
} from '@/components/ui';
import { fetchProtection, updateACLProtection, updateBotProtection, updateIPProtection, updateProtectionPolicy, updateRateLimit } from '../../api/client';
import type { ACLRule, ProtectionCaptchaType, ProtectionConfig } from '../../types/api';
import { displayAction } from '../../utils/display';
import './ProtectionPage.css';

type CaptchaTypeOption = ProtectionCaptchaType | 'image' | 'slider';

const captchaTypes: CaptchaTypeOption[] = ['random', 'pow', 'image', 'slider', 'curve_draw', 'curve_slider', 'shape_slider', 'rotate', 'restore_slider', 'angle', 'scratch', 'text_click', 'icon_click'];

const fallback: ProtectionConfig = {
  policy: { web_attack: 'smart', api_security: 'smart', bot_cc: 'smart', threat_intel: 'smart' },
  ip: {
    whitelist: [],
    blacklist: [],
    access_rules: [],
    reputation_overrides: {},
    tags: {},
    threat_intel: [],
    providers: [],
    geoip: { enabled: false, database: '', precision_database: '', blocked_countries: [], country_cidrs: {} },
  },
  ratelimit: { enabled: false, default: { requests: 0, window: '', burst: 0 } },
  bot: {
    enabled: false,
    js_challenge: false,
    captcha: false,
    captcha_type: 'pow',
    captcha_types: ['pow'],
    captcha_challenge_ttl: '5m',
    captcha_failure_window: '10m',
    captcha_block_duration: '30m',
    captcha_escalation_types: ['pow'],
    captcha_binding_mode: 'strict_ip_ua',
    captcha_policy_version: 'v1',
    captcha_max_attempts: 5,
    image_captcha_length: 6,
    image_captcha_width: 220,
    image_captcha_height: 86,
    image_captcha_audio_limit: 6,
    slider_captcha_width: 320,
    slider_captcha_height: 150,
    slider_captcha_piece: 42,
    slider_captcha_tolerance: 6,
    slider_captcha_min_drag: '450ms',
    slider_captcha_track_required: true,
    captcha_mobile_type: 'pow',
    challenge_difficulty: 4,
    altcha_max_number: 75000,
    altcha_header_name: 'X-CheeseWAF-Altcha',
    waiting_room: false,
    waiting_room_max_active: 1000,
    waiting_room_ttl: '5m',
    challenge_ttl: '',
    cookie_name: '',
    secret: '',
    path_prefixes: [],
    exempt_path_prefixes: [],
    allowed_user_agents: [],
    suspicious_user_agents: [],
  },
  acl: { enabled: false, rules: [] },
};
type DurationUnit = 'ms' | 's' | 'm' | 'h' | 'd';

const geoRegionGroups = [
  { labelKey: 'geo.continents.asia', codes: ['CN', 'HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'IN', 'VN', 'TH', 'MY', 'ID', 'PH', 'PK', 'KZ'] },
  { labelKey: 'geo.continents.europe', codes: ['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'SE', 'CH', 'PL', 'RO', 'CZ', 'AT', 'HU', 'FI', 'DK', 'NO', 'IE', 'GR', 'PT', 'BE', 'SK', 'SI'] },
  { labelKey: 'geo.continents.northAmerica', codes: ['US', 'CA', 'MX'] },
  { labelKey: 'geo.continents.southAmerica', codes: ['BR', 'AR', 'CL', 'CO', 'PE', 'VE'] },
  { labelKey: 'geo.continents.africa', codes: ['ZA', 'EG', 'NG', 'KE', 'MA'] },
  { labelKey: 'geo.continents.oceania', codes: ['AU', 'NZ'] },
  { labelKey: 'geo.continents.middleEast', codes: ['AE', 'SA', 'IL', 'IR', 'TR'] },
] as const;

type BotFormState = {
  enabled: boolean;
  jsChallenge: boolean;
  captcha: boolean;
  captchaType: string;
  captchaTypes: string[];
  captchaChallengeTtl: number | string;
  captchaFailureWindow: number | string;
  captchaBlockDuration: number | string;
  captchaEscalationTypes: string[];
  captchaBindingMode: string;
  captchaPolicyVersion: string;
  captchaMaxAttempts: number;
  imageCaptchaLength: number;
  imageCaptchaWidth: number;
  imageCaptchaHeight: number;
  imageCaptchaAudioLimit: number;
  sliderCaptchaWidth: number;
  sliderCaptchaHeight: number;
  sliderCaptchaPiece: number;
  sliderCaptchaTolerance: number;
  sliderCaptchaMinDrag: number | string;
  sliderCaptchaTrackRequired: boolean;
  captchaMobileType: string;
  challengeDifficulty: number;
  altchaMaxNumber: number;
  altchaHeaderName: string;
  waitingRoom: boolean;
  waitingRoomMaxActive: number;
  waitingRoomTtl: number | string;
  challengeTtl: number | string;
  cookieName: string;
  secret: string;
  protectedPaths: string[];
  exemptPaths: string[];
  allowedUA: string[];
  suspiciousUA: string[];
};

function botToForm(bot: ProtectionConfig['bot']): BotFormState {
  return {
    enabled: bot.enabled,
    jsChallenge: bot.js_challenge,
    captcha: bot.captcha,
    captchaType: bot.captcha_type || 'pow',
    captchaTypes: bot.captcha_types?.length ? bot.captcha_types : ['pow'],
    captchaChallengeTtl: bot.captcha_challenge_ttl || '5m',
    captchaFailureWindow: bot.captcha_failure_window || '10m',
    captchaBlockDuration: bot.captcha_block_duration || '30m',
    captchaEscalationTypes: bot.captcha_escalation_types ?? [],
    captchaBindingMode: bot.captcha_binding_mode || 'strict_ip_ua',
    captchaPolicyVersion: bot.captcha_policy_version || 'v1',
    captchaMaxAttempts: bot.captcha_max_attempts,
    imageCaptchaLength: bot.image_captcha_length,
    imageCaptchaWidth: bot.image_captcha_width,
    imageCaptchaHeight: bot.image_captcha_height,
    imageCaptchaAudioLimit: bot.image_captcha_audio_limit,
    sliderCaptchaWidth: bot.slider_captcha_width,
    sliderCaptchaHeight: bot.slider_captcha_height,
    sliderCaptchaPiece: bot.slider_captcha_piece,
    sliderCaptchaTolerance: bot.slider_captcha_tolerance,
    sliderCaptchaMinDrag: bot.slider_captcha_min_drag || '450ms',
    sliderCaptchaTrackRequired: bot.slider_captcha_track_required ?? true,
    captchaMobileType: bot.captcha_mobile_type || 'pow',
    challengeDifficulty: bot.challenge_difficulty,
    altchaMaxNumber: bot.altcha_max_number,
    altchaHeaderName: bot.altcha_header_name,
    waitingRoom: bot.waiting_room,
    waitingRoomMaxActive: bot.waiting_room_max_active,
    waitingRoomTtl: bot.waiting_room_ttl || '5m',
    challengeTtl: bot.challenge_ttl || '30m',
    cookieName: bot.cookie_name,
    secret: bot.secret,
    protectedPaths: bot.path_prefixes,
    exemptPaths: bot.exempt_path_prefixes,
    allowedUA: bot.allowed_user_agents,
    suspiciousUA: bot.suspicious_user_agents,
  };
}

export default function ProtectionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, error, isError, isLoading, refetch } = useQuery({ queryKey: ['protection'], queryFn: fetchProtection, retry: false });
  const protection = useMemo(() => normalizeProtection(data), [data]);
  const policyItems = [
    { field: 'web_attack', label: t('sites.webAttackLevel'), hint: t('protection.webAttackHint') },
    { field: 'api_security', label: t('sites.apiSecurityLevel'), hint: t('protection.apiSecurityHint') },
    { field: 'bot_cc', label: t('sites.botCCLevel'), hint: t('protection.botCCHint') },
    { field: 'threat_intel', label: t('sites.threatIntelLevel'), hint: t('protection.threatIntelHint') },
  ] as const;
  const [policyDraft, setPolicyDraft] = useState(protection.policy);
  const [policySaving, setPolicySaving] = useState<Record<string, boolean>>({});
  useEffect(() => { setPolicyDraft(protection.policy); }, [protection.policy]);

  const [botForm, setBotForm] = useState<BotFormState>(() => botToForm(protection.bot));
  useEffect(() => { setBotForm(botToForm(protection.bot)); }, [protection.bot]);

  const [geoForm, setGeoForm] = useState({
    enabled: protection.ip.geoip.enabled,
    database: protection.ip.geoip.database,
    precisionDatabase: protection.ip.geoip.precision_database,
    blocked: protection.ip.geoip.blocked_countries,
  });
  useEffect(() => {
    setGeoForm({
      enabled: protection.ip.geoip.enabled,
      database: protection.ip.geoip.database,
      precisionDatabase: protection.ip.geoip.precision_database,
      blocked: protection.ip.geoip.blocked_countries,
    });
  }, [protection.ip.geoip]);

  const [rateForm, setRateForm] = useState({
    enabled: protection.ratelimit.enabled,
    requests: protection.ratelimit.default.requests,
    burst: protection.ratelimit.default.burst,
  });
  useEffect(() => {
    setRateForm({
      enabled: protection.ratelimit.enabled,
      requests: protection.ratelimit.default.requests,
      burst: protection.ratelimit.default.burst,
    });
  }, [protection.ratelimit]);

  const policyMutation = useMutation({
    mutationFn: updateProtectionPolicy,
    onSuccess: (_result, variables) => {
      const fields = Object.keys(variables) as Array<keyof typeof variables>;
      setPolicySaving((prev) => { const next = { ...prev }; for (const f of fields) delete next[f]; return next; });
      queryClient.invalidateQueries({ queryKey: ['protection'] });
    },
    onError: (mutationError, variables) => {
      const fields = Object.keys(variables) as Array<keyof typeof variables>;
      setPolicySaving((prev) => { const next = { ...prev }; for (const f of fields) delete next[f]; return next; });
      setPolicyDraft(protection.policy);
      toast.error(mutationError.message);
    },
  });
  const ipMutation = useMutation({
    mutationFn: updateIPProtection,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['protection'] }); toast.success(t('common.saved')); },
    onError: (err) => toast.error(err instanceof Error ? err.message : t('common.requestFailed')),
  });
  const rateMutation = useMutation({
    mutationFn: updateRateLimit,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['protection'] }); toast.success(t('common.saved')); },
    onError: (err) => toast.error(err instanceof Error ? err.message : t('common.requestFailed')),
  });
  const botMutation = useMutation({
    mutationFn: updateBotProtection,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['protection'] }); toast.success(t('common.saved')); },
    onError: (err) => toast.error(err instanceof Error ? err.message : t('common.requestFailed')),
  });
  const aclMutation = useMutation({
    mutationFn: updateACLProtection,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['protection'] }); toast.success(t('common.saved')); },
    onError: (err) => toast.error(err instanceof Error ? err.message : t('common.requestFailed')),
  });
  const [aclDraft, setAclDraft] = useState<ACLRule | null>(null);
  const [aclEditing, setAclEditing] = useState(false);
  const [aclUnsaved, setAclUnsaved] = useState(false);
  const [deleteAclId, setDeleteAclId] = useState<string | null>(null);
  const aclBusyId = aclMutation.isPending
    ? (Array.isArray(aclMutation.variables?.rules)
      ? (() => {
          const nextRules = aclMutation.variables!.rules;
          const prevRules = protection.acl.rules;
          if (nextRules.length !== prevRules.length) {
            const deleted = prevRules.find((rule) => !nextRules.some((item) => item.id === rule.id));
            if (deleted) return deleted.id;
            const added = nextRules.find((rule) => !prevRules.some((item) => item.id === rule.id));
            if (added) return added.id;
          }
          const changed = nextRules.find((rule) => {
            const prev = prevRules.find((item) => item.id === rule.id);
            return prev && (prev.enabled !== rule.enabled || prev.name !== rule.name || prev.action !== rule.action || prev.path_prefix !== rule.path_prefix || prev.method !== rule.method);
          });
          return changed?.id ?? nextRules[0]?.id ?? null;
        })()
      : null)
    : null;

  function startNewACL() {
    const id = typeof crypto.randomUUID === 'function'
      ? `acl-${crypto.randomUUID()}`
      : `acl-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    setAclDraft({ id, name: '', method: '', path_prefix: '', header: '', header_value: '', action: 'block', severity: 'medium', enabled: true });
    setAclEditing(true);
    setAclUnsaved(true);
  }
  function editACL(rule: ACLRule) {
    setAclDraft({ ...rule });
    setAclEditing(true);
    setAclUnsaved(false);
  }
  function saveACLDraft() {
    if (!aclDraft) return;
    const name = aclDraft.name.trim();
    if (!name) {
      toast.warning(t('rules.nameHint', { defaultValue: t('rules.namePlaceholder') }));
      return;
    }
    const nextDraft = { ...aclDraft, name };
    const rules = [...protection.acl.rules];
    const idx = rules.findIndex((r) => r.id === nextDraft.id);
    if (idx >= 0) rules[idx] = nextDraft;
    else rules.push(nextDraft);
    aclMutation.mutate({ ...protection.acl, rules }, {
      onSuccess: () => {
        setAclDraft(null);
        setAclEditing(false);
        setAclUnsaved(false);
      },
    });
  }
  function toggleACL(id: string, enabled: boolean) {
    const rules = protection.acl.rules.map((rule) => (rule.id === id ? { ...rule, enabled } : rule));
    aclMutation.mutate({ ...protection.acl, rules });
  }
  function deleteACL(id: string) {
    setDeleteAclId(id);
  }
  function confirmDeleteACL() {
    if (!deleteAclId) return;
    const id = deleteAclId;
    setDeleteAclId(null);
    const rules = protection.acl.rules.filter((r) => r.id !== id);
    aclMutation.mutate({ ...protection.acl, rules });
    if (aclDraft?.id === id) {
      setAclDraft(null);
      setAclEditing(false);
      setAclUnsaved(false);
    }
  }

  function saveBot(event: FormEvent) {
    event.preventDefault();
    const values = botForm;
    botMutation.mutate({
      ...protection.bot,
      enabled: values.enabled ?? protection.bot.enabled,
      js_challenge: values.jsChallenge ?? protection.bot.js_challenge,
      captcha: values.captcha ?? protection.bot.captcha,
      captcha_type: values.captchaType ?? protection.bot.captcha_type,
      captcha_types: asArr(values.captchaTypes ?? protection.bot.captcha_types) as ProtectionCaptchaType[],
      captcha_challenge_ttl: durationToNanoseconds(values.captchaChallengeTtl, protection.bot.captcha_challenge_ttl || '5m'),
      captcha_failure_window: durationToNanoseconds(values.captchaFailureWindow, protection.bot.captcha_failure_window || '10m'),
      captcha_block_duration: durationToNanoseconds(values.captchaBlockDuration, protection.bot.captcha_block_duration || '30m'),
      captcha_escalation_types: asArr(values.captchaEscalationTypes ?? protection.bot.captcha_escalation_types) as ProtectionCaptchaType[],
      captcha_binding_mode: values.captchaBindingMode ?? protection.bot.captcha_binding_mode,
      captcha_policy_version: String(values.captchaPolicyVersion ?? protection.bot.captcha_policy_version ?? '').trim() || 'v1',
      captcha_max_attempts: values.captchaMaxAttempts ?? protection.bot.captcha_max_attempts,
      image_captcha_length: values.imageCaptchaLength ?? protection.bot.image_captcha_length,
      image_captcha_width: values.imageCaptchaWidth ?? protection.bot.image_captcha_width,
      image_captcha_height: values.imageCaptchaHeight ?? protection.bot.image_captcha_height,
      image_captcha_audio_limit: values.imageCaptchaAudioLimit ?? protection.bot.image_captcha_audio_limit,
      slider_captcha_width: values.sliderCaptchaWidth ?? protection.bot.slider_captcha_width,
      slider_captcha_height: values.sliderCaptchaHeight ?? protection.bot.slider_captcha_height,
      slider_captcha_piece: values.sliderCaptchaPiece ?? protection.bot.slider_captcha_piece,
      slider_captcha_tolerance: values.sliderCaptchaTolerance ?? protection.bot.slider_captcha_tolerance,
      slider_captcha_min_drag: durationToNanoseconds(values.sliderCaptchaMinDrag, protection.bot.slider_captcha_min_drag || '450ms'),
      slider_captcha_track_required: values.sliderCaptchaTrackRequired ?? protection.bot.slider_captcha_track_required,
      captcha_mobile_type: values.captchaMobileType ?? protection.bot.captcha_mobile_type,
      challenge_difficulty: values.challengeDifficulty ?? protection.bot.challenge_difficulty,
      altcha_max_number: values.altchaMaxNumber ?? protection.bot.altcha_max_number,
      altcha_header_name: values.altchaHeaderName ?? protection.bot.altcha_header_name,
      waiting_room: values.waitingRoom ?? protection.bot.waiting_room,
      waiting_room_max_active: values.waitingRoomMaxActive ?? protection.bot.waiting_room_max_active,
      waiting_room_ttl: durationToNanoseconds(values.waitingRoomTtl, protection.bot.waiting_room_ttl || '5m'),
      challenge_ttl: durationToNanoseconds(values.challengeTtl, protection.bot.challenge_ttl || '30m'),
      cookie_name: values.cookieName ?? protection.bot.cookie_name,
      secret: values.secret ?? protection.bot.secret,
      path_prefixes: asArr(values.protectedPaths ?? protection.bot.path_prefixes),
      exempt_path_prefixes: asArr(values.exemptPaths ?? protection.bot.exempt_path_prefixes),
      allowed_user_agents: asArr(values.allowedUA ?? protection.bot.allowed_user_agents),
      suspicious_user_agents: asArr(values.suspiciousUA ?? protection.bot.suspicious_user_agents),
    });
  }

  function saveGeo(event: FormEvent) {
    event.preventDefault();
    ipMutation.mutate({
      ...protection.ip,
      geoip: {
        ...protection.ip.geoip,
        enabled: geoForm.enabled,
        database: String(geoForm.database ?? '').trim(),
        precision_database: String(geoForm.precisionDatabase ?? '').trim(),
        blocked_countries: splitList(geoForm.blocked).map((item) => item.toUpperCase()),
      },
    });
  }

  function saveRate(event: FormEvent) {
    event.preventDefault();
    rateMutation.mutate({
      enabled: rateForm.enabled,
      default: { ...protection.ratelimit.default, requests: rateForm.requests, burst: rateForm.burst },
    });
  }

  const patchBot = <K extends keyof BotFormState>(key: K, value: BotFormState[K]) => {
    setBotForm((c) => ({ ...c, [key]: value }));
  };

  if (isLoading) {
    return (
      <section className="page-surface protection-page">
        <header className="page-header"><div><h1>{t('protection.title')}</h1><p>{t('protection.subtitle')}</p></div></header>
        <section className="panel protection-page-state" aria-label={t('common.loading')}><Spinner /></section>
      </section>
    );
  }

  if (isError) {
    return (
      <section className="page-surface protection-page">
        <header className="page-header"><div><h1>{t('protection.title')}</h1><p>{t('protection.subtitle')}</p></div></header>
        <div className="inline-error protection-load-error" role="alert">
          <span>{queryErrorMessage(error, t('common.noData'))}</span>
          <Button size="sm" variant="outline" onClick={() => refetch()}>{t('common.retry')}</Button>
        </div>
      </section>
    );
  }

  return (
    <section className="page-surface protection-page">
      <header className="page-header">
        <div>
          <h1>{t('protection.title')}</h1>
          <p>{t('protection.subtitle')}</p>
        </div>
      </header>

      <section className="panel policy-panel">
        <div className="panel-heading">
          <h2><ShieldAlert size={16} /> {t('protection.policy')}</h2>
          <span className="policy-current-summary">{t('protection.policyDefaultHint')}</span>
        </div>
        <div className="policy-level-grid">
          {policyItems.map((item) => {
            const currentLevel = policyDraft[item.field] || 'smart';
            const isSaving = policySaving[item.field];
            return (
              <div className={`policy-level-card policy-level-card-${currentLevel}`} key={item.field}>
                <div className="policy-level-card-head">
                  <span>{item.label}</span>
                  <strong>{policyLevelLabel(currentLevel, t)}</strong>
                </div>
                <p>{item.hint}</p>
                <ProtectionLevelSelect
                  value={currentLevel}
                  disabled={isSaving}
                  onChange={async (level) => {
                    const prevLevel = policyDraft[item.field];
                    setPolicyDraft((draft) => ({ ...draft, [item.field]: level }));
                    setPolicySaving((prev) => ({ ...prev, [item.field]: true }));
                    try {
                      await policyMutation.mutateAsync({ [item.field]: level } as ProtectionConfig['policy']);
                    } catch {
                      setPolicyDraft((draft) => ({ ...draft, [item.field]: prevLevel }));
                    }
                  }}
                />
                {isSaving && <span className="policy-saving-indicator">{t('common.saving')}</span>}
              </div>
            );
          })}
        </div>
      </section>

      <div className="settings-grid protection-settings-grid">
        <section className="panel protection-bot-panel">
          <div className="panel-heading">
            <h2><Bot size={16} /> {t('protection.bot')}</h2>
            <span className="policy-current-summary">{t('protection.botChallengeHint')}</span>
            <Button size="sm" variant="outline" onClick={() => window.open('/captcha-lab', '_blank', 'noopener,noreferrer')}>
              <ExternalLink size={14} />
              {t('protection.openCaptchaLab')}
            </Button>
          </div>
          <form onSubmit={saveBot}>
            <Tabs defaultValue="overview" className="protection-bot-tabs">
              <TabsList className="flex flex-wrap h-auto">
                <TabsTrigger value="overview">{t('protection.botOverview')}</TabsTrigger>
                <TabsTrigger value="captcha-policy">{t('protection.captchaPolicy')}</TabsTrigger>
                <TabsTrigger value="pow">{t('protection.powAltcha')}</TabsTrigger>
                <TabsTrigger value="image">{t('protection.imageCaptcha')}</TabsTrigger>
                <TabsTrigger value="slider">{t('protection.sliderCaptcha')}</TabsTrigger>
                <TabsTrigger value="waiting">{t('protection.waitingRoom')}</TabsTrigger>
                <TabsTrigger value="paths">{t('protection.scopeAndTrust')}</TabsTrigger>
              </TabsList>

              <TabsContent value="overview">
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field label={t('protection.bot')} hint={t('protection.botEnabledHint')}>
                    <Switch checked={botForm.enabled} onCheckedChange={(v) => patchBot('enabled', v)} />
                  </Field>
                  <Field label={t('protection.jsChallenge')} hint={t('protection.jsChallengeHint')}>
                    <Switch checked={botForm.jsChallenge} onCheckedChange={(v) => patchBot('jsChallenge', v)} />
                  </Field>
                  <Field label={t('protection.captcha')} hint={t('protection.captchaHint')}>
                    <Switch checked={botForm.captcha} onCheckedChange={(v) => patchBot('captcha', v)} />
                  </Field>
                  <Field label={t('protection.captchaType')} hint={t('protection.captchaTypeHint')}>
                    <CaptchaTypeSelect value={botForm.captchaType} onChange={(v) => patchBot('captchaType', String(v))} />
                  </Field>
                  <Field className="captcha-pool-field" label={t('protection.captchaTypePool')} hint={t('protection.captchaTypePoolHint')}>
                    <CaptchaTypeSelect multiple value={botForm.captchaTypes} onChange={(v) => patchBot('captchaTypes', asArr(v))} />
                  </Field>
                  <Field label={t('protection.captchaMaxAttempts')} hint={t('protection.captchaMaxAttemptsHint')}>
                    <Input type="number" min={1} max={20} value={botForm.captchaMaxAttempts} onChange={(e) => patchBot('captchaMaxAttempts', Number(e.target.value || 1))} />
                  </Field>
                  <Field label={t('protection.captchaMobileType')} hint={t('protection.captchaMobileTypeHint')}>
                    <Select value={botForm.captchaMobileType} onValueChange={(v) => patchBot('captchaMobileType', v)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="pow">{t('protection.captchaTypePow')}</SelectItem>
                        <SelectItem value="image">{t('protection.captchaTypeImage')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field className="duration-field" label={t('protection.challengeTtl')} hint={t('protection.challengeTtlHint')}>
                    <DurationUnitInput value={botForm.challengeTtl} onChange={(v) => patchBot('challengeTtl', v)} />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="captcha-policy">
                <div className="captcha-policy-intro">
                  <div><strong>{t('protection.captchaPolicyTitle')}</strong><span>{t('protection.captchaPolicyHint')}</span></div>
                  <Badge variant="secondary">{protection.bot.captcha_policy_version || 'v1'}</Badge>
                </div>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field className="captcha-pool-field" label={t('protection.captchaEscalationTypes')} hint={t('protection.captchaEscalationTypesHint')}>
                    <CaptchaTypeSelect multiple excludeRandom value={botForm.captchaEscalationTypes} onChange={(v) => patchBot('captchaEscalationTypes', asArr(v))} />
                  </Field>
                  <Field className="duration-field" label={t('protection.captchaChallengeTtl')} hint={t('protection.captchaChallengeTtlHint')}>
                    <DurationUnitInput value={botForm.captchaChallengeTtl} onChange={(v) => patchBot('captchaChallengeTtl', v)} />
                  </Field>
                  <Field className="duration-field" label={t('protection.captchaFailureWindow')} hint={t('protection.captchaFailureWindowHint')}>
                    <DurationUnitInput value={botForm.captchaFailureWindow} onChange={(v) => patchBot('captchaFailureWindow', v)} />
                  </Field>
                  <Field className="duration-field" label={t('protection.captchaBlockDuration')} hint={t('protection.captchaBlockDurationHint')}>
                    <DurationUnitInput value={botForm.captchaBlockDuration} onChange={(v) => patchBot('captchaBlockDuration', v)} />
                  </Field>
                  <Field label={t('protection.captchaBindingMode')} hint={t('protection.captchaBindingModeHint')}>
                    <Select value={botForm.captchaBindingMode} onValueChange={(v) => patchBot('captchaBindingMode', v)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="strict_ip_ua">{t('protection.captchaBindingIpUa')}</SelectItem>
                        <SelectItem value="ip_prefix_ua">{t('protection.captchaBindingIp')}</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field label={t('protection.captchaPolicyVersion')} hint={t('protection.captchaPolicyVersionHint')}>
                    <Input maxLength={64} placeholder="v1" value={botForm.captchaPolicyVersion} onChange={(e) => patchBot('captchaPolicyVersion', e.target.value)} required />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="pow">
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field label={t('protection.challengeDifficulty')} hint={t('protection.challengeDifficultyHint')}>
                    <Input type="number" min={1} max={6} value={botForm.challengeDifficulty} onChange={(e) => patchBot('challengeDifficulty', Number(e.target.value || 1))} />
                  </Field>
                  <Field label={t('protection.altchaMaxNumber')} hint={t('protection.altchaMaxNumberHint')}>
                    <Input type="number" min={1000} max={50000000} value={botForm.altchaMaxNumber} onChange={(e) => patchBot('altchaMaxNumber', Number(e.target.value || 1000))} />
                  </Field>
                  <Field label={t('protection.altchaHeader')} hint={t('protection.altchaHeaderHint')}>
                    <Input value={botForm.altchaHeaderName} onChange={(e) => patchBot('altchaHeaderName', e.target.value)} />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="image">
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field label={t('protection.imageCaptchaLength')} hint={t('protection.imageCaptchaLengthHint')}>
                    <Input type="number" min={4} max={8} value={botForm.imageCaptchaLength} onChange={(e) => patchBot('imageCaptchaLength', Number(e.target.value || 4))} />
                  </Field>
                  <Field label={t('protection.imageCaptchaSize')} hint={t('protection.imageCaptchaSizeHint')}>
                    <Input type="number" min={160} max={420} value={botForm.imageCaptchaWidth} onChange={(e) => patchBot('imageCaptchaWidth', Number(e.target.value || 160))} />
                  </Field>
                  <Field label={t('protection.imageCaptchaHeight')}>
                    <Input type="number" min={60} max={180} value={botForm.imageCaptchaHeight} onChange={(e) => patchBot('imageCaptchaHeight', Number(e.target.value || 60))} />
                  </Field>
                  <Field label={t('protection.imageCaptchaAudioLimit')} hint={t('protection.imageCaptchaAudioLimitHint')}>
                    <Input type="number" min={1} max={20} value={botForm.imageCaptchaAudioLimit} onChange={(e) => patchBot('imageCaptchaAudioLimit', Number(e.target.value || 1))} />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="slider">
                <div className="captcha-preview-card captcha-preview-card-product">
                  <div className="captcha-preview-stage">
                    <span className="captcha-preview-gap" />
                    <span className="captcha-preview-piece" />
                  </div>
                  <div className="captcha-preview-track">
                    <span className="captcha-preview-fill" />
                    <span className="captcha-preview-thumb" aria-hidden="true">›</span>
                    <span>{t('protection.sliderCaptchaPreview')}</span>
                  </div>
                  <p>{t('protection.sliderCaptchaPreviewHint')}</p>
                </div>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field label={t('protection.sliderCaptchaWidth')} hint={t('protection.sliderCaptchaWidthHint')}>
                    <Input type="number" min={240} max={520} value={botForm.sliderCaptchaWidth} onChange={(e) => patchBot('sliderCaptchaWidth', Number(e.target.value || 240))} />
                  </Field>
                  <Field label={t('protection.sliderCaptchaHeight')} hint={t('protection.sliderCaptchaHeightHint')}>
                    <Input type="number" min={100} max={260} value={botForm.sliderCaptchaHeight} onChange={(e) => patchBot('sliderCaptchaHeight', Number(e.target.value || 100))} />
                  </Field>
                  <Field label={t('protection.sliderCaptchaPiece')} hint={t('protection.sliderCaptchaPieceHint')}>
                    <Input type="number" min={32} max={80} value={botForm.sliderCaptchaPiece} onChange={(e) => patchBot('sliderCaptchaPiece', Number(e.target.value || 32))} />
                  </Field>
                  <Field label={t('protection.sliderCaptchaTolerance')} hint={t('protection.sliderCaptchaToleranceHint')}>
                    <Input type="number" min={2} max={16} value={botForm.sliderCaptchaTolerance} onChange={(e) => patchBot('sliderCaptchaTolerance', Number(e.target.value || 2))} />
                  </Field>
                  <Field className="duration-field" label={t('protection.sliderCaptchaMinDrag')} hint={t('protection.sliderCaptchaMinDragHint')}>
                    <DurationUnitInput units={['ms', 's']} fallback="450ms" value={botForm.sliderCaptchaMinDrag} onChange={(v) => patchBot('sliderCaptchaMinDrag', v)} />
                  </Field>
                  <Field label={t('protection.sliderCaptchaTrackRequired')} hint={t('protection.sliderCaptchaTrackRequiredHint')}>
                    <Switch checked={botForm.sliderCaptchaTrackRequired} onCheckedChange={(v) => patchBot('sliderCaptchaTrackRequired', v)} />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="waiting">
                <div className="protection-form-grid protection-form-grid-compact">
                  <Field label={t('protection.waitingRoom')} hint={t('protection.waitingRoomEnabledHint')}>
                    <Switch checked={botForm.waitingRoom} onCheckedChange={(v) => patchBot('waitingRoom', v)} />
                  </Field>
                  <Field label={t('protection.waitingRoomMaxActive')} hint={t('protection.waitingRoomMaxActiveHint')}>
                    <Input type="number" min={1} max={1000000} value={botForm.waitingRoomMaxActive} onChange={(e) => patchBot('waitingRoomMaxActive', Number(e.target.value || 1))} />
                  </Field>
                  <Field className="duration-field" label={t('protection.waitingRoomTtl')} hint={t('protection.waitingRoomTtlHint')}>
                    <DurationUnitInput value={botForm.waitingRoomTtl} onChange={(v) => patchBot('waitingRoomTtl', v)} />
                  </Field>
                </div>
              </TabsContent>

              <TabsContent value="paths">
                <div className="protection-form-grid">
                  <Field label={t('protection.cookieName')} hint={t('protection.cookieNameHint')}>
                    <Input value={botForm.cookieName} onChange={(e) => patchBot('cookieName', e.target.value)} />
                  </Field>
                  <Field label={t('protection.secret')} hint={t('protection.secretHint')}>
                    <Input type="password" value={botForm.secret} onChange={(e) => patchBot('secret', e.target.value)} />
                  </Field>
                </div>
                <ListEditor label={t('protection.protectedPaths')} hint={t('protection.protectedPathsHint')} placeholder="/" value={botForm.protectedPaths} onChange={(v) => patchBot('protectedPaths', v)} />
                <ListEditor label={t('protection.exemptPaths')} hint={t('protection.exemptPathsHint')} placeholder="/health" value={botForm.exemptPaths} onChange={(v) => patchBot('exemptPaths', v)} />
                <ListEditor label={t('protection.allowedUA')} hint={t('protection.allowedUAHint')} placeholder="Googlebot" value={botForm.allowedUA} onChange={(v) => patchBot('allowedUA', v)} />
                <ListEditor label={t('protection.suspiciousUA')} hint={t('protection.suspiciousUAHint')} placeholder="curl" value={botForm.suspiciousUA} onChange={(v) => patchBot('suspiciousUA', v)} />
              </TabsContent>
            </Tabs>
            <div className="form-action-row">
              <Button type="submit" loading={botMutation.isPending}>{t('common.save')}</Button>
            </div>
          </form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Globe2 size={16} /> {t('protection.geoip')}</h2></div>
          <form onSubmit={saveGeo}>
            <div className="protection-form-grid">
              <Field label={t('protection.geoip')}>
                <Switch checked={geoForm.enabled} onCheckedChange={(enabled) => setGeoForm((c) => ({ ...c, enabled }))} />
              </Field>
              <Field label={t('protection.geoipDatabase')} hint={t('protection.geoipDatabaseHint')}>
                <Input placeholder="/var/lib/cheesewaf/GeoLite2-City.mmdb" value={geoForm.database} onChange={(e) => setGeoForm((c) => ({ ...c, database: e.target.value }))} />
              </Field>
              <Field label={t('protection.geoipPrecisionDatabase')} hint={t('protection.geoipPrecisionDatabaseHint')}>
                <Input placeholder="/var/lib/cheesewaf/ip-precision.json" value={geoForm.precisionDatabase} onChange={(e) => setGeoForm((c) => ({ ...c, precisionDatabase: e.target.value }))} />
              </Field>
              <Field label={t('protection.blockedCountries')} hint={t('protection.blockedCountriesHint')}>
                <GeoRegionSelector value={geoForm.blocked} onChange={(blocked) => setGeoForm((c) => ({ ...c, blocked }))} />
              </Field>
            </div>
            <div className="form-action-row">
              <span className="field-help">{t('protection.geoipAccessNote')}</span>
              <Button type="submit" loading={ipMutation.isPending}>{t('common.save')}</Button>
            </div>
          </form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><TimerReset size={16} /> {t('protection.ratelimit')}</h2></div>
          <form onSubmit={saveRate}>
            <div className="protection-form-grid">
              <Field label={t('common.online')}>
                <Switch checked={rateForm.enabled} onCheckedChange={(enabled) => setRateForm((c) => ({ ...c, enabled }))} />
              </Field>
              <Field label={t('protection.requests')}>
                <Input type="number" min={1} max={100000} value={rateForm.requests} onChange={(e) => setRateForm((c) => ({ ...c, requests: Number(e.target.value || 1) }))} />
              </Field>
              <Field label={t('protection.burst')}>
                <Input type="number" min={0} max={10000} value={rateForm.burst} onChange={(e) => setRateForm((c) => ({ ...c, burst: Number(e.target.value || 0) }))} />
              </Field>
            </div>
            <Button type="submit" loading={rateMutation.isPending}>{t('common.save')}</Button>
          </form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ShieldAlert size={16} /> {t('protection.acl')}</h2>
          <span>{t('protection.aclHint')}</span>
          <Button size="sm" onClick={startNewACL}><Plus size={15} />{t('common.add')}</Button>
        </div>
        {aclEditing && aclDraft && (
          <div className="acl-editor-card">
            <div className="protection-form-grid protection-form-grid-compact">
              <label>
                <span>{t('rules.name')}</span>
                <Input value={aclDraft.name} placeholder={t('rules.namePlaceholder')} onChange={(e) => { setAclDraft((d) => d ? { ...d, name: e.target.value } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('rules.method')}</span>
                <Select value={aclDraft.method || '*'} onValueChange={(method) => { setAclDraft((d) => d ? { ...d, method: String(method) } : d); setAclUnsaved(true); }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {['*', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => (
                      <SelectItem key={m} value={m}>{m}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('rules.path')}</span>
                <Input value={aclDraft.path_prefix || ''} placeholder="/admin" onChange={(e) => { setAclDraft((d) => d ? { ...d, path_prefix: e.target.value } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('logs.action')}</span>
                <Select value={aclDraft.action} onValueChange={(action) => { setAclDraft((d) => d ? { ...d, action: String(action) } : d); setAclUnsaved(true); }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="block">{displayAction('block', t)}</SelectItem>
                    <SelectItem value="challenge">{displayAction('challenge', t)}</SelectItem>
                    <SelectItem value="log">{displayAction('log', t)}</SelectItem>
                    <SelectItem value="pass">{displayAction('pass', t)}</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('rules.header')}</span>
                <Input value={aclDraft.header || ''} placeholder="X-Custom-Header" onChange={(e) => { setAclDraft((d) => d ? { ...d, header: e.target.value } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('rules.enabled')}</span>
                <Switch checked={aclDraft.enabled} onCheckedChange={(enabled) => { setAclDraft((d) => d ? { ...d, enabled } : d); setAclUnsaved(true); }} />
              </label>
            </div>
            <div className="acl-editor-actions">
              <Button variant="outline" disabled={aclMutation.isPending} onClick={() => { setAclDraft(null); setAclEditing(false); setAclUnsaved(false); }}>{t('common.cancel')}</Button>
              <Button disabled={!aclUnsaved || !aclDraft.name.trim()} loading={aclMutation.isPending && aclBusyId === aclDraft.id} onClick={saveACLDraft}>{t('common.save')}</Button>
            </div>
          </div>
        )}
        {protection.acl.rules.length === 0 && !aclEditing ? (
          <div className="empty-state">
            <span>{t('protection.aclEmpty')}</span>
          </div>
        ) : (
          <Table className="protection-acl-table">
            <TableHeader>
              <TableRow>
                <TableHead>{t('rules.name')}</TableHead>
                <TableHead>{t('rules.method')}</TableHead>
                <TableHead>{t('rules.path')}</TableHead>
                <TableHead>{t('logs.action')}</TableHead>
                <TableHead>{t('rules.enabled')}</TableHead>
                <TableHead>{t('ip.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {protection.acl.rules.map((record) => (
                <TableRow key={record.id}>
                  <TableCell><strong className="acl-table-name" title={record.name}>{record.name}</strong></TableCell>
                  <TableCell><span className="acl-table-method">{record.method || '*'}</span></TableCell>
                  <TableCell><code className="table-code acl-table-path" title={record.path_prefix || '*'}>{record.path_prefix || '*'}</code></TableCell>
                  <TableCell>
                    <Badge variant={record.action === 'block' ? 'destructive' : record.action === 'challenge' ? 'warning' : 'secondary'}>
                      {displayAction(record.action, t)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={record.enabled}
                      disabled={aclBusyId === record.id}
                      onCheckedChange={(enabled) => toggleACL(record.id, enabled)}
                    />
                  </TableCell>
                  <TableCell>
                    <span className="action-group">
                      <Button size="sm" variant="outline" onClick={() => editACL(record)}><Pencil size={14} />{t('common.edit')}</Button>
                      <Button size="sm" variant="destructive" loading={aclBusyId === record.id} onClick={() => deleteACL(record.id)}><Trash2 size={14} />{t('common.delete')}</Button>
                    </span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <div className="protection-acl-cards">
          {aclEditing && aclDraft && (
            <article className="protection-acl-card protection-acl-card-editing">
              <header>
                <strong>{aclDraft.name || t('rules.namePlaceholder')}</strong>
                <Switch checked={aclDraft.enabled} onCheckedChange={(enabled) => { setAclDraft((d) => d ? { ...d, enabled } : d); setAclUnsaved(true); }} />
              </header>
              <label>
                <span>{t('rules.name')}</span>
                <Input value={aclDraft.name} placeholder={t('rules.namePlaceholder')} onChange={(e) => { setAclDraft((d) => d ? { ...d, name: e.target.value } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('rules.method')}</span>
                <Select value={aclDraft.method || '*'} onValueChange={(method) => { setAclDraft((d) => d ? { ...d, method: String(method) } : d); setAclUnsaved(true); }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {['*', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => (
                      <SelectItem key={m} value={m}>{m}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </label>
              <label>
                <span>{t('rules.path')}</span>
                <Input value={aclDraft.path_prefix || ''} placeholder="/admin" onChange={(e) => { setAclDraft((d) => d ? { ...d, path_prefix: e.target.value } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('logs.action')}</span>
                <Select value={aclDraft.action} onValueChange={(action) => { setAclDraft((d) => d ? { ...d, action: String(action) } : d); setAclUnsaved(true); }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="block">{displayAction('block', t)}</SelectItem>
                    <SelectItem value="challenge">{displayAction('challenge', t)}</SelectItem>
                    <SelectItem value="log">{displayAction('log', t)}</SelectItem>
                    <SelectItem value="pass">{displayAction('pass', t)}</SelectItem>
                  </SelectContent>
                </Select>
              </label>
              <footer>
                <Button size="sm" variant="outline" disabled={aclMutation.isPending} onClick={() => { setAclDraft(null); setAclEditing(false); setAclUnsaved(false); }}>{t('common.cancel')}</Button>
                <Button size="sm" disabled={!aclUnsaved || !aclDraft.name.trim()} loading={aclMutation.isPending && aclBusyId === aclDraft.id} onClick={saveACLDraft}>{t('common.save')}</Button>
              </footer>
            </article>
          )}
          {protection.acl.rules.map((rule) => (
            <article className="protection-acl-card" key={rule.id}>
              <header>
                <strong title={rule.name}>{rule.name}</strong>
                <Switch checked={rule.enabled} disabled={aclBusyId === rule.id} onCheckedChange={(enabled) => toggleACL(rule.id, enabled)} />
              </header>
              <div><span>{t('rules.method')}</span><strong>{rule.method || '*'}</strong></div>
              <div><span>{t('rules.path')}</span><code>{rule.path_prefix || '*'}</code></div>
              <div>
                <span>{t('logs.action')}</span>
                <Badge variant={rule.action === 'block' ? 'destructive' : rule.action === 'challenge' ? 'warning' : 'secondary'}>
                  {displayAction(rule.action, t)}
                </Badge>
              </div>
              <footer>
                <Button size="sm" variant="outline" onClick={() => editACL(rule)}>{t('common.edit')}</Button>
                <Button size="sm" variant="destructive" loading={aclBusyId === rule.id} onClick={() => deleteACL(rule.id)}>{t('common.delete')}</Button>
              </footer>
            </article>
          ))}
        </div>
      </section>

      <Dialog open={Boolean(deleteAclId)} onOpenChange={(open) => { if (!open) setDeleteAclId(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('common.confirmDeleteTitle')}</DialogTitle>
            <DialogDescription>{t('common.confirmDeleteEntry')}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteAclId(null)}>{t('common.cancel')}</Button>
            <Button variant="destructive" onClick={confirmDeleteACL}>{t('common.delete')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function Field({
  label,
  hint,
  className,
  children,
}: {
  label: string;
  hint?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={className ? `field-stack ${className}` : 'field-stack'}>
      <Label>{label}</Label>
      {children}
      {hint ? <span className="field-help">{hint}</span> : null}
    </div>
  );
}

function queryErrorMessage(error: unknown, fallbackMessage: string) {
  return error instanceof Error && error.message.trim() ? error.message : fallbackMessage;
}

function splitList(value: unknown) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

function GeoRegionSelector({ value, onChange }: { value?: string[]; onChange?: (value: string[]) => void }) {
  const { t } = useTranslation();
  const selected = Array.isArray(value) ? value : splitList(value);
  const toggle = (code: string) => {
    const upper = code.toUpperCase();
    const next = selected.includes(upper)
      ? selected.filter((item) => item !== upper)
      : [...selected, upper];
    onChange?.(next.map((item) => item.toUpperCase()));
  };
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" className="geo-region-select w-full justify-start font-normal">
          {selected.length > 0 ? selected.join(', ') : t('protection.blockedCountriesPlaceholder')}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 max-h-72 overflow-auto" align="start">
        <div className="flex flex-col gap-3">
          {geoRegionGroups.map((group) => (
            <div key={group.labelKey}>
              <div className="mb-1 text-xs font-semibold text-muted-foreground">{t(group.labelKey)}</div>
              <div className="flex flex-col gap-1">
                {group.codes.map((code) => (
                  <label key={code} className="flex items-center gap-2 text-sm">
                    <Checkbox checked={selected.includes(code)} onCheckedChange={() => toggle(code)} />
                    {t(`geo.countries.${code}`, { defaultValue: code })} ({code})
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function normalizeProtection(input?: ProtectionConfig): ProtectionConfig {
  const next = input ?? fallback;
  return {
    ...fallback,
    ...next,
    policy: { ...fallback.policy, ...next.policy },
    ip: {
      ...fallback.ip,
      ...next.ip,
      whitelist: asArray(next.ip?.whitelist),
      blacklist: asArray(next.ip?.blacklist),
      access_rules: asArray(next.ip?.access_rules),
      reputation_overrides: next.ip?.reputation_overrides ?? {},
      tags: next.ip?.tags ?? {},
      threat_intel: asArray(next.ip?.threat_intel),
      providers: asArray(next.ip?.providers),
      geoip: {
        ...fallback.ip.geoip,
        ...next.ip?.geoip,
        blocked_countries: asArray(next.ip?.geoip?.blocked_countries),
        precision_database: next.ip?.geoip?.precision_database ?? '',
        country_cidrs: next.ip?.geoip?.country_cidrs ?? {},
      },
    },
    ratelimit: {
      ...fallback.ratelimit,
      ...next.ratelimit,
      default: { ...fallback.ratelimit.default, ...next.ratelimit?.default },
    },
    bot: {
      ...fallback.bot,
      ...next.bot,
      path_prefixes: asArray(next.bot?.path_prefixes),
      exempt_path_prefixes: asArray(next.bot?.exempt_path_prefixes),
      allowed_user_agents: asArray(next.bot?.allowed_user_agents),
      suspicious_user_agents: asArray(next.bot?.suspicious_user_agents),
      captcha_types: asArray(next.bot?.captcha_types),
      captcha_escalation_types: asArray(next.bot?.captcha_escalation_types),
    },
    acl: {
      ...fallback.acl,
      ...next.acl,
      rules: asArray(next.acl?.rules),
    },
  };
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function ProtectionLevelSelect({ value, onChange, disabled }: { value?: string; onChange?: (value: string) => void; disabled?: boolean }) {
  const { t } = useTranslation();
  const current = value || 'smart';
  const options = [
    { value: 'off', label: t('sites.levelOff') },
    { value: 'low', label: t('sites.levelLow') },
    { value: 'smart', label: t('sites.levelSmart') },
    { value: 'high', label: t('sites.levelHigh') },
    { value: 'strict', label: t('sites.levelStrict') },
  ];
  const currentIndex = Math.max(0, options.findIndex((option) => option.value === current));
  return (
    <div
      className="protection-level-picker"
      role="radiogroup"
      aria-label={t('protection.policy')}
      onKeyDown={(event) => {
        if (disabled) return;
        const delta = event.key === 'ArrowRight' || event.key === 'ArrowDown' ? 1 : event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 0;
        if (!delta) return;
        event.preventDefault();
        const next = options[(currentIndex + delta + options.length) % options.length];
        onChange?.(next.value);
      }}
    >
      {options.map((option, index) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          disabled={disabled}
          tabIndex={disabled ? -1 : current === option.value || (currentIndex < 0 && index === 0) ? 0 : -1}
          aria-checked={current === option.value}
          className={current === option.value ? `protection-level-option protection-level-option-${option.value} protection-level-option-active` : 'protection-level-option'}
          onClick={() => onChange?.(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function CaptchaTypeSelect({
  multiple = false,
  excludeRandom = false,
  value,
  onChange,
}: {
  multiple?: boolean;
  excludeRandom?: boolean;
  value?: string | string[];
  onChange?: (value: string | string[]) => void;
}) {
  const { t } = useTranslation();
  const poolOptions = captchaTypes.filter((type) => type !== 'image' && type !== 'slider');
  const options = excludeRandom ? poolOptions.filter((type) => type !== 'random') : multiple ? poolOptions : captchaTypes;

  if (!multiple) {
    const current = String(value || 'pow');
    return (
      <Select value={current} onValueChange={(next) => onChange?.(next)}>
        <SelectTrigger><SelectValue placeholder={t('protection.captchaTypePlaceholder')} /></SelectTrigger>
        <SelectContent>
          {options.map((type) => (
            <SelectItem key={type} value={type}>{captchaTypeLabel(type, t)}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  }

  const selected = Array.isArray(value) ? value : value ? [String(value)] : [];
  const toggle = (type: string) => {
    const next = selected.includes(type)
      ? selected.filter((item) => item !== type)
      : [...selected, type];
    onChange?.(next);
  };
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" className="w-full justify-start font-normal">
          {selected.length > 0
            ? selected.map((type) => captchaTypeLabel(type as CaptchaTypeOption, t)).join(', ')
            : t('protection.captchaTypePlaceholder')}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-72 max-h-64 overflow-auto" align="start">
        <div className="flex flex-col gap-2">
          {options.map((type) => (
            <label key={type} className="flex items-center gap-2 text-sm">
              <Checkbox checked={selected.includes(type)} onCheckedChange={() => toggle(type)} />
              {captchaTypeLabel(type, t)}
            </label>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

function captchaTypeLabel(type: CaptchaTypeOption | string, t: (key: string) => string) {
  if (type === 'image') return t('protection.captchaTypeImage');
  if (type === 'slider') return t('protection.captchaTypeSlider');
  return t(`protection.captchaTypes.${type}`);
}

function DurationUnitInput({
  value,
  onChange,
  units = ['s', 'm', 'h', 'd'],
  fallback = '30m',
}: {
  value?: number | string;
  onChange?: (next: number) => void;
  units?: DurationUnit[];
  fallback?: number | string;
}) {
  const { t } = useTranslation();
  const [parts, setParts] = useState(() => durationToUnitParts(value, units, fallback));
  useEffect(() => {
    const incoming = durationToNanoseconds(value, fallback);
    const local = parts.amount * durationUnitToNanoseconds(parts.unit);
    if (incoming !== local) {
      setParts(durationToUnitParts(value, units, fallback));
    }
  }, [fallback, units, value]);

  const emit = (amount: number | string | null | undefined, nextUnit = parts.unit) => {
    const numeric = Math.max(1, Number(amount || 1));
    setParts({ amount: numeric, unit: nextUnit });
    onChange?.(numeric * durationUnitToNanoseconds(nextUnit));
  };

  return (
    <div className="compound-input duration-unit-input flex gap-2">
      <Input type="number" min={1} value={parts.amount} onChange={(e) => emit(e.target.value)} />
      <Select value={parts.unit} onValueChange={(next) => emit(parts.amount, next as DurationUnit)}>
        <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
        <SelectContent>
          {units.map((option) => (
            <SelectItem key={option} value={option}>{durationUnitLabel(option, t)}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function durationToNanoseconds(value: number | string | undefined, fallback: number | string = '30m'): number {
  if (typeof value === 'number') {
    return value > 0 ? value : durationToNanoseconds(fallback);
  }
  const raw = String(value ?? '').trim();
  if (!raw) {
    return durationToNanoseconds(fallback);
  }
  const numeric = Number.parseFloat(raw);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return durationToNanoseconds(fallback);
  }
  if (raw.endsWith('ms')) return numeric * durationUnitToNanoseconds('ms');
  if (raw.endsWith('d')) return numeric * durationUnitToNanoseconds('d');
  if (raw.endsWith('h')) return numeric * durationUnitToNanoseconds('h');
  if (raw.endsWith('m')) return numeric * durationUnitToNanoseconds('m');
  if (raw.endsWith('s')) return numeric * durationUnitToNanoseconds('s');
  return numeric;
}

function durationToUnitParts(value: number | string | undefined, units: DurationUnit[], fallback: number | string): { amount: number; unit: DurationUnit } {
  if (typeof value === 'string') {
    const match = value.trim().toLowerCase().match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)$/);
    const explicitUnit = match?.[2] as DurationUnit | undefined;
    if (match && explicitUnit && units.includes(explicitUnit)) {
      return { amount: Math.max(1, Number(match[1])), unit: explicitUnit };
    }
  }
  const ns = Math.max(1, Number(durationToNanoseconds(value, fallback) || 0));
  for (const unit of [...units].reverse()) {
    const divisor = durationUnitToNanoseconds(unit);
    if (ns >= divisor && ns % divisor === 0) {
      return { amount: ns / divisor, unit };
    }
  }
  const unit = units[0] ?? 's';
  return { amount: Math.max(1, Math.round(ns / durationUnitToNanoseconds(unit))), unit };
}

function durationUnitToNanoseconds(unit: DurationUnit) {
  switch (unit) {
    case 'ms':
      return 1_000_000;
    case 'd':
      return 24 * 60 * 60 * 1_000_000_000;
    case 'h':
      return 60 * 60 * 1_000_000_000;
    case 'm':
      return 60 * 1_000_000_000;
    default:
      return 1_000_000_000;
  }
}

function durationUnitLabel(unit: DurationUnit, t: ReturnType<typeof useTranslation>['t']) {
  if (unit === 'ms') return 'ms';
  if (unit === 's') return t('common.seconds');
  if (unit === 'm') return t('common.minutes');
  if (unit === 'h') return t('common.hours');
  return t('common.days');
}

function ListEditor({
  label,
  hint,
  placeholder,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  value: string[];
  onChange: (next: string[]) => void;
}) {
  const { t } = useTranslation();
  const items = Array.isArray(value) ? value : [];
  return (
    <div className="field-stack">
      <Label>{label}</Label>
      {hint ? <span className="field-help">{hint}</span> : null}
      <div className="list-editor">
        {items.map((item, index) => (
          <div className="list-editor-item" key={`${index}-${item}`}>
            <Input
              placeholder={placeholder}
              value={item}
              onChange={(e) => {
                const next = [...items];
                next[index] = e.target.value;
                onChange(next);
              }}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              aria-label={`${t('common.delete')} ${label}`}
              title={`${t('common.delete')} ${label}`}
              onClick={() => onChange(items.filter((_, i) => i !== index))}
            >
              <Trash2 size={12} />
            </Button>
          </div>
        ))}
        <Button type="button" size="sm" variant="outline" onClick={() => onChange([...items, ''])}>
          <Plus size={12} />
          {t('common.add')}
        </Button>
      </div>
    </div>
  );
}

function asArr(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return [];
}

function policyLevelLabel(level: string | undefined, t: ReturnType<typeof useTranslation>['t']) {
  switch (level || 'smart') {
    case 'off':
      return t('sites.levelOff');
    case 'low':
      return t('sites.levelLow');
    case 'high':
      return t('sites.levelHigh');
    case 'strict':
      return t('sites.levelStrict');
    default:
      return t('sites.levelSmart');
  }
}
