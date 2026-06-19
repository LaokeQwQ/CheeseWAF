import { Button, Form, Input, InputNumber, Select, Switch, Table, Tabs, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Bot, Clock3, Globe2, Image as ImageIcon, KeyRound, List, Pencil, Plus, Puzzle, Route, ShieldAlert, TimerReset, Trash2 } from 'lucide-react';
import { fetchProtection, updateACLProtection, updateBotProtection, updateIPProtection, updateProtectionPolicy, updateRateLimit } from '../../api/client';
import type { ACLRule, ProtectionConfig } from '../../types/api';
import { displayAction } from '../../utils/display';

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
  { label: 'Asia', codes: ['CN', 'HK', 'MO', 'TW', 'JP', 'KR', 'SG', 'IN', 'VN', 'TH', 'MY', 'ID', 'PH', 'PK', 'KZ'] },
  { label: 'Europe', codes: ['GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'SE', 'CH', 'PL', 'RO', 'CZ', 'AT', 'HU', 'FI', 'DK', 'NO', 'IE', 'GR', 'PT', 'BE', 'SK', 'SI'] },
  { label: 'North America', codes: ['US', 'CA', 'MX'] },
  { label: 'South America', codes: ['BR', 'AR', 'CL', 'CO', 'PE', 'VE'] },
  { label: 'Africa', codes: ['ZA', 'EG', 'NG', 'KE', 'MA'] },
  { label: 'Oceania', codes: ['AU', 'NZ'] },
  { label: 'Middle East', codes: ['AE', 'SA', 'IL', 'IR', 'TR'] },
] as const;

export default function ProtectionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['protection'], queryFn: fetchProtection, retry: false });
  const protection = normalizeProtection(data);
  const policyItems = [
    { field: 'web_attack', label: t('sites.webAttackLevel'), hint: t('protection.webAttackHint') },
    { field: 'api_security', label: t('sites.apiSecurityLevel'), hint: t('protection.apiSecurityHint') },
    { field: 'bot_cc', label: t('sites.botCCLevel'), hint: t('protection.botCCHint') },
    { field: 'threat_intel', label: t('sites.threatIntelLevel'), hint: t('protection.threatIntelHint') },
  ] as const;
  const [policyDraft, setPolicyDraft] = useState(protection.policy);
  const [policySaving, setPolicySaving] = useState<Record<string, boolean>>({});
  useEffect(() => { setPolicyDraft(protection.policy); }, [protection.policy]);
  const policyMutation = useMutation({
    mutationFn: updateProtectionPolicy,
    onSuccess: (_result, variables) => {
      const fields = Object.keys(variables) as Array<keyof typeof variables>;
      setPolicySaving((prev) => { const next = { ...prev }; for (const f of fields) delete next[f]; return next; });
      queryClient.invalidateQueries({ queryKey: ['protection'] });
    },
    onError: (_error, variables) => {
      const fields = Object.keys(variables) as Array<keyof typeof variables>;
      setPolicySaving((prev) => { const next = { ...prev }; for (const f of fields) delete next[f]; return next; });
      setPolicyDraft(protection.policy);
    },
  });
  const ipMutation = useMutation({ mutationFn: updateIPProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const rateMutation = useMutation({ mutationFn: updateRateLimit, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const botMutation = useMutation({ mutationFn: updateBotProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const aclMutation = useMutation({ mutationFn: updateACLProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const [aclDraft, setAclDraft] = useState<ACLRule | null>(null);
  const [aclEditing, setAclEditing] = useState(false);
  const [aclChanged, setAclChanged] = useState(false);

  function startNewACL() {
    setAclDraft({ id: `acl-${Date.now()}`, name: '', method: '', path_prefix: '', header: '', header_value: '', action: 'block', severity: 'medium', enabled: true });
    setAclEditing(true);
  }
  function editACL(rule: ACLRule) {
    setAclDraft({ ...rule });
    setAclEditing(true);
  }
  function saveACLDraft() {
    if (!aclDraft) return;
    const rules = [...protection.acl.rules];
    const idx = rules.findIndex((r) => r.id === aclDraft.id);
    if (idx >= 0) rules[idx] = aclDraft;
    else rules.push(aclDraft);
    aclMutation.mutate({ ...protection.acl, rules });
    setAclDraft(null);
    setAclEditing(false);
    setAclChanged(false);
    setAclUnsaved(false);
  }
  function deleteACL(id: string) {
    const rules = protection.acl.rules.filter((r) => r.id !== id);
    aclMutation.mutate({ ...protection.acl, rules });
    setAclUnsaved(false);
  }
  const [aclUnsaved, setAclUnsaved] = useState(false);

  return (
    <section className="page-surface">
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
          </div>
          <Form
            key={`bot-${protection.bot.enabled}-${protection.bot.cookie_name}`}
            layout="vertical"
            initialValues={{
              enabled: protection.bot.enabled,
              jsChallenge: protection.bot.js_challenge,
              captcha: protection.bot.captcha,
              captchaType: protection.bot.captcha_type || 'pow',
              captchaMaxAttempts: protection.bot.captcha_max_attempts,
              imageCaptchaLength: protection.bot.image_captcha_length,
              imageCaptchaWidth: protection.bot.image_captcha_width,
              imageCaptchaHeight: protection.bot.image_captcha_height,
              imageCaptchaAudioLimit: protection.bot.image_captcha_audio_limit,
              sliderCaptchaWidth: protection.bot.slider_captcha_width,
              sliderCaptchaHeight: protection.bot.slider_captcha_height,
              sliderCaptchaPiece: protection.bot.slider_captcha_piece,
              sliderCaptchaTolerance: protection.bot.slider_captcha_tolerance,
              sliderCaptchaMinDrag: protection.bot.slider_captcha_min_drag || '450ms',
              sliderCaptchaTrackRequired: protection.bot.slider_captcha_track_required ?? true,
              captchaMobileType: protection.bot.captcha_mobile_type || 'pow',
              challengeDifficulty: protection.bot.challenge_difficulty,
              altchaMaxNumber: protection.bot.altcha_max_number,
              altchaHeaderName: protection.bot.altcha_header_name,
              waitingRoom: protection.bot.waiting_room,
              waitingRoomMaxActive: protection.bot.waiting_room_max_active,
              waitingRoomTtl: protection.bot.waiting_room_ttl || '5m',
              challengeTtl: protection.bot.challenge_ttl || '30m',
              cookieName: protection.bot.cookie_name,
              secret: protection.bot.secret,
              protectedPaths: protection.bot.path_prefixes,
              exemptPaths: protection.bot.exempt_path_prefixes,
              allowedUA: protection.bot.allowed_user_agents,
              suspiciousUA: protection.bot.suspicious_user_agents,
            }}
            onSubmit={(values) => botMutation.mutate({
              enabled: values.enabled,
              js_challenge: values.jsChallenge,
              captcha: values.captcha,
              captcha_type: values.captchaType,
              captcha_max_attempts: values.captchaMaxAttempts,
              image_captcha_length: values.imageCaptchaLength,
              image_captcha_width: values.imageCaptchaWidth,
              image_captcha_height: values.imageCaptchaHeight,
              image_captcha_audio_limit: values.imageCaptchaAudioLimit,
              slider_captcha_width: values.sliderCaptchaWidth,
              slider_captcha_height: values.sliderCaptchaHeight,
              slider_captcha_piece: values.sliderCaptchaPiece,
              slider_captcha_tolerance: values.sliderCaptchaTolerance,
              slider_captcha_min_drag: durationToNanoseconds(values.sliderCaptchaMinDrag, '450ms'),
              slider_captcha_track_required: values.sliderCaptchaTrackRequired,
              captcha_mobile_type: values.captchaMobileType,
              challenge_difficulty: values.challengeDifficulty,
              altcha_max_number: values.altchaMaxNumber,
              altcha_header_name: values.altchaHeaderName,
              waiting_room: values.waitingRoom,
              waiting_room_max_active: values.waitingRoomMaxActive,
              waiting_room_ttl: durationToNanoseconds(values.waitingRoomTtl, '5m'),
              challenge_ttl: durationToNanoseconds(values.challengeTtl, '30m'),
              cookie_name: values.cookieName,
              secret: values.secret,
              path_prefixes: asArr(values.protectedPaths),
              exempt_path_prefixes: asArr(values.exemptPaths),
              allowed_user_agents: asArr(values.allowedUA),
              suspicious_user_agents: asArr(values.suspiciousUA),
            })}
          >
            <Tabs
              defaultActiveTab="overview"
              tabPosition="top"
              size="small"
              className="protection-bot-tabs"
            >
              <Tabs.TabPane key="overview" title={t('protection.botOverview')}>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Form.Item label={t('protection.bot')} field="enabled" triggerPropName="checked" extra={t('protection.botEnabledHint')}><Switch /></Form.Item>
                  <Form.Item label={t('protection.jsChallenge')} field="jsChallenge" triggerPropName="checked" extra={t('protection.jsChallengeHint')}><Switch /></Form.Item>
                  <Form.Item label={t('protection.captcha')} field="captcha" triggerPropName="checked" extra={t('protection.captchaHint')}><Switch /></Form.Item>
                  <Form.Item label={t('protection.captchaType')} field="captchaType" extra={t('protection.captchaTypeHint')}>
                    <Select>
                      <Select.Option value="pow">{t('protection.captchaTypePow')}</Select.Option>
                      <Select.Option value="image">{t('protection.captchaTypeImage')}</Select.Option>
                      <Select.Option value="slider">{t('protection.captchaTypeSlider')}</Select.Option>
                    </Select>
                  </Form.Item>
                  <Form.Item label={t('protection.captchaMaxAttempts')} field="captchaMaxAttempts" extra={t('protection.captchaMaxAttemptsHint')}><InputNumber min={1} max={20} /></Form.Item>
                  <Form.Item label={t('protection.captchaMobileType')} field="captchaMobileType" extra={t('protection.captchaMobileTypeHint')}>
                    <Select>
                      <Select.Option value="pow">{t('protection.captchaTypePow')}</Select.Option>
                      <Select.Option value="image">{t('protection.captchaTypeImage')}</Select.Option>
                    </Select>
                  </Form.Item>
                  <Form.Item className="duration-field" label={t('protection.challengeTtl')} field="challengeTtl" extra={t('protection.challengeTtlHint')}><DurationUnitInput /></Form.Item>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane key="pow" title={t('protection.powAltcha')}>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Form.Item label={t('protection.challengeDifficulty')} field="challengeDifficulty" extra={t('protection.challengeDifficultyHint')}><InputNumber min={1} max={6} /></Form.Item>
                  <Form.Item label={t('protection.altchaMaxNumber')} field="altchaMaxNumber" extra={t('protection.altchaMaxNumberHint')}><InputNumber min={1000} max={50000000} /></Form.Item>
                  <Form.Item label={t('protection.altchaHeader')} field="altchaHeaderName" extra={t('protection.altchaHeaderHint')}><Input /></Form.Item>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane key="image" title={t('protection.imageCaptcha')}>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Form.Item label={t('protection.imageCaptchaLength')} field="imageCaptchaLength" extra={t('protection.imageCaptchaLengthHint')}><InputNumber min={4} max={8} /></Form.Item>
                  <Form.Item label={t('protection.imageCaptchaSize')} field="imageCaptchaWidth" extra={t('protection.imageCaptchaSizeHint')}><InputNumber min={160} max={420} /></Form.Item>
                  <Form.Item label={t('protection.imageCaptchaHeight')} field="imageCaptchaHeight"><InputNumber min={60} max={180} /></Form.Item>
                  <Form.Item label={t('protection.imageCaptchaAudioLimit')} field="imageCaptchaAudioLimit" extra={t('protection.imageCaptchaAudioLimitHint')}><InputNumber min={1} max={20} /></Form.Item>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane key="slider" title={t('protection.sliderCaptcha')}>
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
                  <Form.Item label={t('protection.sliderCaptchaWidth')} field="sliderCaptchaWidth" extra={t('protection.sliderCaptchaWidthHint')}><InputNumber min={240} max={520} /></Form.Item>
                  <Form.Item label={t('protection.sliderCaptchaHeight')} field="sliderCaptchaHeight" extra={t('protection.sliderCaptchaHeightHint')}><InputNumber min={100} max={260} /></Form.Item>
                  <Form.Item label={t('protection.sliderCaptchaPiece')} field="sliderCaptchaPiece" extra={t('protection.sliderCaptchaPieceHint')}><InputNumber min={32} max={80} /></Form.Item>
                  <Form.Item label={t('protection.sliderCaptchaTolerance')} field="sliderCaptchaTolerance" extra={t('protection.sliderCaptchaToleranceHint')}><InputNumber min={2} max={16} /></Form.Item>
                  <Form.Item className="duration-field" label={t('protection.sliderCaptchaMinDrag')} field="sliderCaptchaMinDrag" extra={t('protection.sliderCaptchaMinDragHint')}><DurationUnitInput units={['ms', 's']} fallback="450ms" /></Form.Item>
                  <Form.Item label={t('protection.sliderCaptchaTrackRequired')} field="sliderCaptchaTrackRequired" triggerPropName="checked" extra={t('protection.sliderCaptchaTrackRequiredHint')}><Switch /></Form.Item>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane key="waiting" title={t('protection.waitingRoom')}>
                <div className="protection-form-grid protection-form-grid-compact">
                  <Form.Item label={t('protection.waitingRoom')} field="waitingRoom" triggerPropName="checked" extra={t('protection.waitingRoomEnabledHint')}><Switch /></Form.Item>
                  <Form.Item label={t('protection.waitingRoomMaxActive')} field="waitingRoomMaxActive" extra={t('protection.waitingRoomMaxActiveHint')}><InputNumber min={1} max={1000000} /></Form.Item>
                  <Form.Item className="duration-field" label={t('protection.waitingRoomTtl')} field="waitingRoomTtl" extra={t('protection.waitingRoomTtlHint')}><DurationUnitInput /></Form.Item>
                </div>
              </Tabs.TabPane>
              <Tabs.TabPane key="paths" title={t('protection.scopeAndTrust')}>
                <div className="protection-form-grid">
                  <Form.Item label={t('protection.cookieName')} field="cookieName" extra={t('protection.cookieNameHint')}><Input /></Form.Item>
                  <Form.Item label={t('protection.secret')} field="secret" extra={t('protection.secretHint')}>
                    <Input.Password />
                  </Form.Item>
                </div>
                <ListEditor label={t('protection.protectedPaths')} field="protectedPaths" hint={t('protection.protectedPathsHint')} placeholder="/" />
                <ListEditor label={t('protection.exemptPaths')} field="exemptPaths" hint={t('protection.exemptPathsHint')} placeholder="/health" />
                <ListEditor label={t('protection.allowedUA')} field="allowedUA" hint={t('protection.allowedUAHint')} placeholder="Googlebot" />
                <ListEditor label={t('protection.suspiciousUA')} field="suspiciousUA" hint={t('protection.suspiciousUAHint')} placeholder="curl" />
              </Tabs.TabPane>
            </Tabs>
            <div className="form-action-row">
              <Button type="primary" htmlType="submit" loading={botMutation.isPending}>{t('common.save')}</Button>
            </div>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Globe2 size={16} /> {t('protection.geoip')}</h2></div>
          <Form
            key={`geoip-${protection.ip.geoip.enabled}`}
            layout="vertical"
            initialValues={{
              enabled: protection.ip.geoip.enabled,
              database: protection.ip.geoip.database,
              precisionDatabase: protection.ip.geoip.precision_database,
              blocked: protection.ip.geoip.blocked_countries,
            }}
            onSubmit={(values) => ipMutation.mutate({
              ...protection.ip,
              geoip: {
                ...protection.ip.geoip,
                enabled: values.enabled,
                database: String(values.database ?? '').trim(),
                precision_database: String(values.precisionDatabase ?? '').trim(),
                blocked_countries: splitList(values.blocked).map((item) => item.toUpperCase()),
              },
            })}
          >
            <div className="protection-form-grid">
              <Form.Item label={t('protection.geoip')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
              <Form.Item label={t('protection.geoipDatabase')} field="database" extra={t('protection.geoipDatabaseHint')}><Input placeholder="/var/lib/cheesewaf/GeoLite2-City.mmdb" /></Form.Item>
              <Form.Item label={t('protection.geoipPrecisionDatabase')} field="precisionDatabase" extra={t('protection.geoipPrecisionDatabaseHint')}><Input placeholder="/var/lib/cheesewaf/ip-precision.json" /></Form.Item>
              <Form.Item label={t('protection.blockedCountries')} field="blocked" extra={t('protection.blockedCountriesHint')}><GeoRegionSelector /></Form.Item>
            </div>
            <div className="form-action-row">
              <span className="field-help">{t('protection.geoipAccessNote')}</span>
              <Button type="primary" htmlType="submit" loading={ipMutation.isPending}>{t('common.save')}</Button>
            </div>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><TimerReset size={16} /> {t('protection.ratelimit')}</h2></div>
          <Form
            key={`ratelimit-${protection.ratelimit.enabled}-${protection.ratelimit.default.requests}`}
            layout="vertical"
            initialValues={{ enabled: protection.ratelimit.enabled, requests: protection.ratelimit.default.requests, burst: protection.ratelimit.default.burst }}
            onSubmit={(values) => rateMutation.mutate({ enabled: values.enabled, default: { ...protection.ratelimit.default, requests: values.requests, burst: values.burst } })}
          >
            <div className="protection-form-grid">
              <Form.Item label={t('common.online')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
              <Form.Item label={t('protection.requests')} field="requests"><InputNumber min={1} max={100000} /></Form.Item>
              <Form.Item label={t('protection.burst')} field="burst"><InputNumber min={0} max={10000} /></Form.Item>
            </div>
            <Button type="primary" htmlType="submit" loading={rateMutation.isPending}>{t('common.save')}</Button>
          </Form>
        </section>
      </div>

      <section className="table-panel">
        <div className="panel-heading">
          <h2><ShieldAlert size={16} /> {t('protection.acl')}</h2>
          <span>{t('protection.aclHint')}</span>
          <Button type="primary" icon={<Plus size={15} />} size="small" onClick={startNewACL}>{t('common.add')}</Button>
        </div>
        {aclEditing && aclDraft && (
          <div className="acl-editor-card">
            <div className="protection-form-grid protection-form-grid-compact">
              <label>
                <span>{t('rules.name')}</span>
                <Input value={aclDraft.name} placeholder={t('rules.namePlaceholder')} onChange={(name) => { setAclDraft((d) => d ? { ...d, name } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('rules.method')}</span>
                <Select value={aclDraft.method || '*'} onChange={(method) => { setAclDraft((d) => d ? { ...d, method: String(method) } : d); setAclUnsaved(true); }}>
                  <Select.Option value="*">*</Select.Option>
                  <Select.Option value="GET">GET</Select.Option>
                  <Select.Option value="POST">POST</Select.Option>
                  <Select.Option value="PUT">PUT</Select.Option>
                  <Select.Option value="DELETE">DELETE</Select.Option>
                  <Select.Option value="PATCH">PATCH</Select.Option>
                  <Select.Option value="HEAD">HEAD</Select.Option>
                  <Select.Option value="OPTIONS">OPTIONS</Select.Option>
                </Select>
              </label>
              <label>
                <span>{t('rules.path')}</span>
                <Input value={aclDraft.path_prefix || ''} placeholder="/admin" onChange={(path_prefix) => { setAclDraft((d) => d ? { ...d, path_prefix } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('logs.action')}</span>
                <Select value={aclDraft.action} onChange={(action) => { setAclDraft((d) => d ? { ...d, action: String(action) } : d); setAclUnsaved(true); }}>
                  <Select.Option value="block">{displayAction('block', t)}</Select.Option>
                  <Select.Option value="challenge">{displayAction('challenge', t)}</Select.Option>
                  <Select.Option value="log">{displayAction('log', t)}</Select.Option>
                  <Select.Option value="pass">{displayAction('pass', t)}</Select.Option>
                </Select>
              </label>
              <label>
                <span>{t('rules.header')}</span>
                <Input value={aclDraft.header || ''} placeholder="X-Custom-Header" onChange={(header) => { setAclDraft((d) => d ? { ...d, header } : d); setAclUnsaved(true); }} />
              </label>
              <label>
                <span>{t('rules.enabled')}</span>
                <Switch checked={aclDraft.enabled} onChange={(enabled) => { setAclDraft((d) => d ? { ...d, enabled } : d); setAclUnsaved(true); }} />
              </label>
            </div>
            <div className="acl-editor-actions">
              <Button onClick={() => { setAclDraft(null); setAclEditing(false); setAclUnsaved(false); }}>{t('common.cancel')}</Button>
              <Button type="primary" disabled={!aclUnsaved} loading={aclMutation.isPending} onClick={saveACLDraft}>{t('common.save')}</Button>
            </div>
          </div>
        )}
        {protection.acl.rules.length === 0 && !aclEditing ? (
          <div className="empty-state">
            <span>{t('protection.aclEmpty')}</span>
          </div>
        ) : (
          <Table
            className="protection-acl-table"
            rowKey="id"
            pagination={false}
            loading={isLoading}
            data={protection.acl.rules}
            columns={[
              { title: t('rules.name'), dataIndex: 'name', render: (name: string) => <strong>{name}</strong> },
              { title: t('rules.method'), dataIndex: 'method', render: (method: string) => method || '*' },
              { title: t('rules.path'), dataIndex: 'path_prefix', render: (path: string) => <code className="table-code">{path || '*'}</code> },
              {
                title: t('logs.action'),
                dataIndex: 'action',
                render: (action: string) => <Tag color={action === 'block' ? 'red' : action === 'challenge' ? 'orange' : 'blue'}>{displayAction(action, t)}</Tag>,
              },
              { title: t('rules.enabled'), dataIndex: 'enabled', render: (_: boolean, record: ACLRule) => <Switch checked={record.enabled} size="small" /> },
              {
                title: t('ip.actions'),
                dataIndex: 'actions',
                render: (_: unknown, record: ACLRule) => (
                  <span className="action-group">
                    <Button size="small" icon={<Pencil size={14} />} onClick={() => editACL(record)}>{t('common.edit')}</Button>
                    <Button size="small" status="danger" icon={<Trash2 size={14} />} onClick={() => deleteACL(record.id)}>{t('common.delete')}</Button>
                  </span>
                ),
              },
            ]}
          />
        )}
        <div className="protection-acl-cards">
          {protection.acl.rules.map((rule) => (
            <article className="protection-acl-card" key={rule.id}>
              <header>
                <strong>{rule.name}</strong>
                <Switch checked={rule.enabled} size="small" />
              </header>
              <div><span>{t('rules.method')}</span><strong>{rule.method || '*'}</strong></div>
              <div><span>{t('rules.path')}</span><code>{rule.path_prefix || '*'}</code></div>
              <div><span>{t('logs.action')}</span><Tag color={rule.action === 'block' ? 'red' : rule.action === 'challenge' ? 'orange' : 'blue'}>{displayAction(rule.action, t)}</Tag></div>
              <footer>
                <Button size="small" onClick={() => editACL(rule)}>{t('common.edit')}</Button>
                <Button size="small" status="danger" onClick={() => deleteACL(rule.id)}>{t('common.delete')}</Button>
              </footer>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
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
  return (
    <Select
      className="geo-region-select"
      mode="multiple"
      allowClear
      showSearch
      value={selected}
      placeholder={t('protection.blockedCountriesPlaceholder')}
      onChange={(next) => onChange?.((Array.isArray(next) ? next : []).map((item) => String(item).toUpperCase()))}
    >
      {geoRegionGroups.map((group) => (
        <Select.OptGroup key={group.label} label={group.label}>
          {group.codes.map((code) => (
            <Select.Option key={code} value={code}>
              {t(`geo.countries.${code}`, { defaultValue: code })} ({code})
            </Select.Option>
          ))}
        </Select.OptGroup>
      ))}
    </Select>
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
  return (
    <div className="protection-level-picker" role="radiogroup" aria-label={t('protection.policy')}>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          disabled={disabled}
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
  const parts = durationToUnitParts(value, units, fallback);
  const [unit, setUnit] = useState<DurationUnit>(parts.unit);
  useEffect(() => {
    setUnit(parts.unit);
  }, [parts.unit, parts.amount]);

  const emit = (amount: number | string | null | undefined, nextUnit = unit) => {
    const numeric = Math.max(1, Number(amount || 1));
    onChange?.(numeric * durationUnitToNanoseconds(nextUnit));
  };

  return (
    <div className="compound-input duration-unit-input">
      <InputNumber min={1} value={parts.amount} onChange={(next) => emit(next)} />
      <Select value={unit} onChange={(next) => { const nextUnit = String(next) as DurationUnit; setUnit(nextUnit); emit(parts.amount, nextUnit); }}>
        {units.map((option) => (
          <Select.Option key={option} value={option}>{durationUnitLabel(option, t)}</Select.Option>
        ))}
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
  if (raw.endsWith('ms')) {
    return numeric * durationUnitToNanoseconds('ms');
  }
  if (raw.endsWith('d')) {
    return numeric * durationUnitToNanoseconds('d');
  }
  if (raw.endsWith('h')) {
    return numeric * durationUnitToNanoseconds('h');
  }
  if (raw.endsWith('m')) {
    return numeric * durationUnitToNanoseconds('m');
  }
  if (raw.endsWith('s')) {
    return numeric * durationUnitToNanoseconds('s');
  }
  return numeric;
}

function durationToUnitParts(value: number | string | undefined, units: DurationUnit[], fallback: number | string): { amount: number; unit: DurationUnit } {
  const ns = Math.max(1, Number(durationToNanoseconds(value, fallback) || 0));
  for (const unit of units) {
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

function ListEditor({ label, field, hint, placeholder }: { label: string; field: string; hint?: string; placeholder?: string }) {
  const { t } = useTranslation();
  return (
    <Form.Item label={label} field={field} extra={hint}>
      <Form.List field={field}>
        {(fields, { add, remove }) => (
          <div className="list-editor">
            {fields.map((f) => (
              <div className="list-editor-item" key={f.key}>
                <Form.Item field={f.field} noStyle><Input placeholder={placeholder} /></Form.Item>
                <Button size="mini" icon={<Trash2 size={12} />} onClick={() => remove(f.key)} />
              </div>
            ))}
            <Button size="mini" icon={<Plus size={12} />} onClick={() => add()}>{t('common.add')}</Button>
          </div>
        )}
      </Form.List>
    </Form.Item>
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
