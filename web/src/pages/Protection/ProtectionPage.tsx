import { Button, Form, Input, InputNumber, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Bot, Clock3, Globe2, Image as ImageIcon, KeyRound, Puzzle, Route, ShieldAlert, TimerReset } from 'lucide-react';
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
    geoip: { enabled: false, database: '', blocked_countries: [], country_cidrs: {} },
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

const geoRegionOptions = ['CN', 'HK', 'MO', 'TW', 'US', 'RU', 'SG', 'JP', 'KR', 'DE', 'GB', 'FR', 'IN', 'BR', 'VN'] as const;

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
  const policyMutation = useMutation({ mutationFn: updateProtectionPolicy, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const ipMutation = useMutation({ mutationFn: updateIPProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const rateMutation = useMutation({ mutationFn: updateRateLimit, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const botMutation = useMutation({ mutationFn: updateBotProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });
  const aclMutation = useMutation({ mutationFn: updateACLProtection, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['protection'] }) });

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
        <Form
          key={`policy-${Object.values(protection.policy).join('-')}`}
          layout="vertical"
          initialValues={protection.policy}
          onSubmit={(values) => policyMutation.mutate(values as ProtectionConfig['policy'])}
        >
          <div className="policy-level-grid">
            {policyItems.map((item) => (
              <div className={`policy-level-card policy-level-card-${protection.policy[item.field] || 'smart'}`} key={item.field}>
                <div className="policy-level-card-head">
                  <span>{item.label}</span>
                  <strong>{policyLevelLabel(protection.policy[item.field], t)}</strong>
                </div>
                <p>{item.hint}</p>
                <Form.Item label={false} field={item.field}>
                  <ProtectionLevelSelect />
                </Form.Item>
              </div>
            ))}
          </div>
          <Button type="primary" htmlType="submit" loading={policyMutation.isPending}>{t('common.save')}</Button>
        </Form>
      </section>

      <div className="settings-grid protection-settings-grid">
        <section className="panel protection-bot-panel">
          <div className="panel-heading">
            <h2><Bot size={16} /> {t('protection.botChallenge')}</h2>
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
              challengeDifficulty: protection.bot.challenge_difficulty,
              altchaMaxNumber: protection.bot.altcha_max_number,
              altchaHeaderName: protection.bot.altcha_header_name,
              waitingRoom: protection.bot.waiting_room,
              waitingRoomMaxActive: protection.bot.waiting_room_max_active,
              waitingRoomTtl: protection.bot.waiting_room_ttl || '5m',
              challengeTtl: protection.bot.challenge_ttl || '30m',
              cookieName: protection.bot.cookie_name,
              secret: protection.bot.secret,
              protectedPaths: protection.bot.path_prefixes.join(','),
              exemptPaths: protection.bot.exempt_path_prefixes.join(','),
              allowedUA: protection.bot.allowed_user_agents.join(','),
              suspiciousUA: protection.bot.suspicious_user_agents.join(','),
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
              challenge_difficulty: values.challengeDifficulty,
              altcha_max_number: values.altchaMaxNumber,
              altcha_header_name: values.altchaHeaderName,
              waiting_room: values.waitingRoom,
              waiting_room_max_active: values.waitingRoomMaxActive,
              waiting_room_ttl: durationToNanoseconds(values.waitingRoomTtl, '5m'),
              challenge_ttl: durationToNanoseconds(values.challengeTtl, '30m'),
              cookie_name: values.cookieName,
              secret: values.secret,
              path_prefixes: splitList(values.protectedPaths),
              exempt_path_prefixes: splitList(values.exemptPaths),
              allowed_user_agents: splitList(values.allowedUA),
              suspicious_user_agents: splitList(values.suspiciousUA),
            })}
          >
            <div className="protection-section-stack">
              <div className="protection-section-card protection-section-card-main protection-section-card-plain">
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
                  <Form.Item className="duration-field" label={t('protection.challengeTtl')} field="challengeTtl" extra={t('protection.challengeTtlHint')}><DurationUnitInput /></Form.Item>
                </div>
              </div>

              <div className="protection-subsection-grid">
                <div className="protection-section-card">
                  <header>
                    <strong><KeyRound size={15} /> {t('protection.powAltcha')}</strong>
                    <span>{t('protection.powAltchaHint')}</span>
                  </header>
                  <div className="protection-form-grid protection-form-grid-compact">
                    <Form.Item label={t('protection.challengeDifficulty')} field="challengeDifficulty" extra={t('protection.challengeDifficultyHint')}><InputNumber min={1} max={6} /></Form.Item>
                    <Form.Item label={t('protection.altchaMaxNumber')} field="altchaMaxNumber" extra={t('protection.altchaMaxNumberHint')}><InputNumber min={1000} max={50000000} /></Form.Item>
                    <Form.Item label={t('protection.altchaHeader')} field="altchaHeaderName" extra={t('protection.altchaHeaderHint')}><Input /></Form.Item>
                  </div>
                </div>

                <div className="protection-section-card">
                  <header>
                    <strong><ImageIcon size={15} /> {t('protection.imageCaptcha')}</strong>
                    <span>{t('protection.imageCaptchaHint')}</span>
                  </header>
                  <div className="protection-form-grid protection-form-grid-compact">
                    <Form.Item label={t('protection.imageCaptchaLength')} field="imageCaptchaLength" extra={t('protection.imageCaptchaLengthHint')}><InputNumber min={4} max={8} /></Form.Item>
                    <Form.Item label={t('protection.imageCaptchaSize')} field="imageCaptchaWidth" extra={t('protection.imageCaptchaSizeHint')}><InputNumber min={160} max={420} /></Form.Item>
                    <Form.Item label={t('protection.imageCaptchaHeight')} field="imageCaptchaHeight"><InputNumber min={60} max={180} /></Form.Item>
                    <Form.Item label={t('protection.imageCaptchaAudioLimit')} field="imageCaptchaAudioLimit" extra={t('protection.imageCaptchaAudioLimitHint')}><InputNumber min={1} max={20} /></Form.Item>
                  </div>
                </div>

                <div className="protection-section-card">
                  <header>
                    <strong><Puzzle size={15} /> {t('protection.sliderCaptcha')}</strong>
                    <span>{t('protection.sliderCaptchaHint')}</span>
                  </header>
                  <div className="protection-form-grid protection-form-grid-compact">
                    <Form.Item label={t('protection.sliderCaptchaWidth')} field="sliderCaptchaWidth"><InputNumber min={240} max={520} /></Form.Item>
                    <Form.Item label={t('protection.sliderCaptchaHeight')} field="sliderCaptchaHeight"><InputNumber min={100} max={260} /></Form.Item>
                    <Form.Item label={t('protection.sliderCaptchaPiece')} field="sliderCaptchaPiece" extra={t('protection.sliderCaptchaPieceHint')}><InputNumber min={32} max={80} /></Form.Item>
                    <Form.Item label={t('protection.sliderCaptchaTolerance')} field="sliderCaptchaTolerance" extra={t('protection.sliderCaptchaToleranceHint')}><InputNumber min={2} max={16} /></Form.Item>
                    <Form.Item className="duration-field" label={t('protection.sliderCaptchaMinDrag')} field="sliderCaptchaMinDrag" extra={t('protection.sliderCaptchaMinDragHint')}><DurationUnitInput units={['ms', 's']} fallback="450ms" /></Form.Item>
                  </div>
                </div>

                <div className="protection-section-card">
                  <header>
                    <strong><Clock3 size={15} /> {t('protection.waitingRoom')}</strong>
                    <span>{t('protection.waitingRoomHint')}</span>
                  </header>
                  <div className="protection-form-grid protection-form-grid-compact">
                    <Form.Item label={t('protection.waitingRoom')} field="waitingRoom" triggerPropName="checked" extra={t('protection.waitingRoomEnabledHint')}><Switch /></Form.Item>
                    <Form.Item label={t('protection.waitingRoomMaxActive')} field="waitingRoomMaxActive" extra={t('protection.waitingRoomMaxActiveHint')}><InputNumber min={1} max={1000000} /></Form.Item>
                    <Form.Item className="duration-field" label={t('protection.waitingRoomTtl')} field="waitingRoomTtl" extra={t('protection.waitingRoomTtlHint')}><DurationUnitInput /></Form.Item>
                  </div>
                </div>
              </div>

              <div className="protection-section-card">
                <header>
                  <strong><Route size={15} /> {t('protection.scopeAndTrust')}</strong>
                  <span>{t('protection.scopeAndTrustHint')}</span>
                </header>
                <div className="protection-form-grid">
                  <Form.Item label={t('protection.cookieName')} field="cookieName" extra={t('protection.cookieNameHint')}><Input /></Form.Item>
                  <Form.Item label={t('protection.secret')} field="secret" extra={t('protection.secretHint')}><Input.Password /></Form.Item>
                  <Form.Item label={t('protection.protectedPaths')} field="protectedPaths" extra={t('protection.protectedPathsHint')}><Input placeholder="/" /></Form.Item>
                  <Form.Item label={t('protection.exemptPaths')} field="exemptPaths" extra={t('protection.exemptPathsHint')}><Input placeholder="/health,/api/" /></Form.Item>
                  <Form.Item label={t('protection.allowedUA')} field="allowedUA" extra={t('protection.allowedUAHint')}><Input /></Form.Item>
                  <Form.Item label={t('protection.suspiciousUA')} field="suspiciousUA" extra={t('protection.suspiciousUAHint')}><Input /></Form.Item>
                </div>
              </div>
            </div>
            <div className="form-action-row">
              <Button type="primary" htmlType="submit" loading={botMutation.isPending}>{t('common.save')}</Button>
            </div>
          </Form>
        </section>

        <section className="panel">
          <div className="panel-heading"><h2><Globe2 size={16} /> {t('protection.geoip')}</h2></div>
          <Form
            key={`geoip-${protection.ip.geoip.enabled}-${protection.ip.whitelist.join('|')}`}
            layout="vertical"
            initialValues={{
              enabled: protection.ip.geoip.enabled,
              database: protection.ip.geoip.database,
              blocked: protection.ip.geoip.blocked_countries,
              whitelist: protection.ip.whitelist.join(','),
              blacklist: protection.ip.blacklist.join(','),
            }}
            onSubmit={(values) => ipMutation.mutate({
              ...protection.ip,
              whitelist: splitList(values.whitelist),
              blacklist: splitList(values.blacklist),
              geoip: { ...protection.ip.geoip, enabled: values.enabled, database: String(values.database ?? '').trim(), blocked_countries: splitList(values.blocked).map((item) => item.toUpperCase()) },
            })}
          >
            <div className="protection-form-grid">
              <Form.Item label={t('protection.geoip')} field="enabled" triggerPropName="checked"><Switch /></Form.Item>
              <Form.Item label={t('protection.geoipDatabase')} field="database"><Input placeholder="/var/lib/cheesewaf/GeoLite2-City.mmdb" /></Form.Item>
              <Form.Item label={t('protection.blockedCountries')} field="blocked" extra={t('protection.blockedCountriesHint')}><GeoRegionSelector /></Form.Item>
              <Form.Item label={t('ip.whitelist')} field="whitelist"><Input /></Form.Item>
              <Form.Item label={t('ip.blacklist')} field="blacklist"><Input /></Form.Item>
            </div>
            <Button type="primary" htmlType="submit" loading={ipMutation.isPending}>{t('common.save')}</Button>
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
          <Button onClick={() => aclMutation.mutate(protection.acl)} loading={aclMutation.isPending}>{t('common.save')}</Button>
        </div>
        <Table
          className="protection-acl-table"
          rowKey="id"
          pagination={false}
          loading={isLoading}
          data={protection.acl.rules}
          columns={[
            { title: t('rules.name'), dataIndex: 'name' },
            { title: 'Method', dataIndex: 'method', render: (method: string) => method || '*' },
            { title: 'Path', dataIndex: 'path_prefix', render: (path: string) => <code className="table-code" title={path || '*'}>{path || '*'}</code> },
            {
              title: t('logs.action'),
              dataIndex: 'action',
              render: (action: string) => (
                <span className="status-group">
                  <Tag color={action === 'block' ? 'red' : 'blue'}>{displayAction(action, t)}</Tag>
                </span>
              ),
            },
            { title: t('rules.enabled'), dataIndex: 'enabled', render: (_: boolean, record: ACLRule) => <Switch checked={record.enabled} size="small" /> },
          ]}
        />
        <div className="protection-acl-cards">
          {protection.acl.rules.map((rule) => (
            <article className="protection-acl-card" key={rule.id}>
              <header>
                <strong>{rule.name}</strong>
                <Switch checked={rule.enabled} size="small" />
              </header>
              <div>
                <span>Method</span>
                <strong>{rule.method || '*'}</strong>
              </div>
              <div>
                <span>Path</span>
                <code>{rule.path_prefix || '*'}</code>
              </div>
              <div>
                <span>{t('logs.action')}</span>
                <Tag color={rule.action === 'block' ? 'red' : 'blue'}>{displayAction(rule.action, t)}</Tag>
              </div>
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
      value={selected}
      placeholder={t('protection.blockedCountriesPlaceholder')}
      onChange={(next) => onChange?.((Array.isArray(next) ? next : []).map((item) => String(item).toUpperCase()))}
    >
      {geoRegionOptions.map((code) => (
        <Select.Option key={code} value={code}>
          {t(`geo.countries.${code}`, { defaultValue: code })} ({code})
        </Select.Option>
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

function ProtectionLevelSelect({ value, onChange }: { value?: string; onChange?: (value: string) => void }) {
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
