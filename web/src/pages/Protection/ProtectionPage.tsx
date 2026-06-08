import { Button, Form, Input, InputNumber, Select, Switch, Table, Tag } from '@arco-design/web-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Bot, Globe2, ShieldAlert, TimerReset } from 'lucide-react';
import { fetchProtection, updateACLProtection, updateBotProtection, updateIPProtection, updateProtectionPolicy, updateRateLimit } from '../../api/client';
import type { ACLRule, ProtectionConfig } from '../../types/api';
import { displayAction } from '../../utils/display';

const fallback: ProtectionConfig = {
  policy: { web_attack: 'smart', api_security: 'smart', bot_cc: 'smart', threat_intel: 'smart' },
  ip: { whitelist: [], blacklist: [], tags: {}, geoip: { enabled: false, database: '', blocked_countries: [], country_cidrs: {} } },
  ratelimit: { enabled: false, default: { requests: 0, window: '', burst: 0 } },
  bot: {
    enabled: false,
    js_challenge: false,
    captcha: false,
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

export default function ProtectionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['protection'], queryFn: fetchProtection, retry: false });
  const protection = normalizeProtection(data);
  const policyItems = [
    { field: 'web_attack', label: t('sites.webAttackLevel') },
    { field: 'api_security', label: t('sites.apiSecurityLevel') },
    { field: 'bot_cc', label: t('sites.botCCLevel') },
    { field: 'threat_intel', label: t('sites.threatIntelLevel') },
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
          <span className="policy-current-summary">
            {policyItems.map((item) => (
              <span key={item.field}>{item.label}: {policyLevelLabel(protection.policy[item.field], t)}</span>
            ))}
          </span>
        </div>
        <Form
          key={`policy-${Object.values(protection.policy).join('-')}`}
          layout="vertical"
          initialValues={protection.policy}
          onSubmit={(values) => policyMutation.mutate(values as ProtectionConfig['policy'])}
        >
          <div className="policy-level-grid">
            {policyItems.map((item) => (
              <div className="policy-level-card" key={item.field}>
                <span>{item.label}</span>
                <strong>{policyLevelLabel(protection.policy[item.field], t)}</strong>
                <Form.Item label={false} field={item.field}>
                  <ProtectionLevelSelect />
                </Form.Item>
              </div>
            ))}
          </div>
          <Button type="primary" htmlType="submit" loading={policyMutation.isPending}>{t('common.save')}</Button>
        </Form>
      </section>

      <div className="settings-grid">
        <section className="panel">
          <div className="panel-heading"><h2><Bot size={16} /> {t('protection.bot')}</h2></div>
          <Form
            key={`bot-${protection.bot.enabled}-${protection.bot.cookie_name}`}
            layout="vertical"
            initialValues={{
              enabled: protection.bot.enabled,
              jsChallenge: protection.bot.js_challenge,
              captcha: protection.bot.captcha,
              challengeDifficulty: protection.bot.challenge_difficulty,
              altchaMaxNumber: protection.bot.altcha_max_number,
              altchaHeaderName: protection.bot.altcha_header_name,
              waitingRoom: protection.bot.waiting_room,
              waitingRoomMaxActive: protection.bot.waiting_room_max_active,
              waitingRoomTtl: String(protection.bot.waiting_room_ttl),
              challengeTtl: String(protection.bot.challenge_ttl),
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
              challenge_difficulty: values.challengeDifficulty,
              altcha_max_number: values.altchaMaxNumber,
              altcha_header_name: values.altchaHeaderName,
              waiting_room: values.waitingRoom,
              waiting_room_max_active: values.waitingRoomMaxActive,
              waiting_room_ttl: values.waitingRoomTtl,
              challenge_ttl: values.challengeTtl,
              cookie_name: values.cookieName,
              secret: values.secret,
              path_prefixes: splitList(values.protectedPaths),
              exempt_path_prefixes: splitList(values.exemptPaths),
              allowed_user_agents: splitList(values.allowedUA),
              suspicious_user_agents: splitList(values.suspiciousUA),
            })}
          >
            <Form.Item label={t('protection.bot')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('protection.jsChallenge')} field="jsChallenge"><Switch /></Form.Item>
            <Form.Item label={t('protection.captcha')} field="captcha"><Switch /></Form.Item>
            <Form.Item label={t('protection.challengeDifficulty')} field="challengeDifficulty"><InputNumber min={1} max={6} /></Form.Item>
            <Form.Item label={t('protection.altchaMaxNumber')} field="altchaMaxNumber"><InputNumber min={1000} max={50000000} /></Form.Item>
            <Form.Item label={t('protection.altchaHeader')} field="altchaHeaderName"><Input /></Form.Item>
            <Form.Item label={t('protection.waitingRoom')} field="waitingRoom"><Switch /></Form.Item>
            <Form.Item label={t('protection.waitingRoomMaxActive')} field="waitingRoomMaxActive"><InputNumber min={1} max={1000000} /></Form.Item>
            <Form.Item label={t('protection.waitingRoomTtl')} field="waitingRoomTtl"><Input placeholder="5m" /></Form.Item>
            <Form.Item label={t('protection.challengeTtl')} field="challengeTtl"><Input placeholder="30m" /></Form.Item>
            <Form.Item label={t('protection.cookieName')} field="cookieName"><Input /></Form.Item>
            <Form.Item label={t('protection.secret')} field="secret"><Input.Password /></Form.Item>
            <Form.Item label={t('protection.protectedPaths')} field="protectedPaths"><Input placeholder="/" /></Form.Item>
            <Form.Item label={t('protection.exemptPaths')} field="exemptPaths"><Input placeholder="/health,/api/" /></Form.Item>
            <Form.Item label={t('protection.allowedUA')} field="allowedUA"><Input /></Form.Item>
            <Form.Item label={t('protection.suspiciousUA')} field="suspiciousUA"><Input /></Form.Item>
            <Button type="primary" htmlType="submit" loading={botMutation.isPending}>{t('common.save')}</Button>
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
              blocked: protection.ip.geoip.blocked_countries.join(','),
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
            <Form.Item label={t('protection.geoip')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('protection.geoipDatabase')} field="database"><Input placeholder="/var/lib/cheesewaf/GeoLite2-City.mmdb" /></Form.Item>
            <Form.Item label={t('protection.blockedCountries')} field="blocked"><Input placeholder="CN,RU" /></Form.Item>
            <Form.Item label={t('ip.whitelist')} field="whitelist"><Input /></Form.Item>
            <Form.Item label={t('ip.blacklist')} field="blacklist"><Input /></Form.Item>
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
            <Form.Item label={t('common.online')} field="enabled"><Switch /></Form.Item>
            <Form.Item label={t('protection.requests')} field="requests"><InputNumber min={1} max={100000} /></Form.Item>
            <Form.Item label={t('protection.burst')} field="burst"><InputNumber min={0} max={10000} /></Form.Item>
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
      </section>
    </section>
  );
}

function splitList(value: unknown) {
  return String(value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
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
      tags: next.ip?.tags ?? {},
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
  return (
    <Select className="protection-level-select" value={value || 'smart'} onChange={(next) => onChange?.(String(next))}>
      <Select.Option value="off">{t('sites.levelOff')}</Select.Option>
      <Select.Option value="low">{t('sites.levelLow')}</Select.Option>
      <Select.Option value="smart">{t('sites.levelSmart')}</Select.Option>
      <Select.Option value="high">{t('sites.levelHigh')}</Select.Option>
      <Select.Option value="strict">{t('sites.levelStrict')}</Select.Option>
    </Select>
  );
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
