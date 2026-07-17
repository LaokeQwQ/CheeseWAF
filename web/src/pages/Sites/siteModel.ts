import type { Site, SiteAdvanced } from '../../types/api';

export const defaultSiteAdvanced: SiteAdvanced = {
  certificate: {
    mode: 'file',
    cert_pem: '',
    key_pem: '',
    auto_renew: false,
    force_https: false,
    hsts: true,
    min_tls_version: '1.2',
    acme: {
      provider_id: '',
      dns_api: 'dns_cf',
      account_email: '',
      server: 'letsencrypt',
      key_type: 'ec-256',
      acme_sh_path: 'acme.sh',
      home: '',
      cert_dir: '',
      reload_command: '',
      domains: [],
      env: {},
      notify: true,
      last_status: '',
      last_run_id: '',
    },
  },
  origin: {
    scheme: 'http',
    pass_host: true,
    host_header: '',
    proxy_timeout: '30s',
    max_body_bytes: 64 * 1024 * 1024,
    max_header_size: 1024 * 1024,
  },
  health_check: {
    enabled: false,
    path: '/',
    interval: '30s',
    timeout: '3s',
    healthy_threshold: 1,
    unhealthy_threshold: 3,
  },
  protection: {
    semantic_sql: true,
    semantic_xss: true,
    semantic_rce: true,
    semantic_lfi: true,
    semantic_xxe: true,
    semantic_ssrf: true,
    semantic_nosql: true,
    semantic_ssti: true,
    bot: false,
    ratelimit: true,
    acl: true,
    apisec: true,
  },
  semantic_policy: {
    budget_exhausted_policy: 'auto',
    path_allowlist: [],
    param_allowlist: [],
  },
  policy: {
    web_attack: '',
    api_security: '',
    bot_cc: '',
    threat_intel: '',
  },
  response: {
    enabled: true,
    max_body_bytes: 2 * 1024 * 1024,
    sensitive_patterns: ['AKIA', 'password', 'secret', 'private key'],
  },
  rewrite: [],
  access_control: {
    auth_enabled: false,
    waiting_room: false,
    dynamic_guard: true,
    trusted_cidrs: [],
  },
  access_log_enabled: true,
};

export const defaultSite: Site = {
  id: '',
  name: '',
  domains: [],
  upstreams: [],
  listen_port: 80,
  loadbalance: 'round_robin',
  enable_ssl: false,
  cert_file: '',
  key_file: '',
  waf_enabled: true,
  waf_mode: 'block',
  advanced: defaultSiteAdvanced,
  enabled: true,
};

export function normalizeSite(input?: Partial<Site>): Site {
  const advanced = input?.advanced ?? defaultSiteAdvanced;
  return {
    ...defaultSite,
    ...input,
    domains: asArray(input?.domains),
    upstreams: asArray(input?.upstreams),
    advanced: {
      ...defaultSiteAdvanced,
      ...advanced,
      certificate: {
        ...defaultSiteAdvanced.certificate,
        ...advanced.certificate,
        acme: {
          ...defaultSiteAdvanced.certificate.acme,
          ...advanced.certificate?.acme,
          domains: asArray(advanced.certificate?.acme?.domains),
          env: advanced.certificate?.acme?.env ?? {},
        },
      },
      origin: { ...defaultSiteAdvanced.origin, ...advanced.origin },
      health_check: { ...defaultSiteAdvanced.health_check, ...advanced.health_check },
      protection: { ...defaultSiteAdvanced.protection, ...advanced.protection },
      semantic_policy: {
        ...defaultSiteAdvanced.semantic_policy,
        ...advanced.semantic_policy,
        path_allowlist: asArray(advanced.semantic_policy?.path_allowlist),
        param_allowlist: asArray(advanced.semantic_policy?.param_allowlist),
      },
      policy: { ...defaultSiteAdvanced.policy, ...advanced.policy },
      response: {
        ...defaultSiteAdvanced.response,
        ...advanced.response,
        sensitive_patterns: asArray(advanced.response?.sensitive_patterns),
      },
      rewrite: asArray(advanced.rewrite),
      access_control: {
        ...defaultSiteAdvanced.access_control,
        ...advanced.access_control,
        trusted_cidrs: asArray(advanced.access_control?.trusted_cidrs),
      },
      access_log_enabled: advanced.access_log_enabled ?? defaultSiteAdvanced.access_log_enabled ?? true,
    },
  };
}

export function splitList(value: unknown) {
  return String(value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function asCSV(value: unknown[]) {
  return value.join(', ');
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}
