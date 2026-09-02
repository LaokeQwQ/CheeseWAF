import type { NginxImportSite, Site, SiteAdvanced, SiteRewriteRule } from '../../types/api';

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
    promote_seconds: 0,
    auto_agree: false,
    fingerprint_deny: [],
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
    tamper_key: '',
    tamper_snapshots: [],
  },
  rewrite: [],
  custom_rules: [],
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
  paranoia_level: 3,
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
    paranoia_level: normalizeParanoiaLevel(input?.paranoia_level),
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
        promote_seconds: normalizePromoteSeconds(advanced.semantic_policy?.promote_seconds),
        auto_agree: Boolean(advanced.semantic_policy?.auto_agree),
        fingerprint_deny: asArray(advanced.semantic_policy?.fingerprint_deny),
      },
      policy: { ...defaultSiteAdvanced.policy, ...advanced.policy },
      response: {
        ...defaultSiteAdvanced.response,
        ...advanced.response,
        sensitive_patterns: asArray(advanced.response?.sensitive_patterns),
        tamper_snapshots: asArray(advanced.response?.tamper_snapshots),
      },
      rewrite: asArray(advanced.rewrite),
      custom_rules: asArray(advanced.custom_rules),
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

/** Mirrors the backend body limit in internal/api/handler/ops.go (1 MiB). */
export const NGINX_IMPORT_MAX_BYTES = 1 << 20;

/**
 * Why a parsed nginx server block cannot be turned into a site. Empty means the
 * candidate is importable. Values are i18n key suffixes under `sites.import.issue`.
 */
export type NginxImportIssue = '' | 'name' | 'domain' | 'upstream';

export type NginxImportRow = {
  name: string;
  domains: string[];
  upstreams: string[];
  listenPort: number;
  rewrite: SiteRewriteRule[];
  issue: NginxImportIssue;
};

/**
 * Counts `server { ... }` openings the way the backend parser does, so the UI can
 * report how many blocks were dropped (a block with neither server_name nor
 * proxy_pass never reaches the response).
 */
export function countNginxServerBlocks(contents: string): number {
  let count = 0;
  for (const raw of String(contents ?? '').split('\n')) {
    const line = (raw.split('#')[0] ?? '').trim();
    if (line.startsWith('server') && line.includes('{')) {
      count += 1;
    }
  }
  return count;
}

export function nginxImportRows(parsed: NginxImportSite[] | null | undefined): NginxImportRow[] {
  return (Array.isArray(parsed) ? parsed : []).map((site) => {
    const domains = asArray(site.domains).map((item) => String(item ?? '').trim()).filter(Boolean);
    const upstreams = asArray(site.upstreams)
      .map((item) => String((typeof item === 'string' ? item : item?.address) ?? '').trim())
      .filter(Boolean);
    const name = String(site.name ?? '').trim();
    const port = Number(site.listen_port);
    return {
      name,
      domains,
      upstreams,
      listenPort: Number.isInteger(port) && port > 0 && port <= 65535 ? port : 80,
      rewrite: asArray(site.waf?.rewrite).map((rule, index) => ({
        id: rule?.id || `nginx-rewrite-${index + 1}`,
        pattern: String(rule?.pattern ?? ''),
        replacement: String(rule?.replacement ?? ''),
        redirect_code: Number(rule?.redirect_code) || 0,
        enabled: rule?.enabled ?? true,
      })).filter((rule) => rule.pattern !== '' && rule.replacement !== ''),
      // Matches config.Validate: name, at least one domain and one upstream are required.
      issue: !name ? 'name' : domains.length === 0 ? 'domain' : upstreams.length === 0 ? 'upstream' : '',
    };
  });
}

export function nginxImportPayload(row: NginxImportRow): Partial<Site> {
  return {
    name: row.name,
    domains: row.domains,
    upstreams: row.upstreams,
    listen_port: row.listenPort,
    loadbalance: 'round_robin',
    enable_ssl: false,
    waf_enabled: true,
    waf_mode: 'block',
    paranoia_level: 3,
    enabled: true,
    advanced: {
      ...defaultSiteAdvanced,
      access_log_enabled: true,
      rewrite: row.rewrite,
    },
  };
}

function asArray<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

export function normalizeParanoiaLevel(value: unknown): number {
  const level = Number(value);
  if (!Number.isInteger(level) || level < 0 || level > 5) {
    return 3;
  }
  return level;
}

export function normalizePromoteSeconds(value: unknown): number {
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds < 0) {
    return 0;
  }
  return seconds;
}
