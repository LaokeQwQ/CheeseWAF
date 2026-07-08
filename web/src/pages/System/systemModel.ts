import type { APISecAuthConfig, SystemConfig } from '../../types/api';

export const second = 1_000_000_000;

const fallbackAPIAuth: APISecAuthConfig = {
  enabled: false,
  jwt_issuers: [],
  jwt_audiences: [],
  required_scopes: [],
  endpoint_policies: [],
  jwt_algorithms: [],
  jwt_shared_secret: '',
  jwt_public_key_file: '',
  jwt_public_key_pem: '',
  jwks_file: '',
  jwks_json: '',
  jwks_url: '',
  jwks_cache_file: './data/apisec-jwks-cache.json',
  jwks_refresh_interval: 60 * 60 * second,
};

export const fallbackSystem: SystemConfig = {
  console: {
    login: {
      captcha: {
        enabled: true,
        mode: 'slider',
        max_number: 75000,
        ttl: 120 * second,
        slider: {
          width: 320,
          height: 150,
          piece_size: 42,
          tolerance: 6,
          min_drag: 450_000_000,
          pow_enabled: false,
          pow_max_number: 12000,
        },
      },
      security_entry: { enabled: false, path: '/__cheesewaf-entry', cookie_name: 'cheesewaf_admin_entry' },
      background: { enabled: false, type: 'auto', url: '' },
    },
    map: {
      china_boundary: {
        enabled: false,
        source_type: 'file',
        source: '',
        license: '',
        review_id: '',
        attribution: '',
        allow_insecure: false,
        allow_private: false,
      },
    },
  },
  server: {
    listen: ':80',
    listen_tls: ':443',
    listen_http3: ':443',
    admin_listen: '127.0.0.1:9443',
    admin_public: false,
    admin_tls: { enabled: false, cert_file: './data/certs/admin.crt', key_file: './data/certs/admin.key', self_signed: true },
    read_timeout: 15 * second,
    write_timeout: 30 * second,
    idle_timeout: 60 * second,
    http3: { enabled: false, zero_rtt: false },
  },
  tls: { auto_cert: false, cert_file: '', key_file: '', min_version: '1.3', hsts: true },
  storage: {
    sqlite: { path: './data/cheesewaf.db' },
    redis: { enabled: false, address: '127.0.0.1:6379' },
    clickhouse: { enabled: false, endpoint: '', allow_private_endpoint: false, database: 'cheesewaf', table: 'waf_logs', username: '', password: '', timeout: 5 * second },
    victorialogs: { enabled: false, endpoint: '', allow_private_endpoint: false, timeout: 5 * second },
    postgresql: { enabled: false, dsn: '', table: 'waf_logs', timeout: 5 * second },
    elasticsearch: { enabled: false, endpoint: '', allow_private_endpoint: false, index: 'cheesewaf-logs', username: '', password: '', api_key: '', headers: {}, timeout: 5 * second },
  },
  logging: { level: 'info', format: 'json', output: { type: 'file', file: { path: './logs/access.log', max_size: '100MB', max_backups: 10 } } },
  update: {
    ota: {
      enabled: false,
      server: '',
      channel: 'stable',
      check_interval: 6 * 60 * 60 * second,
      auto_update_rules: true,
      auto_update_binary: false,
      verify_signature: true,
      public_key: '',
    },
  },
  acme: {
    enabled: false,
    acme_sh_path: 'acme.sh',
    home: './data/acme',
    server: 'letsencrypt',
    account_email: '',
    cert_dir: './data/certs',
    key_type: 'ec-256',
    reload_command: '',
    dns_providers: [],
    notify: true,
  },
  vulnerability: { enabled: false, feeds: [] },
  monitor: {},
  apisec: { enabled: false, auth: fallbackAPIAuth, management_api: { enabled: false, tokens: [] } },
  block_page: { template_id: 'minimal', custom_enabled: false, custom_html: '' },
};

export function normalizeSystem(input?: Partial<SystemConfig>): SystemConfig {
  const next = input ?? fallbackSystem;
  return {
    ...fallbackSystem,
    ...next,
    console: {
      ...fallbackSystem.console,
      ...next.console,
      login: {
        ...fallbackSystem.console.login,
        ...next.console?.login,
        captcha: {
          ...fallbackSystem.console.login.captcha,
          ...next.console?.login?.captcha,
          slider: {
            ...fallbackSystem.console.login.captcha.slider,
            ...next.console?.login?.captcha?.slider,
          },
        },
        security_entry: {
          ...fallbackSystem.console.login.security_entry,
          ...next.console?.login?.security_entry,
        },
        background: { ...fallbackSystem.console.login.background, ...next.console?.login?.background },
      },
      map: {
        ...fallbackSystem.console.map,
        ...next.console?.map,
        china_boundary: {
          ...fallbackSystem.console.map.china_boundary,
          ...next.console?.map?.china_boundary,
        },
      },
    },
    server: {
      ...fallbackSystem.server,
      ...next.server,
      admin_tls: { ...fallbackSystem.server.admin_tls, ...next.server?.admin_tls },
      http3: { ...fallbackSystem.server.http3, ...next.server?.http3 },
    },
    tls: { ...fallbackSystem.tls, ...next.tls },
    storage: {
      sqlite: { ...fallbackSystem.storage.sqlite, ...next.storage?.sqlite },
      redis: { ...fallbackSystem.storage.redis, ...next.storage?.redis },
      clickhouse: { ...fallbackSystem.storage.clickhouse, ...next.storage?.clickhouse },
      victorialogs: { ...fallbackSystem.storage.victorialogs, ...next.storage?.victorialogs },
      postgresql: { ...fallbackSystem.storage.postgresql, ...next.storage?.postgresql },
      elasticsearch: { ...fallbackSystem.storage.elasticsearch, ...next.storage?.elasticsearch, headers: next.storage?.elasticsearch?.headers ?? {} },
    },
    logging: {
      ...fallbackSystem.logging,
      ...next.logging,
      output: {
        ...fallbackSystem.logging.output,
        ...next.logging?.output,
        file: { ...fallbackSystem.logging.output.file, ...next.logging?.output?.file },
      },
    },
    update: { ota: { ...fallbackSystem.update.ota, ...next.update?.ota } },
    acme: {
      ...fallbackSystem.acme,
      ...next.acme,
      dns_providers: Array.isArray(next.acme?.dns_providers) ? next.acme.dns_providers : [],
    },
    vulnerability: { ...fallbackSystem.vulnerability, ...next.vulnerability, feeds: Array.isArray(next.vulnerability?.feeds) ? next.vulnerability.feeds : [] },
    monitor: next.monitor ?? {},
    apisec: {
      ...fallbackSystem.apisec,
      ...next.apisec,
      auth: { ...fallbackAPIAuth, ...next.apisec?.auth },
      management_api: {
        enabled: Boolean(next.apisec?.management_api?.enabled),
        tokens: Array.isArray(next.apisec?.management_api?.tokens) ? next.apisec.management_api.tokens : [],
      },
    },
    block_page: { ...fallbackSystem.block_page, ...next.block_page },
  };
}

export function durationSeconds(value: number | string | undefined) {
  if (typeof value === 'number') {
    return Math.max(0, Math.round(value / second));
  }
  const raw = String(value ?? '').trim();
  if (!raw) {
    return 0;
  }
  if (raw.endsWith('ms')) {
    return Math.round(Number(raw.slice(0, -2)) / 1000);
  }
  if (raw.endsWith('m')) {
    return Number(raw.slice(0, -1)) * 60;
  }
  if (raw.endsWith('h')) {
    return Number(raw.slice(0, -1)) * 3600;
  }
  if (raw.endsWith('s')) {
    return Number(raw.slice(0, -1));
  }
  return Number(raw) || 0;
}

export function durationMilliseconds(value: number | string | undefined) {
  if (typeof value === 'number') {
    return Math.max(0, Math.round(value / 1_000_000));
  }
  const raw = String(value ?? '').trim();
  if (!raw) {
    return 0;
  }
  if (raw.endsWith('ms')) {
    return Number(raw.slice(0, -2)) || 0;
  }
  if (raw.endsWith('s')) {
    return (Number(raw.slice(0, -1)) || 0) * 1000;
  }
  if (raw.endsWith('m')) {
    return (Number(raw.slice(0, -1)) || 0) * 60_000;
  }
  return Number(raw) || 0;
}

export function secondsToDuration(value: number | string | null | undefined) {
  return Math.max(1, Number(value || 1)) * second;
}

export function millisecondsToDuration(value: number | string | null | undefined) {
  return Math.max(1, Number(value || 1)) * 1_000_000;
}
