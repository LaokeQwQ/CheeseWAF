import type { SystemConfig } from '../../types/api';

export const second = 1_000_000_000;

export const fallbackSystem: SystemConfig = {
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
    clickhouse: { enabled: false, endpoint: '', database: 'cheesewaf', table: 'waf_logs', username: '', password: '', timeout: 5 * second },
    victorialogs: { enabled: false, endpoint: '', timeout: 5 * second },
    postgresql: { enabled: false, dsn: '', table: 'waf_logs', timeout: 5 * second },
    elasticsearch: { enabled: false, endpoint: '', index: 'cheesewaf-logs', username: '', password: '', api_key: '', headers: {}, timeout: 5 * second },
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
  vulnerability: { enabled: false, feeds: [] },
  monitor: {},
  apisec: {},
};

export function normalizeSystem(input?: Partial<SystemConfig>): SystemConfig {
  const next = input ?? fallbackSystem;
  return {
    ...fallbackSystem,
    ...next,
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
    vulnerability: { ...fallbackSystem.vulnerability, ...next.vulnerability, feeds: Array.isArray(next.vulnerability?.feeds) ? next.vulnerability.feeds : [] },
    monitor: next.monitor ?? {},
    apisec: next.apisec ?? {},
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

export function secondsToDuration(value: number | string | null | undefined) {
  return Math.max(1, Number(value || 1)) * second;
}
