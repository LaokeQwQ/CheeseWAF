export type Site = {
  id: string;
  name: string;
  domains: string[];
  upstreams: string[];
  listen_port: number;
  loadbalance: 'round_robin' | 'weighted' | 'ip_hash' | string;
  enable_ssl: boolean;
  cert_file?: string;
  key_file?: string;
  waf_enabled: boolean;
  waf_mode: 'block' | 'monitor' | 'off' | string;
  advanced: SiteAdvanced;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

export type SiteAdvanced = {
  certificate: SiteCertificateConfig;
  origin: SiteOriginConfig;
  health_check: SiteHealthCheckConfig;
  protection: SiteProtectionConfig;
  response: SiteResponseConfig;
  rewrite: SiteRewriteRule[];
  access_control: SiteAccessControl;
};

export type SiteCertificateConfig = {
  mode: 'file' | 'inline' | 'acme' | string;
  cert_pem?: string;
  key_pem?: string;
  auto_renew: boolean;
  force_https: boolean;
  hsts: boolean;
  min_tls_version: string;
};

export type SiteOriginConfig = {
  scheme: 'http' | 'https' | string;
  pass_host: boolean;
  host_header: string;
  proxy_timeout: number | string;
  max_body_bytes: number;
  max_header_size: number;
};

export type SiteHealthCheckConfig = {
  enabled: boolean;
  path: string;
  interval: number | string;
  timeout: number | string;
  healthy_threshold: number;
  unhealthy_threshold: number;
};

export type SiteProtectionConfig = {
  semantic_sql: boolean;
  semantic_xss: boolean;
  semantic_rce: boolean;
  semantic_lfi: boolean;
  semantic_xxe: boolean;
  semantic_ssrf: boolean;
  bot: boolean;
  ratelimit: boolean;
  acl: boolean;
  apisec: boolean;
};

export type SiteResponseConfig = {
  enabled: boolean;
  max_body_bytes: number;
  sensitive_patterns: string[];
};

export type SiteRewriteRule = {
  id: string;
  pattern: string;
  replacement: string;
  redirect_code: number;
  enabled: boolean;
};

export type SiteAccessControl = {
  auth_enabled: boolean;
  waiting_room: boolean;
  dynamic_guard: boolean;
  trusted_cidrs: string[];
};

export type Rule = {
  id: string;
  site_id: string;
  name: string;
  description: string;
  pattern: string;
  location: string;
  action: string;
  severity: string;
  enabled: boolean;
  priority: number;
};

export type ACLRule = {
  id: string;
  name: string;
  method: string;
  path_prefix: string;
  header: string;
  header_value: string;
  action: string;
  severity: string;
  enabled: boolean;
};

export type ProtectionConfig = {
  ip: {
    whitelist: string[];
    blacklist: string[];
    geoip: {
      enabled: boolean;
      database: string;
      blocked_countries: string[];
      country_cidrs: Record<string, string[]>;
    };
    tags: Record<string, string[]>;
  };
  ratelimit: {
    enabled: boolean;
    default: {
      requests: number;
      window: number | string;
      burst: number;
    };
  };
  bot: {
    enabled: boolean;
    js_challenge: boolean;
    captcha: boolean;
    challenge_difficulty: number;
    altcha_max_number: number;
    altcha_header_name: string;
    waiting_room: boolean;
    waiting_room_max_active: number;
    waiting_room_ttl: number | string;
    challenge_ttl: number | string;
    cookie_name: string;
    secret: string;
    path_prefixes: string[];
    exempt_path_prefixes: string[];
    allowed_user_agents: string[];
    suspicious_user_agents: string[];
  };
  acl: {
    enabled: boolean;
    rules: ACLRule[];
  };
};

export type ScheduledTask = {
  id: string;
  name: string;
  type: string;
  schedule: string;
  every: number | string;
  frequency?: string;
  at?: string;
  target: string;
  channel?: string;
  recipient?: string;
  period?: string;
  format?: string;
  keep: number;
  enabled: boolean;
  created_at?: string;
};

export type EdgeConfig = {
  headers: {
    enabled: boolean;
    rules: Array<{
      id: string;
      name: string;
      operation: 'set' | 'add' | 'delete';
      header: string;
      value: string;
      path_prefix: string;
      enabled: boolean;
    }>;
  };
  cache: {
    enabled: boolean;
    mode: string;
    ttl: number | string;
    status_codes: number[];
    path_prefixes: string[];
    max_body_bytes: number;
  };
  compression: {
    enabled: boolean;
    algorithms: string[];
    level: number;
    min_bytes: number;
    content_types: string[];
  };
};

export type StorageStats = {
  data_dir: string;
  log_dir: string;
  data: number;
  logs: number;
};

export type BlockTemplate = {
  id: string;
  name: string;
  description: string;
  html: string;
};

export type AIConfig = {
  enabled: boolean;
  api_base: string;
  api_key: string;
  api_key_set: boolean;
  model: string;
  async: boolean;
};

export type AttackAnalysis = {
  log_id: string;
  risk: string;
  summary: string;
  evidence: string[];
  event_type: string;
  ai_used: boolean;
  recommended_actions: string[];
};

export type AIEventsAnalysisResponse = {
  items: AttackAnalysis[];
  total: number;
};

export type AIAssistantReply = {
  answer: string;
  ai_used: boolean;
  log_ids: string[];
  events: number;
  blocked: number;
  challenge: number;
};

export type LogEntry = {
  id: string;
  timestamp: string;
  trace_id: string;
  site_id: string;
  client_ip: string;
  method: string;
  uri: string;
  status_code: number;
  action: 'pass' | 'block' | 'challenge' | 'log' | string;
  detector_id: string;
  category: string;
  severity: string;
  message: string;
  payload: string;
  user_agent: string;
  country: string;
  latency: number;
  tags?: string[];
  metadata?: Record<string, unknown>;
};

export type LogQuery = {
  limit?: number;
  site_id?: string;
  client_ip?: string;
  category?: string;
  action?: string;
  trace_id?: string;
};

export type LogResponse = {
  items: LogEntry[];
  total: number;
};

export type IPReputationEntry = {
  ip: string;
  list: 'whitelist' | 'blacklist' | 'monitor';
  reputation: number;
  tags: string[];
  intel: ThreatIntelIndicator[];
  stats: {
    total: number;
    blocked: number;
    by_type: Record<string, number>;
  };
};

export type ThreatIntelIndicator = {
  id: string;
  value: string;
  type: string;
  severity: string;
  source: string;
  labels: string[];
  action?: string;
  enabled?: boolean;
  expires_at?: string;
};

export type ThreatIntelProvider = {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  api_key: string;
  format: string;
  action: string;
  min_severity: string;
  interval: number | string;
  headers: Record<string, string>;
  enabled: boolean;
};

export type IPRulesResponse = {
  whitelist: string[];
  blacklist: string[];
  tags: Record<string, string[]>;
  threat_intel: ThreatIntelIndicator[];
  providers: ThreatIntelProvider[];
  geoip: ProtectionConfig['ip']['geoip'];
  entries: IPReputationEntry[];
};

export type User = {
  id: string;
  username: string;
  role: string;
  two_fa_enabled: boolean;
  created_at?: string;
  updated_at?: string;
};

export type TOTPSetup = {
  secret: string;
  otpauth_url: string;
};

export type SystemConfig = {
  server: {
    listen: string;
    listen_tls: string;
    listen_http3: string;
    admin_listen: string;
    read_timeout: number | string;
    write_timeout: number | string;
    idle_timeout: number | string;
    http3: {
      enabled: boolean;
      zero_rtt: boolean;
    };
  };
  tls: {
    auto_cert: boolean;
    cert_file: string;
    key_file: string;
    min_version: string;
    hsts: boolean;
  };
  storage: {
    sqlite: {
      path: string;
    };
    redis: {
      enabled: boolean;
      address: string;
    };
    clickhouse: {
      enabled: boolean;
      endpoint: string;
      database: string;
      table: string;
      username: string;
      password: string;
      timeout: number | string;
    };
    victorialogs: {
      enabled: boolean;
      endpoint: string;
      timeout: number | string;
    };
    postgresql: {
      enabled: boolean;
      dsn: string;
      table: string;
      timeout: number | string;
    };
    elasticsearch: {
      enabled: boolean;
      endpoint: string;
      index: string;
      username: string;
      password: string;
      api_key: string;
      headers: Record<string, string>;
      timeout: number | string;
    };
  };
  logging: {
    level: string;
    format: string;
    output: {
      type: string;
      file: {
        path: string;
        max_size: string;
        max_backups: number;
      };
    };
  };
  update: {
    ota: {
      enabled: boolean;
      server: string;
      channel: string;
      check_interval: number | string;
      auto_update_rules: boolean;
      auto_update_binary: boolean;
      verify_signature: boolean;
      public_key: string;
    };
  };
  vulnerability: {
    enabled: boolean;
    feeds: Array<{
      id: string;
      name: string;
      type: string;
      url: string;
      interval: number | string;
      min_severity: string;
      notify: boolean;
      enabled: boolean;
    }>;
  };
  monitor: Record<string, unknown>;
  apisec: Record<string, unknown>;
};

export type MonitorSnapshot = {
  generated_at: string;
  uptime_seconds: number;
  goroutines: number;
  memory_alloc: number;
  host: HostStats;
  sites: number;
  requests: number;
  blocked: number;
  challenges: number;
  status_codes: Record<string, number>;
  categories: Record<string, number>;
  disk_usage: Record<string, number>;
};

export type HostStats = {
  os: string;
  cpu_percent: number;
  load1: number;
  memory_total: number;
  memory_used: number;
  memory_percent: number;
  disk_total: number;
  disk_used: number;
  disk_percent: number;
  sampled_at: string;
};

export type HealthStatus = {
  status: string;
  uptime_seconds: number;
};

export type Alert = {
  rule_id: string;
  name: string;
  metric: string;
  value: number;
  threshold: number;
  severity: string;
  message: string;
  starts_at: string;
};

export type MonitorSummary = {
  snapshot: MonitorSnapshot;
  metrics: Record<string, number>;
  alerts: Alert[];
  config: Record<string, unknown>;
};

export type APIEndpoint = {
  method: string;
  path: string;
  count: number;
  blocked: number;
  last_seen: string;
  status_family: Record<string, number>;
};

export type APISecSummary = {
  endpoints: APIEndpoint[];
  config: Record<string, unknown>;
};

export type AuditEntry = {
  timestamp: string;
  user: string;
  role: string;
  method: string;
  path: string;
  status: number;
  remote_ip: string;
  latency_ms: number;
};
