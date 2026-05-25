export type Site = {
  id: string;
  name: string;
  domains: string[];
  upstreams: string[];
  listen_port: number;
  enable_ssl: boolean;
  cert_file?: string;
  key_file?: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
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
  recommended_actions: string[];
};

export type IPReputationEntry = {
  ip: string;
  list: 'whitelist' | 'blacklist' | 'monitor';
  reputation: number;
  tags: string[];
  intel: Array<{
    id: string;
    value: string;
    severity: string;
    source: string;
    labels: string[];
  }>;
  stats: {
    total: number;
    blocked: number;
    by_type: Record<string, number>;
  };
};

export type IPRulesResponse = {
  whitelist: string[];
  blacklist: string[];
  tags: Record<string, string[]>;
  threat_intel: Array<Record<string, unknown>>;
  geoip: ProtectionConfig['ip']['geoip'];
  entries: IPReputationEntry[];
};
