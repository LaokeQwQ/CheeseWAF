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
  target: string;
  keep: number;
  enabled: boolean;
  created_at?: string;
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
