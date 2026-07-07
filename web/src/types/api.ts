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
  policy: ProtectionPolicyConfig;
  response: SiteResponseConfig;
  rewrite: SiteRewriteRule[];
  access_control: SiteAccessControl;
};

export type ProtectionLevel = 'off' | 'low' | 'smart' | 'high' | 'strict' | '';

export type ProtectionPolicyConfig = {
  web_attack: ProtectionLevel;
  api_security: ProtectionLevel;
  bot_cc: ProtectionLevel;
  threat_intel: ProtectionLevel;
};

export type SiteCertificateConfig = {
  mode: 'file' | 'inline' | 'acme' | string;
  cert_pem?: string;
  key_pem?: string;
  auto_renew: boolean;
  force_https: boolean;
  hsts: boolean;
  min_tls_version: string;
  acme: SiteACMEConfig;
};

export type SiteACMEConfig = {
  provider_id: string;
  dns_api: string;
  account_email: string;
  server: string;
  key_type: string;
  acme_sh_path: string;
  home: string;
  cert_dir: string;
  reload_command: string;
  domains: string[];
  env: Record<string, string>;
  notify: boolean;
  last_status?: string;
  last_run_id?: string;
  last_issued_at?: string;
  expires_at?: string;
};

export type ACMEDNSProvider = {
  id: string;
  name: string;
  api: string;
  env?: Record<string, string>;
  enabled: boolean;
};

export type ACMEEvent = {
  step: string;
  status: 'pending' | 'running' | 'succeeded' | 'failed' | string;
  message?: string;
  output?: string;
  timestamp: string;
};

export type ACMEIssueRequest = {
  provider_id: string;
  dns_api: string;
  dns_env: Record<string, string>;
  account_email: string;
  server: string;
  key_type: string;
  auto_renew: boolean;
  notify: boolean;
};

export type ACMEIssueResult = {
  run_id: string;
  site_id: string;
  domains: string[];
  cert_file: string;
  key_file: string;
  fullchain: string;
  key_type: string;
  server: string;
  dns_api: string;
  events: ACMEEvent[];
  issued_at: string;
  renew_after?: string;
  auto_renew: boolean;
  notify: boolean;
  elapsed_ms: number;
  provider_id?: string;
  primary_name: string;
};

export type ACMEIssueResponse = {
  site: Site;
  result: ACMEIssueResult;
  events: ACMEEvent[];
  cert: { cert_file: string; key_file: string };
  issued: boolean;
  acme: SiteACMEConfig;
  summary: { site_id: string; domains: string[]; run_id: string };
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
  semantic_nosql: boolean;
  semantic_ssti: boolean;
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
  policy: ProtectionPolicyConfig;
  ip: {
    whitelist: string[];
    blacklist: string[];
    access_rules: IPAccessRule[];
    reputation_overrides: Record<string, number>;
    geoip: {
      enabled: boolean;
      database: string;
      precision_database: string;
      blocked_countries: string[];
      country_cidrs: Record<string, string[]>;
    };
    tags: Record<string, string[]>;
    threat_intel: ThreatIntelIndicator[];
    providers: ThreatIntelProvider[];
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
    captcha_type: 'pow' | 'image' | 'slider' | string;
    captcha_max_attempts: number;
    image_captcha_length: number;
    image_captcha_width: number;
    image_captcha_height: number;
    image_captcha_audio_limit: number;
    slider_captcha_width: number;
    slider_captcha_height: number;
    slider_captcha_piece: number;
    slider_captcha_tolerance: number;
    slider_captcha_min_drag: number | string;
    slider_captcha_track_required: boolean;
    captcha_mobile_type: 'pow' | 'image' | string;
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

export type StorageCleanupResult = {
  cleaned: boolean;
  target: string;
  keep: number;
  scanned: number;
  removed: number;
  timestamp: string;
};

export type BlockTemplate = {
  id: string;
  name: string;
  description: string;
  html: string;
};

export type BlockPageConfig = {
  template_id: string;
  custom_enabled: boolean;
  custom_html: string;
};

export type BlockPagePreview = {
  html: string;
  event_id: string;
  trace_id: string;
  status: number;
};

export type AIConfig = {
  enabled: boolean;
  provider: 'openai' | 'anthropic' | string;
  api_base: string;
  api_key?: string;
  api_key_set: boolean;
  model: string;
  async: boolean;
  allow_private_api_base: boolean;
  assistant?: AIModelConfig;
  reasoning?: AIModelConfig;
  self_learning?: AISelfLearningConfig;
  knowledge?: AIKnowledgeConfig;
};

export type AIModelConfig = {
  provider: 'openai' | 'anthropic' | string;
  api_base: string;
  api_key?: string;
  api_key_set: boolean;
  model: string;
  allow_private_api_base: boolean;
};

export type AISelfLearningConfig = {
  enabled: boolean;
  auto_apply: boolean;
  dry_run: boolean;
  interval: number | string;
  at: string;
  min_confidence: number;
  min_events: number;
  max_events: number;
  max_rules_per_run: number;
  action: 'block' | 'challenge' | 'log' | string;
};

export type AIKnowledgeConfig = {
  enabled: boolean;
  builtin: boolean;
  max_snippets: number;
};

export type AIModelInfo = {
  id: string;
  owned_by?: string;
  created?: number;
};

export type AISelfLearningReport = {
  started_at: string;
  finished_at: string;
  dry_run: boolean;
  auto_apply: boolean;
  window_start: string;
  window_end: string;
  scanned: number;
  groups: number;
  candidates: AISelfLearningCandidate[];
  applied: Rule[];
  skipped: Array<{ candidate: AISelfLearningCandidate; reason: string }>;
};

export type AISelfLearningCandidate = {
  site_id: string;
  category: string;
  location: string;
  pattern: string;
  action: string;
  severity: string;
  confidence: number;
  event_count: number;
  evidence_ids: string[];
  reason: string;
  ai_reviewed: boolean;
};

export type AttackAnalysis = {
  log_id: string;
  risk: string;
  summary: string;
  reasoning_summary?: string;
  evidence: string[];
  event_type: string;
  ai_used: boolean;
  recommended_actions: string[];
  provider?: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
};

export type AIEventsAnalysisResponse = {
  items: AttackAnalysis[];
  total: number;
};

export type AIAssistantReply = {
  answer: string;
  reasoning_summary?: string;
  ai_used: boolean;
  log_ids: string[];
  events: number;
  blocked: number;
  challenge: number;
  provider?: string;
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  tool_executions?: AIToolExecution[];
  trace?: AIAssistantTraceEvent[];
};

export type AIAssistantTraceEvent = {
  type: string;
  message: string;
  provider?: string;
  model?: string;
  mode?: string;
  tool_name?: string;
  args?: Record<string, unknown>;
  result?: AIToolResult;
  approval?: AIApprovalRequest;
  error?: string;
  at?: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
};

export type AIToolSensitivity = 'read_only' | 'modify' | 'destructive' | string;

export type AIApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executed' | string;

export type AIToolResult = {
  success: boolean;
  output: string;
  diff?: string;
  error?: string;
};

export type AIApprovalRequest = {
  id: string;
  tool_name: string;
  args: Record<string, unknown>;
  sensitivity: number | string;
  diff?: string;
  status: AIApprovalStatus;
  created_at: string;
  decided_at?: string;
};

export type AIToolExecution = {
  name: string;
  description?: string;
  sensitivity: AIToolSensitivity;
  args?: Record<string, unknown>;
  result?: AIToolResult;
  approval?: AIApprovalRequest;
  error?: string;
};

export type AIToolDefinition = {
  name: string;
  description: string;
  sensitivity: AIToolSensitivity;
  parameters: Record<string, unknown>;
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
  start?: string;
  end?: string;
};

export type LogResponse = {
  items: LogEntry[];
  total: number;
};

export type IPReputationEntry = {
  ip: string;
  list: 'whitelist' | 'blacklist' | 'monitor';
  reputation: number;
  reputation_override?: number;
  tags: string[];
  intel: ThreatIntelIndicator[];
  access_rules: IPAccessRuleRef[];
  stats: {
    total: number;
    blocked: number;
    by_type: Record<string, number>;
  };
};

export type IPAccessRule = {
  id: string;
  name: string;
  description: string;
  action: 'allow' | 'block' | 'monitor' | string;
  scope: 'global' | 'site' | 'path' | 'directory' | string;
  site_id: string;
  path_prefix: string;
  entries: string[];
  enabled: boolean;
};

export type IPAccessRuleRef = {
  id: string;
  name: string;
  action: string;
  scope: string;
  site_id?: string;
  path_prefix?: string;
  entries?: string[];
};

export type ThreatIntelIndicator = {
  id: string;
  value: string;
  type: string;
  severity: string;
  source: string;
  labels: string[];
  action?: string;
  confidence?: number;
  enabled?: boolean;
  expires_at?: string;
};

export type ThreatIntelProvider = {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  api_key: string;
  auth_type?: string;
  format: string;
  action: string;
  min_severity: string;
  interval: number | string;
  headers: Record<string, string>;
  notes?: string;
  enabled: boolean;
};

export type IPRulesResponse = {
  whitelist: string[];
  blacklist: string[];
  access_rules: IPAccessRule[];
  reputation_overrides: Record<string, number>;
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

export type LoginCAPTCHAConfig = {
  enabled: boolean;
  mode?: 'slider' | 'pow' | string;
  max_number: number;
  ttl: number | string;
  slider: LoginSliderCAPTCHAConfig;
};

export type LoginSliderCAPTCHAConfig = {
  width: number;
  height: number;
  piece_size: number;
  tolerance: number;
  min_drag: number | string;
  pow_enabled: boolean;
  pow_max_number: number;
};

export type LoginSecurityEntryConfig = {
  enabled: boolean;
  path: string;
  cookie_name: string;
};

export type LoginBackgroundConfig = {
  enabled: boolean;
  type: 'auto' | 'image' | 'video' | string;
  url: string;
};

export type LoginCAPTCHAPayload = {
  mode?: 'slider' | 'pow' | string;
  receipt?: string;
  algorithm?: string;
  challenge?: string;
  number?: number;
  salt?: string;
  signature?: string;
  slider?: LoginSliderCAPTCHAPayload;
};

export type LoginSliderCAPTCHAPayload = {
  token: string;
  x: number;
  drag_ms: number;
  track?: string;
};

export type LoginCAPTCHAChallenge = {
  algorithm: string;
  challenge: string;
  salt: string;
  signature: string;
  max_number: number;
  expires_at?: string;
};

export type LoginSliderCAPTCHAChallenge = {
  width: number;
  height: number;
  piece_size: number;
  track_width: number;
  target_y: number;
  tolerance: number;
  min_drag_ms: number;
  image: string;
  piece?: string;
  token: string;
  expires_at?: string;
};

export type LoginOptions = {
  captcha: {
    enabled: boolean;
    mode?: 'slider' | 'pow' | string;
    algorithm?: string;
    max_number?: number;
    slider?: {
      width: number;
      height: number;
      piece_size: number;
      tolerance: number;
      min_drag_ms: number;
      pow_enabled?: boolean;
      pow_max_number?: number;
    };
  };
  background: LoginBackgroundConfig;
};

export type LoginCAPTCHAResponse = {
  enabled: boolean;
  mode?: 'slider' | 'pow' | string;
  challenge?: LoginCAPTCHAChallenge;
  slider?: LoginSliderCAPTCHAChallenge;
};

export type APISecAuthConfig = {
  enabled: boolean;
  jwt_issuers: string[];
  jwt_audiences: string[];
  required_scopes: string[];
  endpoint_policies: APISecAuthEndpointPolicyConfig[];
  jwt_algorithms: string[];
  jwt_shared_secret: string;
  jwt_public_key_file: string;
  jwt_public_key_pem: string;
  jwks_file: string;
  jwks_json: string;
  jwks_url: string;
  jwks_cache_file: string;
  jwks_refresh_interval: number | string;
};

export type APISecAuthEndpointPolicyConfig = {
  id: string;
  method: string;
  path_pattern: string;
  jwt_issuers: string[];
  jwt_audiences: string[];
  required_scopes: string[];
  enabled: boolean;
};

export type APISecSystemConfig = {
  enabled?: boolean;
  auth?: Partial<APISecAuthConfig>;
  discovery?: Record<string, unknown>;
  validation?: Record<string, unknown>;
  rate_limits?: Array<Record<string, unknown>>;
  [key: string]: unknown;
};

export type SystemConfig = {
  console: {
    login: {
      captcha: LoginCAPTCHAConfig;
      security_entry: LoginSecurityEntryConfig;
      background: LoginBackgroundConfig;
    };
    map: {
      china_boundary: MapBoundaryConfig;
    };
  };
  server: {
    listen: string;
    listen_tls: string;
    listen_http3: string;
    admin_listen: string;
    admin_public: boolean;
    admin_tls: {
      enabled: boolean;
      cert_file: string;
      key_file: string;
      self_signed: boolean;
    };
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
      allow_private_endpoint: boolean;
      database: string;
      table: string;
      username: string;
      password: string;
      timeout: number | string;
    };
    victorialogs: {
      enabled: boolean;
      endpoint: string;
      allow_private_endpoint: boolean;
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
      allow_private_endpoint: boolean;
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
  acme: {
    enabled: boolean;
    acme_sh_path: string;
    home: string;
    server: string;
    account_email: string;
    cert_dir: string;
    key_type: string;
    reload_command: string;
    dns_providers: ACMEDNSProvider[];
    notify: boolean;
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
  apisec: APISecSystemConfig;
  block_page: BlockPageConfig;
  version?: VersionInfo;
};

export type VersionInfo = {
  version: string;
  commit: string;
  build_time: string;
  channel: string;
  edition: string;
  go_version: string;
  platform: string;
};

export type MapBoundaryConfig = {
  enabled: boolean;
  source_type: 'file' | 'url' | string;
  source: string;
  license: string;
  review_id: string;
  attribution: string;
  allow_insecure: boolean;
  allow_private: boolean;
};

export type MapBoundaryResponse = {
  enabled: boolean;
  reason?: string;
  source_type?: string;
  source?: string;
  license?: string;
  review_id?: string;
  attribution?: string;
  geojson?: unknown;
};

export type MonitorSnapshot = {
  generated_at: string;
  uptime_seconds: number;
  goroutines: number;
  process_count?: number;
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
  cpu_count: number;
  cpu_percent: number;
  load1: number;
  memory_total: number;
  memory_used: number;
  memory_percent: number;
  swap_total: number;
  swap_used: number;
  swap_percent: number;
  disk_total: number;
  disk_used: number;
  disk_percent: number;
  sampled_at: string;
};

export type HealthStatus = {
  status: string;
  uptime_seconds: number;
};

export type ClusterStatus = {
  mode: 'standalone' | 'single-node' | 'dual-node-load-balancing' | 'minimum-ha' | 'multi-node-ha' | string;
  enabled: boolean;
  cluster_id?: string;
  node_id?: string;
  product_mode_label: string;
  can_write_config: boolean;
  can_receive_traffic: boolean;
  majority_confirmed: boolean;
  node_count: number;
  waf_node_count: number;
  monitor_node_count: number;
  consensus_provider: string;
  protection_mode_reason?: string;
};

export type ClusterJoinToken = {
  id: string;
  value?: string;
  role: 'waf' | 'monitor' | string;
  expires_at: string;
  max_uses: number;
  used_count: number;
  created_at: string;
  revoked: boolean;
};

export type ClusterJoinTokenList = {
  items: ClusterJoinToken[];
  total: number;
};

export type ClusterJoinTokenCreateRequest = {
  role: 'waf' | 'monitor' | string;
  ttl: string;
  max_uses: number;
};

export type ClusterNodeRegistration = {
  node_id: string;
  role: 'waf' | 'monitor' | string;
  cluster_id: string;
  advertise_addr: string;
  joined_at: string;
  certificate_serial: string;
  certificate_expiry: string;
  revoked: boolean;
  revoked_reason?: string;
};

export type ClusterNodeList = {
  items: ClusterNodeRegistration[];
  total: number;
};

export type ClusterDeploymentRequest = {
  host: string;
  user: string;
  port: number;
  password?: string;
  private_key?: string;
  host_key_sha256?: string;
  action?: 'check' | 'install' | 'restart-service' | string;
};

export type ClusterDeploymentCheckResult = {
  ok: boolean;
  host: string;
  user: string;
  port: number;
  command: string[];
  message?: string;
  checked_at: string;
};

export type ClusterDeploymentRunResult = {
  ok: boolean;
  host: string;
  started_at: string;
  finished_at: string;
  output?: string;
  output_truncated?: boolean;
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
