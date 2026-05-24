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
