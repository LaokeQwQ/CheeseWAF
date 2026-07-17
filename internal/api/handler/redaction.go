package handler

import (
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type secretStatus struct {
	Set bool `json:"set"`
}

type acmeDNSProviderView struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	API     string            `json:"api"`
	Env     map[string]string `json:"env,omitempty"`
	EnvKeys []string          `json:"env_keys,omitempty"`
	EnvSet  bool              `json:"env_set"`
	Enabled bool              `json:"enabled"`
}

type siteACMEView struct {
	ProviderID    string            `json:"provider_id"`
	DNSAPI        string            `json:"dns_api"`
	AccountEmail  string            `json:"account_email"`
	Server        string            `json:"server"`
	KeyType       string            `json:"key_type"`
	ACMESHPath    string            `json:"acme_sh_path"`
	Home          string            `json:"home"`
	CertDir       string            `json:"cert_dir"`
	ReloadCommand string            `json:"reload_command"`
	Domains       []string          `json:"domains"`
	Env           map[string]string `json:"env,omitempty"`
	EnvKeys       []string          `json:"env_keys,omitempty"`
	EnvSet        bool              `json:"env_set"`
	Notify        bool              `json:"notify"`
	LastStatus    string            `json:"last_status"`
	LastRunID     string            `json:"last_run_id"`
	LastIssuedAt  time.Time         `json:"last_issued_at,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at,omitempty"`
}

func systemConfigView(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{"version": nil}
	}
	return map[string]any{
		"server":        cfg.Server,
		"time_sync":     cfg.TimeSync,
		"tls":           cfg.TLS,
		"storage":       storageConfigView(cfg.Storage),
		"logging":       cfg.Logging,
		"console":       consoleConfigView(cfg.Console),
		"acme":          acmeConfigView(cfg.ACME),
		"protection":    protectionConfigView(cfg.Protection),
		"setup":         cfg.Setup,
		"scheduler":     cfg.Scheduler,
		"edge":          cfg.Edge,
		"ai":            aiConfigView(cfg.AI),
		"update":        cfg.Update,
		"vulnerability": cfg.Vulnerability,
		"monitor":       monitorConfigView(cfg.Monitor),
		"apisec":        apiSecConfigView(cfg.APISec),
		"block_page":    cfg.BlockPage,
	}
}

func storageConfigView(in config.StorageConfig) config.StorageConfig {
	out := in
	out.ClickHouse.Password = ""
	out.PostgreSQL.DSN = ""
	out.Elasticsearch.Password = ""
	out.Elasticsearch.APIKey = ""
	out.Elasticsearch.Headers = redactStringMap(out.Elasticsearch.Headers)
	return out
}

func consoleConfigView(in config.ConsoleConfig) config.ConsoleConfig {
	out := in
	return out
}

func acmeConfigView(in config.ACMEConfig) map[string]any {
	providers := make([]acmeDNSProviderView, 0, len(in.DNSProviders))
	for _, provider := range in.DNSProviders {
		keys := sortedMapKeys(provider.Env)
		providers = append(providers, acmeDNSProviderView{
			ID:      provider.ID,
			Name:    provider.Name,
			API:     provider.API,
			Env:     redactStringMap(provider.Env),
			EnvKeys: keys,
			EnvSet:  len(keys) > 0,
			Enabled: provider.Enabled,
		})
	}
	return map[string]any{
		"enabled":        in.Enabled,
		"acme_sh_path":   in.ACMESHPath,
		"home":           in.Home,
		"server":         in.Server,
		"account_email":  in.AccountEmail,
		"cert_dir":       in.CertDir,
		"key_type":       in.KeyType,
		"reload_command": in.ReloadCommand,
		"dns_providers":  providers,
		"notify":         in.Notify,
	}
}

func protectionConfigView(in config.ProtectionConfig) config.ProtectionConfig {
	out := in
	out.Bot.Secret = ""
	out.IP.Providers = append([]config.ThreatIntelProviderConfig(nil), in.IP.Providers...)
	for idx := range out.IP.Providers {
		out.IP.Providers[idx].APIKey = ""
		out.IP.Providers[idx].Headers = redactStringMap(out.IP.Providers[idx].Headers)
	}
	return out
}

func monitorConfigView(in config.MonitorConfig) config.MonitorConfig {
	out := in
	out.Notifiers = append([]config.NotifierConfig(nil), in.Notifiers...)
	for idx := range out.Notifiers {
		out.Notifiers[idx].Token = ""
		out.Notifiers[idx].Headers = redactStringMap(out.Notifiers[idx].Headers)
	}
	return out
}

func apiSecConfigView(in config.APISecConfig) config.APISecConfig {
	out := in
	out.Auth.JWTSharedSecret = ""
	out.Auth.JWTPublicKeyPEM = ""
	out.Auth.JWKSJSON = ""
	out.ManagementAPI.Tokens = append([]config.ManagementAPITokenConfig(nil), in.ManagementAPI.Tokens...)
	for idx := range out.ManagementAPI.Tokens {
		out.ManagementAPI.Tokens[idx].Hash = ""
	}
	return out
}

func siteView(site storage.Site) storage.Site {
	out := site
	out.Advanced.Certificate.KeyPEM = ""
	out.Advanced.Certificate.ACME.Env = redactStringMap(out.Advanced.Certificate.ACME.Env)
	return out
}

// preserveSiteSecrets restores redacted secrets when the client omits them on update.
func preserveSiteSecrets(existing *storage.Site, next *storage.Site) {
	if existing == nil || next == nil {
		return
	}
	if strings.TrimSpace(next.Advanced.Certificate.KeyPEM) == "" {
		next.Advanced.Certificate.KeyPEM = existing.Advanced.Certificate.KeyPEM
	}
	next.Advanced.Certificate.ACME.Env = preserveStringMapSecrets(
		existing.Advanced.Certificate.ACME.Env,
		next.Advanced.Certificate.ACME.Env,
	)
}

func siteACMEConfigView(in storage.SiteACMEConfig) siteACMEView {
	keys := sortedMapKeys(in.Env)
	return siteACMEView{
		ProviderID:    in.ProviderID,
		DNSAPI:        in.DNSAPI,
		AccountEmail:  in.AccountEmail,
		Server:        in.Server,
		KeyType:       in.KeyType,
		ACMESHPath:    in.ACMESHPath,
		Home:          in.Home,
		CertDir:       in.CertDir,
		ReloadCommand: in.ReloadCommand,
		Domains:       in.Domains,
		Env:           redactStringMap(in.Env),
		EnvKeys:       keys,
		EnvSet:        len(keys) > 0,
		Notify:        in.Notify,
		LastStatus:    in.LastStatus,
		LastRunID:     in.LastRunID,
		LastIssuedAt:  in.LastIssuedAt,
		ExpiresAt:     in.ExpiresAt,
	}
}

func sitesView(sites []storage.Site) []storage.Site {
	out := make([]storage.Site, len(sites))
	for idx, site := range sites {
		out[idx] = siteView(site)
	}
	return out
}

func preserveSystemSecrets(current config.Config, next *config.Config) {
	if next == nil {
		return
	}
	if next.Storage.ClickHouse.Password == "" {
		next.Storage.ClickHouse.Password = current.Storage.ClickHouse.Password
	}
	if next.Storage.PostgreSQL.DSN == "" {
		next.Storage.PostgreSQL.DSN = current.Storage.PostgreSQL.DSN
	}
	if next.Storage.Elasticsearch.Password == "" {
		next.Storage.Elasticsearch.Password = current.Storage.Elasticsearch.Password
	}
	if next.Storage.Elasticsearch.APIKey == "" {
		next.Storage.Elasticsearch.APIKey = current.Storage.Elasticsearch.APIKey
	}
	next.Storage.Elasticsearch.Headers = preserveStringMapSecrets(current.Storage.Elasticsearch.Headers, next.Storage.Elasticsearch.Headers)
	next.ACME.DNSProviders = preserveACMEDNSProviderSecrets(current.ACME.DNSProviders, next.ACME.DNSProviders)
	if next.Protection.Bot.Secret == "" {
		next.Protection.Bot.Secret = current.Protection.Bot.Secret
	}
	next.Protection.IP.Providers = preserveThreatIntelProviderSecrets(current.Protection.IP.Providers, next.Protection.IP.Providers)
	next.Monitor.Notifiers = preserveNotifierSecrets(current.Monitor.Notifiers, next.Monitor.Notifiers)
	if next.APISec.Auth.JWTSharedSecret == "" {
		next.APISec.Auth.JWTSharedSecret = current.APISec.Auth.JWTSharedSecret
	}
	if next.APISec.Auth.JWTPublicKeyPEM == "" {
		next.APISec.Auth.JWTPublicKeyPEM = current.APISec.Auth.JWTPublicKeyPEM
	}
	if next.APISec.Auth.JWKSJSON == "" {
		next.APISec.Auth.JWKSJSON = current.APISec.Auth.JWKSJSON
	}
	next.APISec.ManagementAPI.Tokens = preserveManagementAPITokenSecrets(current.APISec.ManagementAPI.Tokens, next.APISec.ManagementAPI.Tokens)
}

func preserveManagementAPITokenSecrets(current, next []config.ManagementAPITokenConfig) []config.ManagementAPITokenConfig {
	byID := map[string]config.ManagementAPITokenConfig{}
	for _, token := range current {
		byID[token.ID] = token
	}
	for idx := range next {
		if existing, ok := byID[next[idx].ID]; ok {
			if next[idx].Hash == "" {
				next[idx].Hash = existing.Hash
			}
			if next[idx].Prefix == "" {
				next[idx].Prefix = existing.Prefix
			}
			if next[idx].CreatedAt.IsZero() {
				next[idx].CreatedAt = existing.CreatedAt
			}
		}
	}
	return next
}

func preserveACMEDNSProviderSecrets(current, next []config.ACMEDNSProviderConfig) []config.ACMEDNSProviderConfig {
	byID := map[string]config.ACMEDNSProviderConfig{}
	for _, provider := range current {
		byID[provider.ID] = provider
	}
	for idx := range next {
		if existing, ok := byID[next[idx].ID]; ok {
			next[idx].Env = preserveStringMapSecrets(existing.Env, next[idx].Env)
		}
	}
	return next
}

func preserveThreatIntelProviderSecrets(current, next []config.ThreatIntelProviderConfig) []config.ThreatIntelProviderConfig {
	byID := map[string]config.ThreatIntelProviderConfig{}
	for _, provider := range current {
		byID[provider.ID] = provider
	}
	for idx := range next {
		if existing, ok := byID[next[idx].ID]; ok {
			if next[idx].APIKey == "" {
				next[idx].APIKey = existing.APIKey
			}
			next[idx].Headers = preserveStringMapSecrets(existing.Headers, next[idx].Headers)
		}
	}
	return next
}

func preserveNotifierSecrets(current, next []config.NotifierConfig) []config.NotifierConfig {
	byID := map[string]config.NotifierConfig{}
	for _, notifier := range current {
		byID[notifier.ID] = notifier
	}
	for idx := range next {
		if existing, ok := byID[next[idx].ID]; ok {
			if next[idx].Token == "" {
				next[idx].Token = existing.Token
			}
			next[idx].Headers = preserveStringMapSecrets(existing.Headers, next[idx].Headers)
		}
	}
	return next
}

func preserveStringMapSecrets(current, next map[string]string) map[string]string {
	if len(current) == 0 {
		return next
	}
	if next == nil {
		next = map[string]string{}
	}
	for key, value := range current {
		if next[key] == "" {
			next[key] = value
		}
	}
	return next
}

func redactStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]string, len(in))
	for key := range in {
		out[key] = ""
	}
	return out
}

func sortedMapKeys(in map[string]string) []string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
