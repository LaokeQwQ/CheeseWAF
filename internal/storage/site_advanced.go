package storage

import "encoding/json"

const siteAdvancedSchemaVersion = 1

// DecodeStoredSiteAdvanced reads database records, not API request payloads.
func DecodeStoredSiteAdvanced(raw []byte) (SiteAdvanced, error) {
	var value SiteAdvanced
	if err := json.Unmarshal(raw, &value); err != nil {
		return SiteAdvanced{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return SiteAdvanced{}, err
	}
	_, versioned := fields["schema_version"]
	_, websocket := fields["websocket_enabled"]
	_, grpc := fields["grpc_enabled"]
	// Before 0.4.5, every persisted SiteAdvanced lacked both protocol fields.
	// That writer emitted false module switches and http even though runtime
	// ignored them. The same change that activated those settings added both
	// non-omitempty protocol fields, so their presence identifies modern rows.
	if !versioned && !websocket && !grpc {
		value.Protection.Bot = nil
		value.Protection.RateLimit = nil
		value.Protection.ACL = nil
		value.Protection.APISecurity = nil
		value.Origin.Scheme = ""
	}
	if value.SchemaVersion == 0 {
		value.SchemaVersion = siteAdvancedSchemaVersion
	}
	return value, nil
}
