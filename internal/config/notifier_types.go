package config

// NotifierTypes lists the compiled-in notifier types in sorted order. It is the
// single source used by configuration validation; the notifier package asserts
// at test time that every entry has an implementation, so the two cannot drift.
func NotifierTypes() []string {
	return []string{
		"datadog",
		"dingtalk",
		"email",
		"feishu",
		"flashcat",
		"grafana",
		"nightingale",
		"telegram",
		"webhook",
		"wecom",
	}
}
