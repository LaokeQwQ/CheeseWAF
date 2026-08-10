package config

import (
	"strings"
	"testing"
)

func TestCAPTCHAAssetQuotaDefaultsAndValidation(t *testing.T) {
	defaults := Default().CAPTCHAAssets.Limits
	if defaults.MaxAssets != 512 || defaults.MaxTotalBytes != 512<<20 {
		t.Fatalf("unexpected CAPTCHA asset quota defaults: %+v", defaults)
	}

	tests := []struct {
		name string
		edit func(*CAPTCHAAssetLimits)
		want string
	}{
		{name: "zero count", edit: func(l *CAPTCHAAssetLimits) { l.MaxAssets = 0 }, want: "max_assets"},
		{name: "excess count", edit: func(l *CAPTCHAAssetLimits) { l.MaxAssets = 4_097 }, want: "max_assets"},
		{name: "small total", edit: func(l *CAPTCHAAssetLimits) { l.MaxTotalBytes = 64 << 10 }, want: "at least the per-file"},
		{name: "excess total", edit: func(l *CAPTCHAAssetLimits) { l.MaxTotalBytes = 65 << 30 }, want: "max_total_bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.edit(&cfg.CAPTCHAAssets.Limits)
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}
