package engine

import "testing"

// FuzzRuleCompile checks the bounded regex compiler used by custom rules and
// detectors. Accepted expressions must be usable; rejected expressions must
// fail closed without panicking.
func FuzzRuleCompile(f *testing.F) {
	for _, seed := range []string{
		`^/api/[a-z]+$`,
		`(a+)+$`,
		`(?P<x>a|b)*`,
		`(`,
		`a{1,999999}`,
		`\p{Greek}+`,
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		if len(pattern) > 64<<10 {
			t.Skip()
		}
		re, err := CompileSafe(pattern)
		if err != nil {
			return
		}
		if re == nil {
			t.Fatal("nil regex without error")
		}
		_ = re.MatchString("fuzz-input")
	})
}
