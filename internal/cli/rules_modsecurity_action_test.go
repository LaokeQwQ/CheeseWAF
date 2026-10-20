package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestImportModSecurityPreservesDetectionOnlyAction(t *testing.T) {
	store, cfgPath, siteID := rulesTestStore(t)
	file := filepath.Join(t.TempDir(), "rules.conf")
	body := `SecRule REQUEST_URI "@contains observe" "id:observe,phase:2"
SecRule REQUEST_URI "@contains prevent" "id:prevent,deny,log"`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if count, err := importSiteCustomRules(t.Context(), siteID, file); err != nil || count != 2 {
		t.Fatalf("import = %d, %v", count, err)
	}
	updated, err := store.GetSite(t.Context(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Advanced.CustomRules) != 2 || updated.Advanced.CustomRules[0].Action != "log" || updated.Advanced.CustomRules[1].Action != "block" {
		t.Fatalf("stored import lost action semantics: %+v", updated.Advanced.CustomRules)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rules := loaded.Sites[0].WAF.CustomRules
	if len(rules) != 2 || rules[0].Action != "log" || rules[1].Action != "block" {
		t.Fatalf("persisted config lost action semantics: %+v", rules)
	}
}
