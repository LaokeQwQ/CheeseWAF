package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// intel and plugins are restart-only sections. A site/rule save writes the
// whole config document from the live snapshot, so without preserving them an
// operator's YAML edit for the next restart is silently overwritten.
func TestCreateRulePreservesIntelAndPluginSectionsOnDisk(t *testing.T) {
	h, _, site := newSiteTestHandler(t)
	disk, err := config.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	disk.Intel.Sources = []config.IntelSourceConfig{{
		ID: "next-restart", Type: "url", URL: "https://advisory.example.test/feed.xml", Trust: "official", Enabled: true,
	}}
	disk.Plugins = config.PluginsConfig{IndexDir: "/srv/cheesewaf/plugins", WatchInterval: 7 * time.Second}
	if err := config.Save(h.ConfigPath, disk); err != nil {
		t.Fatal(err)
	}
	h.OnSitesChanged = func([]config.SiteConfig) error { return nil }

	router := chi.NewRouter()
	router.Post("/rules", h.CreateRule)
	body := fmt.Sprintf(`{"site_id":%q,"name":"preserve","pattern":"probe","location":"uri","action":"block","severity":"low","enabled":true,"priority":10}`, site.ID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("create rule status = %d: %s", rec.Code, rec.Body.String())
	}
	stored, err := config.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Intel.Sources) != 1 || stored.Intel.Sources[0].ID != "next-restart" {
		t.Fatalf("rule save overwrote intel.sources: %+v", stored.Intel.Sources)
	}
	if stored.Plugins.IndexDir != "/srv/cheesewaf/plugins" || stored.Plugins.WatchInterval != 7*time.Second {
		t.Fatalf("rule save overwrote plugins: %+v", stored.Plugins)
	}
}
