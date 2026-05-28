package apisec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestDiscoverNormalizesVariablePaths(t *testing.T) {
	endpoints := Discover([]storage.LogEntry{
		{Timestamp: time.Now(), Method: "GET", URI: "/api/users/123?expand=1", StatusCode: 200},
		{Timestamp: time.Now(), Method: "GET", URI: "/api/users/456", StatusCode: 403, Action: "block"},
	}, config.APIDiscoveryConfig{Window: time.Hour}, time.Now())
	if len(endpoints) != 1 || endpoints[0].Path != "/api/users/{id}" || endpoints[0].Blocked != 1 {
		t.Fatalf("unexpected endpoints: %+v", endpoints)
	}
}

func TestValidatorReportsMissingQueryParam(t *testing.T) {
	validator, err := NewValidator(config.APIValidationConfig{
		Enabled: true,
		Schemas: []config.APIEndpointSchemaConfig{
			{ID: "search", Method: "GET", PathPattern: `^/api/search$`, RequiredParams: []string{"q"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	findings := validator.Validate(httptest.NewRequest(http.MethodGet, "/api/search", nil))
	if len(findings) != 1 || findings[0].Field != "q" {
		t.Fatalf("expected missing q finding, got %+v", findings)
	}
}
