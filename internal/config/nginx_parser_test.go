package config

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseNginxServerBlock(t *testing.T) {
	sites, err := ParseNginxServerBlock([]byte(`
server {
  listen 8080;
  server_name example.test www.example.test;
  location / {
    proxy_pass http://127.0.0.1:9000;
    rewrite ^/old/(.*)$ /new/$1 break;
  }
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected one site, got %d", len(sites))
	}
	site := sites[0]
	if site.ListenPort != 8080 || site.Name != "example.test" || len(site.Upstreams) != 1 {
		t.Fatalf("unexpected site: %+v", site)
	}
	if len(site.WAF.Rewrite) != 1 || site.WAF.Rewrite[0].Replacement != "/new/$1" {
		t.Fatalf("rewrite not parsed: %+v", site.WAF.Rewrite)
	}
}

func TestParseNginxServerBlockTracksNestedBlocks(t *testing.T) {
	sites, err := ParseNginxServerBlock([]byte(`
server {
  server_name nested.example.test;
  location / {
    if ($request_method = POST) {
      rewrite ^/old$ /new permanent;
    }
    proxy_pass http://127.0.0.1:9000;
  }
  rewrite ^/temporary$ /next redirect;
}
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected one complete server, got %d", len(sites))
	}
	if len(sites[0].Upstreams) != 1 {
		t.Fatalf("directive after nested if was dropped: %+v", sites[0])
	}
	if got := sites[0].WAF.Rewrite; len(got) != 2 || got[0].RedirectCode != 301 || got[1].RedirectCode != 302 {
		t.Fatalf("rewrite status flags were not preserved: %+v", got)
	}
}

func TestParseNginxServerBlockAcceptsOneLineServer(t *testing.T) {
	sites, err := ParseNginxServerBlock([]byte(`server { listen 8081; server_name inline.example.test; location / { proxy_pass http://127.0.0.1:9001; } rewrite ^/old$ /new permanent; }`))
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("expected one inline server, got %d", len(sites))
	}
	if sites[0].ListenPort != 8081 || sites[0].Name != "inline.example.test" || len(sites[0].Upstreams) != 1 {
		t.Fatalf("inline directives not parsed: %+v", sites[0])
	}
	if len(sites[0].WAF.Rewrite) != 1 || sites[0].WAF.Rewrite[0].RedirectCode != http.StatusMovedPermanently {
		t.Fatalf("inline rewrite not parsed: %+v", sites[0].WAF.Rewrite)
	}
}

func TestParseNginxServerBlockAcceptsBoundedMultiMiBLine(t *testing.T) {
	contents := "server {\n#" + strings.Repeat("x", 128<<10) + "\nserver_name long.example.test;\nproxy_pass http://127.0.0.1:9000;\n}\n"
	sites, err := ParseNginxServerBlock([]byte(contents))
	if err != nil {
		t.Fatalf("long nginx line should remain within parser bound: %v", err)
	}
	if len(sites) != 1 || sites[0].Name != "long.example.test" {
		t.Fatalf("unexpected parsed sites: %+v", sites)
	}
}
