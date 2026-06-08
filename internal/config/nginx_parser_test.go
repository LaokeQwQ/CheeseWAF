package config

import "testing"

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
