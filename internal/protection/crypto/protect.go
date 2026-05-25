package crypto

import (
	"encoding/base64"
	"regexp"
	"strings"
)

func ProtectHTML(html []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(html)
	return []byte(`<!doctype html><meta charset="utf-8"><script>document.write(atob("` + encoded + `"));</script><noscript>JavaScript is required.</noscript>`)
}

func ObfuscateJS(source []byte) []byte {
	text := string(source)
	text = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(text, "")
	lines := strings.Split(text, "\n")
	for idx, line := range lines {
		lines[idx] = strings.TrimSpace(line)
	}
	return []byte(strings.Join(lines, ""))
}
