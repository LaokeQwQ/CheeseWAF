package setup

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// URLFileName is the first-install browser URL written under the data directory.
const URLFileName = "setup.url"

// BrowserURL is the first-install page, with the token in the URL fragment.
func BrowserURL(scheme, adminListen, token string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(adminListen))
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/setup#setup_token=%s", scheme, net.JoinHostPort(host, port), url.QueryEscape(token))
}

// WriteURL stores the first-install URL next to the data directory.
func WriteURL(dataDir, page string) error {
	page = strings.TrimSpace(page)
	if dataDir == "" || page == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, URLFileName), []byte(page+"\n"), 0o600)
}

// RemoveURL deletes the first-install URL file after setup completes.
func RemoveURL(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	err := os.Remove(filepath.Join(dataDir, URLFileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
