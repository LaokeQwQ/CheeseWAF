package config

// ParseNginxServerBlock is reserved for Phase 2 import support. Keeping the
// entry point here lets API and CLI code depend on a stable package surface.
func ParseNginxServerBlock(_ []byte) ([]SiteConfig, error) {
	return nil, nil
}
