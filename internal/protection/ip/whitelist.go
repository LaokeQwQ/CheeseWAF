package ip

type Whitelist struct {
	matcher *Matcher
}

func NewWhitelist(entries []string) (*Whitelist, error) {
	matcher, err := NewMatcher(entries)
	if err != nil {
		return nil, err
	}
	return &Whitelist{matcher: matcher}, nil
}

func (w *Whitelist) Allowed(ip string) bool {
	return w != nil && w.matcher.Contains(ip)
}
