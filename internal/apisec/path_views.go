package apisec

import "regexp"

func matchesEndpointPath(pattern *regexp.Regexp, paths []string) bool {
	for _, path := range paths {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}
