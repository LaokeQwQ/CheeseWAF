package crp

import (
	"fmt"
	"strconv"
	"strings"
)

// ErrHostIncompatible reports a package that declares a host version range the
// running host does not satisfy.
var ErrHostIncompatible = fmt.Errorf("%w: host version is outside the declared range", ErrInvalidManifest)

// HostCompatibility declares the host versions a package supports. Empty
// bounds are open-ended. Versions are dotted numeric text such as "0.4.5"; a
// leading "v" is accepted and pre-release/build suffixes are ignored for
// ordering, so a running "0.4.5-beta" satisfies a range starting at "0.4.5".
type HostCompatibility struct {
	Min string `json:"min,omitempty"`
	Max string `json:"max,omitempty"`
}

// Check reports whether hostVersion satisfies the declared range. Both bounds
// are inclusive. An unparsable bound or host version is an error: a typo must
// not silently widen the range.
func (h HostCompatibility) Check(hostVersion string) error {
	host, err := parseVersion(hostVersion)
	if err != nil {
		return fmt.Errorf("host version %q: %w", hostVersion, err)
	}
	if min := strings.TrimSpace(h.Min); min != "" {
		bound, err := parseVersion(min)
		if err != nil {
			return fmt.Errorf("%w: host_compatibility.min %q: %v", ErrInvalidManifest, h.Min, err)
		}
		if compareVersion(host, bound) < 0 {
			return fmt.Errorf("%w: host %s is below min %s", ErrHostIncompatible, strings.TrimSpace(hostVersion), min)
		}
	}
	if max := strings.TrimSpace(h.Max); max != "" {
		bound, err := parseVersion(max)
		if err != nil {
			return fmt.Errorf("%w: host_compatibility.max %q: %v", ErrInvalidManifest, h.Max, err)
		}
		if compareVersion(host, bound) > 0 {
			return fmt.Errorf("%w: host %s is above max %s", ErrHostIncompatible, strings.TrimSpace(hostVersion), max)
		}
	}
	return nil
}

// parseVersion normalizes a dotted numeric version into three components.
func parseVersion(value string) ([3]int, error) {
	var parsed [3]int
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "v")
	trimmed = strings.TrimPrefix(trimmed, "V")
	if trimmed == "" {
		return parsed, fmt.Errorf("version is empty")
	}
	// Pre-release and build metadata never affect ordering here.
	if cut := strings.IndexAny(trimmed, "-+"); cut >= 0 {
		trimmed = trimmed[:cut]
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) > 3 {
		return parsed, fmt.Errorf("version has more than three components")
	}
	for index, part := range parts {
		if part == "" {
			return parsed, fmt.Errorf("version has an empty component")
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return parsed, fmt.Errorf("version component %q is not a number", part)
		}
		parsed[index] = number
	}
	return parsed, nil
}

func compareVersion(left, right [3]int) int {
	for index := 0; index < 3; index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}
