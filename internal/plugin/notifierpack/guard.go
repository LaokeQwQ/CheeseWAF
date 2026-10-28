package notifierpack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrExecutableContent reports a pack that tries to carry code, an artifact, or
// install instructions. A descriptor is metadata only; runtime delivery stays
// in the core, so any such field is a contract violation rather than a feature
// this host forgot to implement.
var ErrExecutableContent = errors.New("notifier pack must not contain executable content")

// ErrEgressTarget reports a pack that tries to declare its own network targets.
// Egress stays under the core netguard policy; a pack only names a template the
// core renders against an operator-configured endpoint.
var ErrEgressTarget = errors.New("notifier pack must not declare egress targets")

// rejectedPackFields are checked case-insensitively against every JSON object
// key at any depth. The decoder rejects unknown struct fields too, but this
// scan runs first so the error names the security rule instead of a generic
// "unknown field".
var rejectedPackFields = map[string]error{
	"executable":     ErrExecutableContent,
	"executables":    ErrExecutableContent,
	"entrypoint":     ErrExecutableContent,
	"entrypoints":    ErrExecutableContent,
	"artifact":       ErrExecutableContent,
	"artifacts":      ErrExecutableContent,
	"binary":         ErrExecutableContent,
	"binaries":       ErrExecutableContent,
	"script":         ErrExecutableContent,
	"scripts":        ErrExecutableContent,
	"command":        ErrExecutableContent,
	"commands":       ErrExecutableContent,
	"process":        ErrExecutableContent,
	"install":        ErrExecutableContent,
	"installer":      ErrExecutableContent,
	"activation":     ErrExecutableContent,
	"activate":       ErrExecutableContent,
	"payload":        ErrExecutableContent,
	"wasm":           ErrExecutableContent,
	"egress":         ErrEgressTarget,
	"egress_targets": ErrEgressTarget,
	"egress_hosts":   ErrEgressTarget,
	"egress_policy":  ErrEgressTarget,
	"allowed_egress": ErrEgressTarget,
	"allow_egress":   ErrEgressTarget,
	"outbound_hosts": ErrEgressTarget,
}

const maxPackJSONDepth = 16

// scanRejectedFields walks the raw JSON and rejects forbidden keys, duplicate
// keys, and excessive nesting before the typed decoder runs.
func scanRejectedFields(data []byte) error {
	// An empty document has its own contract error from the typed decoder; this
	// scan only classifies forbidden content.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanRejectedValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON after the pack object", ErrInvalidPack)
	}
	return nil
}

func scanRejectedValue(decoder *json.Decoder, depth int) error {
	if depth > maxPackJSONDepth {
		return fmt.Errorf("%w: nesting exceeds %d levels", ErrInvalidPack, maxPackJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidPack, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", ErrInvalidPack)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%w: duplicate field %q", ErrInvalidPack, key)
			}
			seen[key] = struct{}{}
			if rule, rejected := rejectedPackFields[strings.ToLower(key)]; rejected {
				return fmt.Errorf("%w: field %q is not permitted", rule, key)
			}
			if err := scanRejectedValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPack, err)
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanRejectedValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPack, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: unexpected JSON delimiter %q", ErrInvalidPack, delim)
	}
}
