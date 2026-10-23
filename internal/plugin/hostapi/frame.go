package hostapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	ErrInvalidFrame   = errors.New("invalid plugin host frame")
	ErrFrameTooLarge  = errors.New("plugin host frame too large")
	ErrDuplicateField = errors.New("plugin host frame contains duplicate field")
	ErrUnknownType    = errors.New("unknown plugin host frame type")
	ErrSequence       = errors.New("plugin host frame sequence is invalid")
)

// DecodeFrame parses one newline-delimited JSON frame. It rejects invalid
// UTF-8, duplicate object keys, unknown fields, trailing data, unknown frame
// types, and frames above max bytes.
func DecodeFrame(data []byte, max int) (Frame, error) {
	if max <= 0 {
		max = MaxFrameBytes
	}
	if len(data) > max {
		return Frame{}, ErrFrameTooLarge
	}
	if !utf8.Valid(data) {
		return Frame{}, ErrInvalidFrame
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Frame{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var frame Frame
	if err := dec.Decode(&frame); err != nil {
		return Frame{}, fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	if err := ensureEOF(dec); err != nil {
		return Frame{}, err
	}
	if frame.SchemaVersion != ProtocolVersion {
		return Frame{}, fmt.Errorf("%w: schema_version %q", ErrInvalidFrame, frame.SchemaVersion)
	}
	if !frame.Type.Valid() {
		return Frame{}, fmt.Errorf("%w: %q", ErrUnknownType, frame.Type)
	}
	if frame.Type.NeedsSequence() && frame.Sequence == 0 {
		return Frame{}, ErrSequence
	}
	if len(frame.Payload) > max {
		return Frame{}, ErrFrameTooLarge
	}
	return frame, nil
}

// EncodeFrame validates and marshals one frame, enforcing the size bound.
func EncodeFrame(frame Frame, max int) ([]byte, error) {
	if max <= 0 {
		max = MaxFrameBytes
	}
	if frame.SchemaVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: schema_version %q", ErrInvalidFrame, frame.SchemaVersion)
	}
	if !frame.Type.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, frame.Type)
	}
	if frame.Type.NeedsSequence() && frame.Sequence == 0 {
		return nil, ErrSequence
	}
	raw, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}
	if len(raw) > max {
		return nil, ErrFrameTooLarge
	}
	return raw, nil
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidFrame)
		}
		return fmt.Errorf("%w: trailing data: %v", ErrInvalidFrame, err)
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanValue(dec, 0); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidFrame)
		}
		return fmt.Errorf("%w: trailing data: %v", ErrInvalidFrame, err)
	}
	return nil
}

func scanValue(dec *json.Decoder, depth int) error {
	if depth > MaxFrameDepth {
		return fmt.Errorf("%w: nesting exceeds %d", ErrInvalidFrame, MaxFrameDepth)
	}
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFrame, err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{}, 8)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidFrame, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%w: object key is not a string", ErrInvalidFrame)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %q", ErrDuplicateField, key)
			}
			seen[key] = struct{}{}
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidFrame, err)
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%w: object not closed", ErrInvalidFrame)
		}
		return nil
	case '[':
		for dec.More() {
			if err := scanValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidFrame, err)
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%w: array not closed", ErrInvalidFrame)
		}
		return nil
	default:
		return fmt.Errorf("%w: unexpected delimiter %q", ErrInvalidFrame, delim)
	}
}
