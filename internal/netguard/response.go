package netguard

import (
	"errors"
	"io"
)

const maxResponseDrainBytes = 64 << 10

// DrainAndClose consumes a small response body before closing it so persistent
// HTTP/1.1 connections can be reused. The bounded read prevents a hostile or
// broken upstream from turning cleanup into an unbounded download.
func DrainAndClose(body io.ReadCloser) error {
	if body == nil {
		return nil
	}
	_, drainErr := io.Copy(io.Discard, io.LimitReader(body, maxResponseDrainBytes+1))
	return errors.Join(drainErr, body.Close())
}
