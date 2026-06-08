package response

import "bytes"

func newReplayReader(body []byte) *bytes.Reader {
	return bytes.NewReader(body)
}
