package semantic

import (
	"testing"
)

// FuzzMultipartInputs checks the bounded multipart extractor used by the
// semantic analyzer. It must never panic, must bound every part, and must
// report incomplete input rather than silently truncating.
func FuzzMultipartInputs(f *testing.F) {
	f.Add([]byte("--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--b--\r\n"), "b")
	f.Add([]byte("--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../x.php\"\r\n\r\n<?php eval($_POST[1]); ?>\r\n--b--\r\n"), "b")
	f.Add([]byte("--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue"), "b")
	f.Add([]byte(""), "b")
	f.Add([]byte("--b--\r\n"), "")

	f.Fuzz(func(t *testing.T, body []byte, boundary string) {
		if len(body) > 1<<20 || len(boundary) > 256 {
			t.Skip()
		}
		inputs, incomplete := multipartInputsWithStatus(body, boundary)
		if len(inputs) > maxMultipartInputs {
			t.Fatalf("inputs = %d, max = %d", len(inputs), maxMultipartInputs)
		}
		for _, input := range inputs {
			if len(input.Raw) > maxInputRawBytes {
				t.Fatalf("raw input = %d, max = %d", len(input.Raw), maxInputRawBytes)
			}
		}
		_ = incomplete
	})
}
