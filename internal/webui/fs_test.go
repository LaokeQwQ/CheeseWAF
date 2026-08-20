package webui

import "testing"

func TestFSRequiresIndexHTML(t *testing.T) {
	_, ok := FS()
	if ok {
		if _, still := FS(); !still {
			t.Fatal("embedded UI disappeared between calls")
		}
		return
	}
	// Checkout without a built UI only ships dist/.keep.
}
