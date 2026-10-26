package crp

import "testing"

// FuzzRuntimeStateJSON covers the durable runtime state decoder. Accepted
// states must have schema 1 and a non-nil plugin map; no input may panic.
func FuzzRuntimeStateJSON(f *testing.F) {
	for _, seed := range []string{
		`{"Schema":1,"Plugins":{}}`,
		`{"Schema":2,"Plugins":{}}`,
		`{"Schema":1,"Plugins":null}`,
		`{"Schema":1,"Plugins":{"demo":{"Revision":1}}}`,
		`{"Schema":1,"Plugins":{"../escape":{}}}`,
		`{"Schema":1,"Plugins":{}} trailing`,
		`{}`,
		`null`,
		`[]`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		state, err := decodeDiskState(data)
		if err != nil {
			return
		}
		if state.Schema != 1 || state.Plugins == nil {
			t.Fatal("accepted invalid runtime state")
		}
	})
}
