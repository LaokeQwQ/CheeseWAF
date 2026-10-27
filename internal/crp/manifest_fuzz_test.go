package crp

import (
	"encoding/json"
	"testing"
)

func fuzzValidManifest() []byte {
	artifact := []byte("payload")
	manifest := Manifest{
		APIVersion:      APIVersion,
		Kind:            Kind,
		Name:            "fuzz-demo",
		PluginID:        "fuzz-demo",
		Version:         "1.0.0",
		Namespace:       "official/fuzz-demo",
		SourceRoot:      "root",
		Source:          "offline",
		ReleaseSequence: 1,
		Artifact:        Artifact{Size: int64(len(artifact)), Digests: digestsForTest(artifact)},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return raw
}

// FuzzParseManifest checks strict JSON decoding and intrinsic validation for
// arbitrary manifest bytes.
func FuzzParseManifest(f *testing.F) {
	for _, seed := range [][]byte{
		fuzzValidManifest(),
		[]byte(`{}`),
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`{"version":"1.0.0","version":"2.0.0"}`),
		[]byte(`{"name":"x","version":"1.0.0","namespace":"official/x","source_root":"root","artifact":{"size":0}}`),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		manifest, err := ParseManifest(data)
		if err != nil {
			return
		}
		if err := manifest.Validate(); err != nil {
			t.Fatalf("accepted manifest does not validate: %v", err)
		}
	})
}
