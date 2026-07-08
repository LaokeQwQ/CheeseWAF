package object

import "testing"

func TestResourceVersionChangesWhenSpecChanges(t *testing.T) {
	a := Resource[NodeSpec, NodeStatus]{
		APIVersion: APIVersionV1,
		Kind:       KindNode,
		Metadata:   Metadata{ID: "node-a", Generation: 1},
		Spec:       NodeSpec{Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
	}
	b := a
	b.Spec.AdvertiseAddr = "10.0.0.2:9444"
	ha, err := HashSpec(a.Spec)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := HashSpec(b.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("spec hash must change when spec changes")
	}
}

func TestNodeModeLabels(t *testing.T) {
	status := NodeStatus{Mode: "protection", CanReceiveTraffic: true, CanWriteConfig: false}
	if status.ProductModeLabel("zh-CN") != "保护模式" {
		t.Fatalf("unexpected zh label: %q", status.ProductModeLabel("zh-CN"))
	}
	if status.ProductModeLabel("en-US") != "Protection mode" {
		t.Fatalf("unexpected en label: %q", status.ProductModeLabel("en-US"))
	}
}

func TestNormalizeResourceAppliesHashAndVersion(t *testing.T) {
	res := Resource[NodeSpec, NodeStatus]{
		APIVersion: APIVersionV1,
		Kind:       KindNode,
		Metadata:   Metadata{ID: "node-a"},
		Spec:       NodeSpec{Role: "waf", AdvertiseAddr: "10.0.0.1:9444"},
	}
	normalized, err := Normalize(res)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Metadata.Generation != 1 {
		t.Fatalf("generation=%d, want 1", normalized.Metadata.Generation)
	}
	if normalized.Metadata.ResourceVersion == "" || normalized.Metadata.LastAppliedHash == "" {
		t.Fatalf("resource version and hash must be set: %+v", normalized.Metadata)
	}
}
