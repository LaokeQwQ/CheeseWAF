package securitytest

import (
	"strings"
	"testing"
)

func TestLoadJSONLValidatesCorpusCases(t *testing.T) {
	raw := strings.Join([]string{
		`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/?q=1%20or%201=1"}`,
		`  `,
		`{"name":"benign","source_family":"unit","label":"benign","method":"POST","target":"/docs","content_type":"application/json","body":"{\"text\":\"select docs\"}"}`,
	}, "\n")

	cases, err := LoadJSONL(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("expected 2 cases, got %d", len(cases))
	}
	if cases[0].Name != "attack" || cases[1].Name != "benign" {
		t.Fatalf("unexpected cases: %+v", cases)
	}
}

func TestLoadJSONLRejectsInvalidCorpusCases(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{name: "bad label", raw: `{"name":"bad","label":"maybe","method":"GET","target":"/"}`},
		{name: "attack missing category", raw: `{"name":"bad","label":"attack","method":"GET","target":"/"}`},
		{name: "blank name", raw: `{"name":" ","label":"benign","method":"GET","target":"/"}`},
		{name: "missing method", raw: `{"name":"bad","label":"benign","target":"/"}`},
		{name: "missing target", raw: `{"name":"bad","label":"benign","method":"GET"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadJSONL(strings.NewReader(tc.raw)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestShardIndexForIsStableAndCoversAllShards(t *testing.T) {
	names := []string{"attack-1", "benign-1", "payload-x", "foo", "bar", "baz"}
	const shards = 4
	seen := make(map[int]bool)
	for _, name := range names {
		idx := ShardIndexFor(name, shards)
		if idx < 0 || idx >= shards {
			t.Fatalf("ShardIndexFor(%q) = %d, want 0..%d", name, idx, shards-1)
		}
		seen[idx] = true
		if ShardIndexFor(name, shards) != idx {
			t.Fatalf("ShardIndexFor(%q) is unstable", name)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no shard was assigned")
	}
}

func TestFilterShardKeepsOnlyMatchingAndPartitions(t *testing.T) {
	cases := []Case{
		{Name: "alpha"}, {Name: "beta"}, {Name: "gamma"}, {Name: "delta"},
	}
	const shards = 2
	total := 0
	for i := 0; i < shards; i++ {
		got := FilterShard(cases, shards, i)
		total += len(got)
		for _, tc := range got {
			if ShardIndexFor(tc.Name, shards) != i {
				t.Fatalf("case %q assigned to shard %d, not %d", tc.Name, ShardIndexFor(tc.Name, shards), i)
			}
		}
	}
	if total != len(cases) {
		t.Fatalf("shards must partition all cases; got total %d, want %d", total, len(cases))
	}
}

func TestForEachJSONLSkipsOverLongLines(t *testing.T) {
	t.Setenv("CHEESEWAF_CORPUS_MAX_LINE_BYTES", "128")
	long := `{"name":"` + strings.Repeat("x", 400) + `","source_family":"unit","label":"benign","method":"GET","target":"/long"}`
	raw := strings.Join([]string{
		`{"name":"ok-one","source_family":"unit","label":"benign","method":"GET","target":"/a"}`,
		long,
		`{"name":"ok-two","source_family":"unit","label":"benign","method":"GET","target":"/b"}`,
	}, "\n")
	var got []Case
	err := ForEachJSONL(strings.NewReader(raw), 1, 0, func(tc Case) error {
		got = append(got, tc)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 readable cases, got %d", len(got))
	}
}
