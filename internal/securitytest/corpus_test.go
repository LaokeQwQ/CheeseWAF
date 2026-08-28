package securitytest

import (
	"bufio"
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

func TestReadBoundedJSONLLineDiscardsHugeLineAndContinues(t *testing.T) {
	const maxLine = 128
	valid := `{"name":"after-long","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 4<<20)+"\n"+valid+"\n"), 64*1024)

	line, overlong, err := readBoundedJSONLLine(reader, maxLine)
	if err != nil {
		t.Fatalf("read long line: %v", err)
	}
	if !overlong {
		t.Fatal("expected the huge line to be marked overlong")
	}
	if cap(line) > maxLine+2 {
		t.Fatalf("reader retained %d bytes for a %d-byte limit", cap(line), maxLine)
	}

	line, overlong, err = readBoundedJSONLLine(reader, maxLine)
	if err != nil {
		t.Fatalf("read valid line after long line: %v", err)
	}
	if overlong || string(line) != valid {
		t.Fatalf("next line = %q overlong=%v, want valid corpus entry", line, overlong)
	}
}

func TestForEachJSONLStatsDistinguishesCorpusAndSelectedShard(t *testing.T) {
	raw := []byte(`{"name":"only-case","source_family":"unit","label":"benign","method":"GET","target":"/ok"}`)
	shard := 1 - ShardIndexForRaw(raw, 2)

	stats, err := ForEachJSONLWithStats(strings.NewReader(string(raw)+"\n"), 2, shard, func(Case) error {
		t.Fatal("a non-selected case reached the callback")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalCases != 1 || stats.SelectedCases != 0 {
		t.Fatalf("stats = %+v, want one total case and zero selected", stats)
	}
}

func TestForEachJSONLRejectsInvalidShardRange(t *testing.T) {
	for _, tc := range []struct {
		shards int
		shard  int
	}{
		{shards: 0, shard: 0},
		{shards: 1, shard: 1},
		{shards: 2, shard: -1},
		{shards: 2, shard: 2},
	} {
		if _, err := ForEachJSONLWithStats(strings.NewReader(""), tc.shards, tc.shard, func(Case) error { return nil }); err == nil {
			t.Fatalf("invalid shard range shards=%d shard=%d was accepted", tc.shards, tc.shard)
		}
	}
}
