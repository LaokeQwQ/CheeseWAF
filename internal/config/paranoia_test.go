package config

import "testing"

func TestEffectiveParanoiaLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{0, 0},
		{-1, DefaultParanoiaLevel},
		{5, 5},
		{6, DefaultParanoiaLevel},
		{1, 1},
		{2, 2},
		{3, 3},
		{4, 4},
	}
	for _, tc := range cases {
		if got := EffectiveParanoiaLevel(tc.in); got != tc.want {
			t.Fatalf("EffectiveParanoiaLevel(%d)=%d, want %d", tc.in, got, tc.want)
		}
	}
}
