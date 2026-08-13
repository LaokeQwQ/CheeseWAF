package semantic

import (
	"strings"
	"testing"
)

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		needles []string
		want    bool
	}{
		{"empty text", "", []string{"a"}, false},
		{"empty needles", "test", []string{}, false},
		{"single match", "hello world", []string{"world"}, true},
		{"no match", "hello world", []string{"foo", "bar"}, false},
		{"first needle matches", "hello world", []string{"hello", "foo"}, true},
		{"last needle matches", "hello world", []string{"foo", "world"}, true},
		{"sql injection", "' OR 1=1--", []string{"'", "OR"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.text, tt.needles); got != tt.want {
				t.Errorf("containsAny(%q, %v) = %v, want %v", tt.text, tt.needles, got, tt.want)
			}
		})
	}
}

func TestContainsAll(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		needles []string
		want    bool
	}{
		{"empty needles", "test", []string{}, true},
		{"single match", "hello world", []string{"world"}, true},
		{"all match", "hello world test", []string{"hello", "world"}, true},
		{"partial match", "hello world", []string{"hello", "foo"}, false},
		{"no match", "hello world", []string{"foo", "bar"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAll(tt.text, tt.needles); got != tt.want {
				t.Errorf("containsAll(%q, %v) = %v, want %v", tt.text, tt.needles, got, tt.want)
			}
		})
	}
}

func TestHasPrefix(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		prefixes []string
		want     bool
	}{
		{"empty prefixes", "test", []string{}, false},
		{"single match", "hello world", []string{"hello"}, true},
		{"no match", "hello world", []string{"foo", "bar"}, false},
		{"first matches", "hello world", []string{"hello", "foo"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasPrefix(tt.text, tt.prefixes); got != tt.want {
				t.Errorf("hasPrefix(%q, %v) = %v, want %v", tt.text, tt.prefixes, got, tt.want)
			}
		})
	}
}

func BenchmarkContainsAny(b *testing.B) {
	text := "SELECT * FROM users WHERE id = '1' OR 1=1--"
	needles := []string{"SELECT", "UNION", "OR", "AND", "--"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = containsAny(text, needles)
	}
}

func BenchmarkContainsAnyMiss(b *testing.B) {
	text := "normal benign user input without any suspicious patterns"
	needles := []string{"SELECT", "UNION", "OR", "AND", "--"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = containsAny(text, needles)
	}
}

func BenchmarkManualContainsVsFastpath(b *testing.B) {
	text := "SELECT * FROM users WHERE id = '1' OR 1=1--"
	needles := []string{"SELECT", "UNION", "OR", "AND", "--"}

	b.Run("manual", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			found := false
			for _, needle := range needles {
				if strings.Contains(text, needle) {
					found = true
					break
				}
			}
			_ = found
		}
	})

	b.Run("fastpath", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = containsAny(text, needles)
		}
	})
}
