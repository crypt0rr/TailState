package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncatePreservesUTF8(t *testing.T) {
	value := strings.Repeat("界", 20)
	got := Truncate(value, 10)
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") || len(got) > 10 {
		t.Fatalf("invalid bounded text %q (%d bytes)", got, len(got))
	}
	if Truncate("short", 10) != "short" || Truncate("value", 0) != "" {
		t.Fatal("unexpected short or zero-length truncation")
	}
	for _, limit := range []int{1, 2} {
		got := Truncate("界", limit)
		if !utf8.ValidString(got) || len(got) > limit {
			t.Fatalf("small truncation exceeded UTF-8 bound: limit=%d value=%q", limit, got)
		}
	}
}
