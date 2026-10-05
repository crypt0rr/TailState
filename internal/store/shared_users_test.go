package store

import (
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

func TestIsSharedUserRequiresSharedType(t *testing.T) {
	for _, tc := range []struct {
		data any
		want bool
	}{
		{map[string]any{"type": "shared"}, true},
		{map[string]any{"type": "Shared"}, true},
		{map[string]any{"type": "member"}, false},
		{map[string]any{}, false},
		{"shared", false},
		{nil, false},
	} {
		if got := isSharedUser(model.Resource{Data: tc.data}); got != tc.want {
			t.Fatalf("isSharedUser(%#v)=%v, want %v", tc.data, got, tc.want)
		}
	}
}
