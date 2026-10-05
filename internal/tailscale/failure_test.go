package tailscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

type timeoutError struct{ timeout bool }

func (e timeoutError) Error() string   { return "network" }
func (e timeoutError) Timeout() bool   { return e.timeout }
func (e timeoutError) Temporary() bool { return false }

// TestFailureCategoryIsBounded keeps collector health reasons to a fixed,
// provider-independent vocabulary derived from statuses and error types.
func TestFailureCategoryIsBounded(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{&oauthStatusError{Status: 401}, FailureAuthRejected},
		{&oauthStatusError{Status: 400}, FailureAuthRejected},
		{fmt.Errorf("wrapped: %w", &HTTPError{Status: 403, Body: "SECRET"}), FailureAuthRejected},
		{&HTTPError{Status: 429}, FailureRateLimited},
		{&oauthStatusError{Status: 429}, FailureRateLimited},
		{&HTTPError{Status: 404}, FailureUnsupported},
		{&HTTPError{Status: 504}, FailureTimeout},
		{&HTTPError{Status: 500}, FailureUpstream5xx},
		{&oauthStatusError{Status: 503}, FailureUpstream5xx},
		{&HTTPError{Status: 418}, FailureInvalidResponse},
		{&PartialError{Err: &HTTPError{Status: 502}}, FailureUpstream5xx},
		{context.DeadlineExceeded, FailureTimeout},
		{timeoutError{timeout: true}, FailureTimeout},
		{&net.OpError{Op: "dial", Err: timeoutError{}}, FailureNetwork},
		{errRetriesExhausted, FailureNetwork},
		{errors.New("tailscale response was not valid JSON: SECRET"), FailureInvalidResponse},
	}
	for _, test := range cases {
		if got := FailureCategory(test.err); got != test.want {
			t.Fatalf("FailureCategory(%v)=%q, want %q", test.err, got, test.want)
		}
	}
}
