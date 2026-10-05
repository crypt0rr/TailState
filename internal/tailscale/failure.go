package tailscale

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// Collector failure categories. Health notifications report only these
// bounded reasons, never upstream error text.
const (
	FailureAuthRejected    = "auth rejected"
	FailureRateLimited     = "rate limited"
	FailureTimeout         = "timeout"
	FailureUpstream5xx     = "upstream 5xx"
	FailureInvalidResponse = "invalid response"
	FailureUnsupported     = "unsupported"
	FailureNetwork         = "network error"
)

// FailureCategory classifies a collector error into one of the bounded
// failure categories. The classification uses the HTTP status TailState
// observed and Go error types, never provider-controlled text.
func FailureCategory(err error) string {
	if err == nil {
		return ""
	}
	status := 0
	var httpErr *HTTPError
	var oauthErr *oauthStatusError
	switch {
	case errors.As(err, &oauthErr):
		status = oauthErr.Status
		if status == http.StatusBadRequest {
			// OAuth token endpoints answer invalid_client/invalid_grant with 400.
			return FailureAuthRejected
		}
	case errors.As(err, &httpErr):
		status = httpErr.Status
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return FailureAuthRejected
	case status == http.StatusTooManyRequests:
		return FailureRateLimited
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		return FailureUnsupported
	case status == http.StatusGatewayTimeout || status == http.StatusRequestTimeout:
		return FailureTimeout
	case status >= 500 && status <= 599:
		return FailureUpstream5xx
	case status != 0:
		return FailureInvalidResponse
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return FailureTimeout
		}
		return FailureNetwork
	}
	if errors.Is(err, errRetriesExhausted) {
		return FailureNetwork
	}
	return FailureInvalidResponse
}
