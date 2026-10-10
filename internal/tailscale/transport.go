package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

func (c *Client) allPages(ctx context.Context, endpoint, arrayKey string) ([]map[string]any, error) {
	return c.allPagesWithOptions(ctx, endpoint, arrayKey)
}

func (c *Client) collectionLimitsOrDefault() CollectionLimits {
	limits := c.collectionLimits
	defaults := DefaultCollectionLimits()
	if limits.MaxItems <= 0 {
		limits.MaxItems = defaults.MaxItems
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = defaults.MaxBytes
	}
	return limits
}

func (c *Client) allPagesWithOptions(ctx context.Context, endpoint, arrayKey string) ([]map[string]any, error) {
	next := endpoint
	var out []map[string]any
	seen := make(map[string]struct{})
	limits := c.collectionLimitsOrDefault()
	var aggregateBytes int64
	for page := 0; page < 100; page++ {
		if _, repeated := seen[next]; repeated {
			return nil, errors.New("tailscale pagination repeated the same page URL")
		}
		seen[next] = struct{}{}
		value, responseBytes, err := c.getWithBytes(ctx, next)
		if err != nil {
			return nil, err
		}
		if responseBytes > limits.MaxBytes-aggregateBytes {
			return nil, fmt.Errorf("%s collection exceeds aggregate response limit of %d bytes", arrayKey, limits.MaxBytes)
		}
		aggregateBytes += responseBytes
		object, objectOK := value.(map[string]any)
		var items []any
		if objectOK {
			raw, present := object[arrayKey]
			if !present || raw == nil {
				return nil, fmt.Errorf("%s response has no %s array (an empty collection must be returned as [])", arrayKey, arrayKey)
			}
			var ok bool
			items, ok = raw.([]any)
			if !ok {
				return nil, fmt.Errorf("%s response %s is not an array (an empty collection must be returned as [])", arrayKey, arrayKey)
			}
		} else {
			var ok bool
			items, ok = value.([]any)
			if !ok {
				return nil, fmt.Errorf("%s response has no %s array (an empty collection must be returned as [])", arrayKey, arrayKey)
			}
		}
		if items == nil {
			return nil, fmt.Errorf("%s response has no %s array (an empty collection must be returned as [])", arrayKey, arrayKey)
		}
		if len(items) > limits.MaxItems-len(out) {
			return nil, fmt.Errorf("%s collection exceeds aggregate item limit of %d", arrayKey, limits.MaxItems)
		}
		for _, item := range items {
			obj, ok := item.(map[string]any)
			if !ok {
				// A collection containing primitives or nulls is not a safe
				// inventory result. Silently dropping those entries could look
				// like mass removal and mutate snapshots on the next poll.
				return nil, fmt.Errorf("%s response %s contains a non-object item", arrayKey, arrayKey)
			}
			out = append(out, obj)
		}
		candidate, cursor := "", ""
		if objectOK {
			candidate, cursor = nextPage(object)
		}
		if cursor != "" {
			// A bare cursor continues the current request: keep its existing
			// query parameters (fields=all, all=true, type=...) and only
			// replace the cursor.
			candidate, err = withCursor(next, cursor)
			if err != nil {
				return nil, err
			}
		}
		if candidate == "" {
			return out, nil
		}
		resolved, err := c.resolvePaginationURL(next, candidate)
		if err != nil {
			return nil, err
		}
		next = resolved
	}
	return nil, errors.New("tailscale pagination exceeded 100 pages")
}

func (c *Client) resolvePaginationURL(current, candidate string) (string, error) {
	currentURL, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("invalid current pagination URL: %w", err)
	}
	pageURL, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid pagination URL: %w", err)
	}
	if !pageURL.IsAbs() {
		pageURL = currentURL.ResolveReference(pageURL)
	}
	apiURL, err := url.Parse(c.base)
	if err != nil {
		return "", fmt.Errorf("invalid Tailscale API URL: %w", err)
	}
	if pageURL.User != nil || !strings.EqualFold(pageURL.Scheme, apiURL.Scheme) || !strings.EqualFold(pageURL.Host, apiURL.Host) {
		return "", errors.New("pagination URL points outside the configured Tailscale API")
	}
	apiPath := strings.TrimSuffix(apiURL.Path, "/")
	if apiPath != "" && pageURL.Path != apiPath && !strings.HasPrefix(pageURL.Path, apiPath+"/") {
		return "", errors.New("pagination URL points outside the configured Tailscale API path")
	}
	return pageURL.String(), nil
}

// nextPage returns either an explicit next-page link or a bare pagination
// cursor from a collection response.
func nextPage(object map[string]any) (link, cursor string) {
	if value, ok := object["next"].(string); ok {
		return value, ""
	}
	if p, ok := object["pagination"].(map[string]any); ok {
		if value, ok := p["next"].(string); ok {
			return value, ""
		}
		if cursor, ok := p["nextCursor"].(string); ok && cursor != "" {
			return "", cursor
		}
	}
	return "", ""
}

// withCursor merges a pagination cursor into the current page URL without
// dropping its other query parameters.
func withCursor(current, cursor string) (string, error) {
	currentURL, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("invalid current pagination URL: %w", err)
	}
	query := currentURL.Query()
	query.Set("cursor", cursor)
	currentURL.RawQuery = query.Encode()
	return currentURL.String(), nil
}

func (c *Client) get(ctx context.Context, endpoint string) (any, error) {
	value, _, err := c.getWithBytes(ctx, endpoint)
	return value, err
}

func (c *Client) getWithBytes(ctx context.Context, endpoint string) (any, int64, error) {
	body, err := c.getBody(ctx, endpoint)
	if err != nil {
		return nil, int64(len(body)), err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, int64(len(body)), nil
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, int64(len(body)), fmt.Errorf("tailscale response was not valid JSON: %w", err)
	}
	return value, int64(len(body)), nil
}

// getBody performs one bounded GET with token refresh and retries and
// returns the successful response body. On an error the body read so far (if
// any) is returned for byte accounting.
func (c *Client) getBody(ctx context.Context, endpoint string) ([]byte, error) {
	// Bound the complete request, including token refreshes and all backoff
	// sleeps. If the caller already supplied an earlier deadline,
	// context.WithTimeout preserves that stricter limit.
	retryCtx, cancel := context.WithTimeout(ctx, maxRequestRetryDuration)
	defer cancel()
	for attempt := 0; attempt < 4; attempt++ {
		token, err := c.accessToken(retryCtx)
		if err != nil {
			// A token-endpoint blip (network error, 429 or 5xx) must not fail
			// every request that happens to need a fresh token. Retry it within
			// the same per-request budget.
			if delay, transient := transientTokenDelay(err, attempt); transient && attempt < 3 && waitWithinBudget(retryCtx, delay) {
				continue
			}
			return nil, err
		}
		req, err := http.NewRequestWithContext(retryCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "tailstate/"+c.version)
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < 3 {
				if !waitForRetry(retryCtx, time.Duration(1<<attempt)*time.Second) {
					return nil, retryCtx.Err()
				}
				continue
			}
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes+1))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(body) > maxAPIResponseBytes {
			return body, fmt.Errorf("tailscale response exceeds %d bytes", maxAPIResponseBytes)
		}
		if resp.StatusCode == 401 && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		}
		if (resp.StatusCode == http.StatusTooManyRequests || transientGatewayStatus(resp.StatusCode)) && attempt < 3 {
			// A 429 and Tailscale's documented "try again later" statuses
			// (502/503/504) are retried with backoff (or the provider's
			// Retry-After) while the request budget allows; otherwise the
			// upstream status is reported unchanged, so a long Retry-After
			// is "rate limited" rather than a timeout after a futile wait.
			delay := retryAfter(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*time.Second)
			if waitWithinBudget(retryCtx, delay) {
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return body, &HTTPError{Status: resp.StatusCode, URL: endpoint, Body: safeBody(body)}
		}
		return body, nil
	}
	return nil, errRetriesExhausted
}

var errRetriesExhausted = errors.New("tailscale request retries exhausted")

// oauthStatusError reports a non-2xx token endpoint response.
type oauthStatusError struct {
	Status     int
	RetryAfter string
}

func (e *oauthStatusError) Error() string {
	return fmt.Sprintf("OAuth token request returned %d", e.Status)
}

// oauthTransportError reports a token request that failed before a response
// was received.
type oauthTransportError struct{ Err error }

func (e *oauthTransportError) Error() string { return e.Err.Error() }

func (e *oauthTransportError) Unwrap() error { return e.Err }

func transientGatewayStatus(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// transientTokenDelay classifies token endpoint failures that are worth
// retrying and returns the delay before the next attempt.
func transientTokenDelay(err error, attempt int) (time.Duration, bool) {
	fallback := time.Duration(1<<attempt) * time.Second
	var statusErr *oauthStatusError
	if errors.As(err, &statusErr) {
		if statusErr.Status == http.StatusTooManyRequests || statusErr.Status >= 500 {
			return retryAfter(statusErr.RetryAfter, fallback), true
		}
		return 0, false
	}
	var transportErr *oauthTransportError
	if errors.As(err, &transportErr) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return fallback, true
	}
	return 0, false
}

// waitWithinBudget sleeps before a retry only when the retry can still start
// inside the request's deadline. It reports false without sleeping when the
// delay would exhaust the budget, so the caller returns the upstream error
// instead of a less useful context deadline error.
func waitWithinBudget(ctx context.Context, delay time.Duration) bool {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
		return false
	}
	return waitForRetry(ctx, delay)
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > 5*time.Minute {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {c.scope()}, "client_id": {c.credentials.ClientID}, "client_secret": {c.credentials.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.credentials.ClientID, c.credentials.ClientSecret)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", &oauthTransportError{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthResponseBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxOAuthResponseBytes {
		return "", fmt.Errorf("OAuth response exceeds %d bytes", maxOAuthResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &oauthStatusError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("OAuth response did not include access_token")
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	c.token = payload.AccessToken
	c.expires = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return c.token, nil
}

// scope returns the space-separated OAuth scope parameter.
func (c *Client) scope() string {
	scopes := make([]string, 0, len(c.credentials.Scopes))
	for _, scope := range c.credentials.Scopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		return DefaultOAuthScope
	}
	return strings.Join(scopes, " ")
}

func retryAfter(value string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 {
		maxSeconds := int64(maxRetryAfterDelay / time.Second)
		if seconds >= maxSeconds {
			return maxRetryAfterDelay
		}
		return time.Duration(seconds) * time.Second
	}
	// Treat an otherwise-valid non-negative integer that exceeds int64 as an
	// already-capped delay instead of allowing it to fall through to fallback.
	numeric := strings.TrimPrefix(raw, "+")
	if numeric != "" && strings.Trim(numeric, "0123456789") == "" {
		return maxRetryAfterDelay
	}
	if when, err := http.ParseTime(value); err == nil {
		return min(max(time.Until(when), 0), maxRetryAfterDelay)
	}
	return fallback
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

var waitForRetry = sleep

func safeBody(body []byte) string {
	value := strings.TrimSpace(string(body))
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		default:
			if r < 0x20 {
				return -1
			}
			return r
		}
	}, value)
	return textutil.Truncate(value, 200)
}
