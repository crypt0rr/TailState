package tailscale

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
	"github.com/crypt0rr/tailstate/internal/textutil"
)

var CoreCollectors = []string{"devices"}
var InventoryCollectors = []string{"device_details", "users", "user_invites", "dns", "policy", "keys", "webhooks", "log_streaming", "contacts", "posture", "settings"}

type Credentials struct{ Tailnet, ClientID, ClientSecret string }

type Client struct {
	base, tokenURL, version string
	credentials             Credentials
	http                    *http.Client
	mu                      sync.Mutex
	deviceCacheMu           sync.RWMutex
	deviceCache             []map[string]any
	token                   string
	expires                 time.Time
}

type HTTPError struct {
	Status int
	URL    string
	Body   string
}

// PartialError reports a collector response that contained usable resources
// but could not complete every related request. Count is the number of failed
// related requests. Callers may apply the returned resources while preserving
// existing snapshots for missing items.
type PartialError struct {
	Err   error
	Count int
}

func (e *PartialError) Error() string {
	if e == nil || e.Err == nil {
		return "partial collector response"
	}
	return "partial collector response: " + e.Err.Error()
}

func (e *PartialError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

const (
	maxAPIResponseBytes   = 16 << 20
	maxOAuthResponseBytes = 1 << 20
	maxRetryAfterDelay    = 5 * time.Minute
	// A provider-controlled Retry-After value must not be able to keep one
	// request occupied indefinitely when the caller uses a context without a
	// deadline. Collectors add their own shorter poll deadline, but direct
	// client users (including the setup test) still need a hard upper bound.
	maxRequestRetryDuration = 30 * time.Second
)

var deviceDetailsPollTimeout = 2 * time.Minute

func (e *HTTPError) Error() string {
	endpoint := e.endpoint()
	message := fmt.Sprintf("Tailscale GET %s returned %d", endpoint, e.Status)
	if body := safeBody([]byte(e.Body)); body != "" {
		message += ": " + body
	}
	return message
}

// SafeMessage returns the operator-facing portion of an upstream error. The
// response body is intentionally omitted because it is untrusted provider
// text and may contain credentials or other sensitive details. Use this at
// HTML, logging, and persistence boundaries; Error remains useful for local
// diagnostics and tests.
func (e *HTTPError) SafeMessage() string {
	if e == nil {
		return "Tailscale request failed"
	}
	return fmt.Sprintf("Tailscale request to %s returned HTTP %d", e.endpoint(), e.Status)
}

// SafeError removes response bodies from Tailscale HTTP errors while
// preserving the endpoint and status needed for operational diagnosis. It
// unwraps PartialError values through errors.As as well.
func SafeError(err error) string {
	if err == nil {
		return ""
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.SafeMessage()
	}
	return err.Error()
}

func (e *HTTPError) endpoint() string {
	endpoint := strings.TrimSpace(e.URL)
	if parsed, err := url.Parse(endpoint); err == nil {
		endpoint = parsed.Path
		if endpoint == "" {
			endpoint = parsed.Host
		}
	} else {
		endpoint = ""
	}
	if endpoint == "" {
		endpoint = "endpoint"
	}
	return endpoint
}

func IsUnsupported(err error) bool {
	var e *HTTPError
	return errors.As(err, &e) && (e.Status == http.StatusForbidden || e.Status == http.StatusNotFound)
}

// IsUnsupportedCollector applies plan-capability semantics only to optional
// collectors. Core device inventory and its dependent details must surface a
// 404 as an upstream failure; otherwise a transient endpoint disappearance
// could be mistaken for an unsupported plan capability. The store still
// requires confirmation before demoting an established optional baseline.
func IsUnsupportedCollector(collector string, err error) bool {
	if collector == "devices" || collector == "device_details" {
		return false
	}
	return IsUnsupported(err)
}

func New(base, tokenURL, version string, credentials Credentials) *Client {
	return &Client{base: strings.TrimRight(base, "/"), tokenURL: tokenURL, version: version, credentials: credentials, http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: noRedirect}}
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// BeginPoll invalidates the per-poll device-list cache. The monitor calls it
// once before collecting a group so devices and device_details share one fresh
// list within that poll without allowing a targeted reconciliation to reuse a
// device identity from an earlier poll.
func (c *Client) BeginPoll() { c.clearDeviceCache() }

func (c *Client) Test(ctx context.Context) error { _, err := c.Collect(ctx, "devices"); return err }

func (c *Client) Collect(ctx context.Context, collector string) ([]model.Resource, error) {
	switch collector {
	case "devices":
		resources, err := c.collection(ctx, c.tailnet("devices?fields=all"), "devices", collector, "device", []string{"id", "nodeId", "nodeID"})
		if err != nil {
			c.clearDeviceCache()
			return nil, err
		}
		c.cacheDeviceResources(resources)
		return resources, nil
	case "device_details":
		return c.deviceDetails(ctx)
	case "users":
		return c.collection(ctx, c.tailnet("users"), "users", collector, "user", []string{"id", "userId", "userID", "loginName"})
	case "user_invites":
		return c.collection(ctx, c.tailnet("user-invites"), "userInvites", collector, "user_invite", []string{"id", "inviteId", "inviteID"})
	case "keys":
		return c.collection(ctx, c.tailnet("keys?all=true"), "keys", collector, "credential", []string{"id", "keyId", "keyID"})
	case "webhooks":
		return c.collection(ctx, c.tailnet("webhooks"), "webhooks", collector, "webhook_configuration", []string{"id", "endpointId", "endpointID"})
	case "dns":
		return c.dns(ctx)
	case "policy":
		return c.policy(ctx)
	case "log_streaming":
		return c.logStreaming(ctx)
	case "contacts":
		return c.single(ctx, c.tailnet("contacts"), collector, "contacts", "Tailnet contacts")
	case "posture":
		return c.collection(ctx, c.tailnet("posture/integrations"), "integrations", collector, "posture_integration", []string{"id", "integrationId", "integrationID"})
	case "settings":
		return c.single(ctx, c.tailnet("settings"), collector, "settings", "Tailnet settings")
	default:
		return nil, fmt.Errorf("unknown collector %q", collector)
	}
}

func (c *Client) deviceDetails(ctx context.Context) ([]model.Resource, error) {
	detailCtx, cancel := context.WithTimeout(ctx, deviceDetailsPollTimeout)
	defer cancel()
	devices, ok := c.cachedDevices()
	if !ok {
		var err error
		devices, err = c.allPages(detailCtx, c.tailnet("devices?fields=all"), "devices")
		if err != nil {
			return nil, err
		}
		c.cacheDeviceMaps(devices)
	}
	return c.deviceDetailsFromDevices(detailCtx, devices)
}

func (c *Client) deviceDetailsFromDevices(ctx context.Context, devices []map[string]any) ([]model.Resource, error) {
	type detailJob struct {
		index  int
		device map[string]any
	}
	type detailResult struct {
		index    int
		resource model.Resource
		err      error
		hasValue bool
	}
	jobs := make(chan detailJob, len(devices))
	results := make(chan detailResult, len(devices))
	workers := min(8, len(devices))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				id := idFor(job.device, []string{"id", "nodeId", "nodeID"})
				if id == "" {
					results <- detailResult{index: job.index, err: errors.New("device detail response omitted device id")}
					continue
				}
				combined := map[string]any{}
				var detailErr error
				for _, detail := range []struct {
					key  string
					path string
				}{
					{key: "routes", path: "routes"},
					{key: "postureAttributes", path: "attributes"},
					{key: "deviceInvites", path: "device-invites"},
				} {
					key, path := detail.key, detail.path
					value, err := c.get(ctx, c.global("device/"+url.PathEscape(id)+"/"+path))
					if err != nil {
						// A missing per-device detail endpoint is an incomplete
						// response, not proof that the whole subresource is
						// unsupported. Preserve that distinction so the monitor does
						// not persist a synthetic "unsupported" value or clear a
						// previously known detail snapshot.
						var httpErr *HTTPError
						if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
							detailErr = err
							break
						}
						if IsUnsupported(err) {
							combined[key] = map[string]any{"unsupported": true}
							continue
						}
						detailErr = err
						break
					}
					combined[key] = value
				}
				if detailErr != nil {
					results <- detailResult{index: job.index, err: detailErr}
					continue
				}
				results <- detailResult{index: job.index, hasValue: true, resource: model.Resource{ID: id, Type: "device_details", Name: nameFor(job.device, id), Collector: "device_details", Data: combined}}
			}
		}()
	}
	for index, device := range devices {
		jobs <- detailJob{index: index, device: device}
	}
	close(jobs)
	wg.Wait()
	close(results)
	ordered := make([]detailResult, 0, len(devices))
	var partialErr error
	partialCount := 0
	for result := range results {
		if result.err != nil {
			partialCount++
			if partialErr == nil {
				partialErr = result.err
			}
			continue
		}
		if result.hasValue {
			ordered = append(ordered, result)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].index < ordered[j].index })
	out := make([]model.Resource, 0, len(ordered))
	for _, result := range ordered {
		out = append(out, result.resource)
	}
	if partialErr != nil {
		return out, &PartialError{Err: partialErr, Count: partialCount}
	}
	return out, nil
}

func (c *Client) cacheDeviceResources(resources []model.Resource) {
	devices := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		if data, ok := resource.Data.(map[string]any); ok {
			devices = append(devices, data)
		}
	}
	c.cacheDeviceMaps(devices)
}

func (c *Client) cacheDeviceMaps(devices []map[string]any) {
	copyOf := append([]map[string]any(nil), devices...)
	c.deviceCacheMu.Lock()
	c.deviceCache = copyOf
	c.deviceCacheMu.Unlock()
}

func (c *Client) cachedDevices() ([]map[string]any, bool) {
	c.deviceCacheMu.RLock()
	defer c.deviceCacheMu.RUnlock()
	if c.deviceCache == nil {
		return nil, false
	}
	return append([]map[string]any(nil), c.deviceCache...), true
}

func (c *Client) clearDeviceCache() {
	c.deviceCacheMu.Lock()
	c.deviceCache = nil
	c.deviceCacheMu.Unlock()
}

func (c *Client) dns(ctx context.Context) ([]model.Resource, error) {
	data := map[string]any{}
	supported := 0
	for _, endpoint := range []string{"nameservers", "preferences", "searchpaths", "split-dns"} {
		value, err := c.get(ctx, c.tailnet("dns/"+endpoint))
		if err != nil {
			if IsUnsupported(err) {
				data[endpoint] = map[string]any{"unsupported": true}
				continue
			}
			return nil, err
		}
		supported++
		data[endpoint] = value
	}
	if supported == 0 {
		return nil, &HTTPError{Status: http.StatusNotFound, URL: "dns", Body: "all DNS endpoints unsupported"}
	}
	return []model.Resource{{ID: "dns", Type: "dns", Name: "DNS configuration", Collector: "dns", Data: data}}, nil
}

func (c *Client) policy(ctx context.Context) ([]model.Resource, error) {
	value, err := c.get(ctx, c.tailnet("acl"))
	if err != nil {
		return nil, err
	}
	sections := map[string]any{}
	if object, ok := value.(map[string]any); ok {
		for key, section := range object {
			raw, _, _ := model.CanonicalForSection("policy", key, section)
			sum := sha256.Sum256(raw)
			sections[key] = hex.EncodeToString(sum[:])
		}
	} else {
		raw, _, _ := model.Canonical(value)
		sum := sha256.Sum256(raw)
		sections["policy"] = hex.EncodeToString(sum[:])
	}
	return []model.Resource{{ID: "policy", Type: "policy", Name: "Tailnet policy", Collector: "policy", Data: sections}}, nil
}

func (c *Client) logStreaming(ctx context.Context) ([]model.Resource, error) {
	data := map[string]any{}
	supported := 0
	for _, kind := range []string{"configuration", "network"} {
		stream, err := c.get(ctx, c.tailnet("logging/"+kind+"/stream"))
		if err != nil {
			if IsUnsupported(err) {
				data[kind] = map[string]any{"unsupported": true}
				continue
			}
			return nil, err
		}
		status, err := c.get(ctx, c.tailnet("logging/"+kind+"/stream/status"))
		if err != nil {
			if IsUnsupported(err) {
				data[kind] = map[string]any{"unsupported": true}
				continue
			}
			return nil, err
		}
		supported++
		data[kind] = map[string]any{"stream": stream, "status": status}
	}
	if supported == 0 {
		return nil, &HTTPError{Status: http.StatusNotFound, URL: "logging", Body: "all log streaming endpoints unsupported"}
	}
	return []model.Resource{{ID: "log_streaming", Type: "log_streaming", Name: "Log streaming configuration", Collector: "log_streaming", Data: data}}, nil
}

func (c *Client) single(ctx context.Context, endpoint, collector, typ, name string) ([]model.Resource, error) {
	value, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return []model.Resource{{ID: collector, Type: typ, Name: name, Collector: collector, Data: value}}, nil
}

func (c *Client) collection(ctx context.Context, endpoint, arrayKey, collector, typ string, ids []string) ([]model.Resource, error) {
	return c.collectionWithOptions(ctx, endpoint, arrayKey, collector, typ, ids, false)
}

func (c *Client) collectionWithOptions(ctx context.Context, endpoint, arrayKey, collector, typ string, ids []string, _ bool) ([]model.Resource, error) {
	values, err := c.allPagesWithOptions(ctx, endpoint, arrayKey)
	if err != nil {
		return nil, err
	}
	out := make([]model.Resource, 0, len(values))
	for _, value := range values {
		id := idFor(value, ids)
		if id == "" {
			_, hash, _ := model.Canonical(value)
			id = fmt.Sprintf("%s-%s", collector, hash[:12])
		}
		out = append(out, model.Resource{ID: id, Type: typ, Name: nameFor(value, id), Collector: collector, Data: value})
	}
	return out, nil
}

func (c *Client) allPages(ctx context.Context, endpoint, arrayKey string) ([]map[string]any, error) {
	return c.allPagesWithOptions(ctx, endpoint, arrayKey)
}

func (c *Client) allPagesWithOptions(ctx context.Context, endpoint, arrayKey string) ([]map[string]any, error) {
	next := endpoint
	var out []map[string]any
	seen := make(map[string]struct{})
	for page := 0; page < 100; page++ {
		if _, repeated := seen[next]; repeated {
			return nil, errors.New("tailscale pagination repeated the same page URL")
		}
		seen[next] = struct{}{}
		value, err := c.get(ctx, next)
		if err != nil {
			return nil, err
		}
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
		candidate := ""
		if objectOK {
			candidate = nextURL(object)
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

func nextURL(object map[string]any) string {
	if value, ok := object["next"].(string); ok {
		return value
	}
	if p, ok := object["pagination"].(map[string]any); ok {
		if value, ok := p["next"].(string); ok {
			return value
		}
		if cursor, ok := p["nextCursor"].(string); ok && cursor != "" {
			return "?cursor=" + url.QueryEscape(cursor)
		}
	}
	return ""
}

func (c *Client) get(ctx context.Context, endpoint string) (any, error) {
	// Bound the complete request, including token refreshes and all backoff
	// sleeps. If the caller already supplied an earlier deadline,
	// context.WithTimeout preserves that stricter limit.
	retryCtx, cancel := context.WithTimeout(ctx, maxRequestRetryDuration)
	defer cancel()
	for attempt := 0; attempt < 4; attempt++ {
		token, err := c.accessToken(retryCtx)
		if err != nil {
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
			return nil, fmt.Errorf("tailscale response exceeds %d bytes", maxAPIResponseBytes)
		}
		if resp.StatusCode == 401 && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		}
		if resp.StatusCode == 429 && attempt < 3 {
			delay := retryAfter(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*time.Second)
			if !waitForRetry(retryCtx, delay) {
				return nil, retryCtx.Err()
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &HTTPError{Status: resp.StatusCode, URL: endpoint, Body: safeBody(body)}
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return nil, nil
		}
		var value any
		if err := json.Unmarshal(body, &value); err != nil {
			return nil, fmt.Errorf("tailscale response was not valid JSON: %w", err)
		}
		return value, nil
	}
	return nil, errors.New("tailscale request retries exhausted")
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expires) > 5*time.Minute {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all:read"}, "client_id": {c.credentials.ClientID}, "client_secret": {c.credentials.ClientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.credentials.ClientID, c.credentials.ClientSecret)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
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
		return "", fmt.Errorf("OAuth token request returned %d", resp.StatusCode)
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

func (c *Client) tailnet(suffix string) string {
	tailnet := c.credentials.Tailnet
	if tailnet == "" {
		tailnet = "-"
	}
	return c.base + "/tailnet/" + url.PathEscape(tailnet) + "/" + suffix
}
func (c *Client) global(suffix string) string { return c.base + "/" + suffix }
func idFor(value map[string]any, keys []string) string {
	for _, key := range keys {
		if id, ok := value[key].(string); ok && id != "" {
			return id
		}
		if number, ok := value[key].(float64); ok {
			return strconv.FormatInt(int64(number), 10)
		}
	}
	return ""
}
func nameFor(value map[string]any, fallback string) string {
	for _, key := range []string{"name", "hostname", "deviceName", "loginName", "email", "description"} {
		if value, ok := value[key].(string); ok && value != "" {
			return value
		}
	}
	return fallback
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
