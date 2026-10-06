package tailscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

var CoreCollectors = []string{"devices"}
var InventoryCollectors = []string{"device_details", "users", "user_invites", "dns", "policy", "keys", "webhooks", "log_streaming", "contacts", "posture", "settings", "services", "oauth_apps"}

// DefaultOAuthScope is requested when no scopes are configured.
const DefaultOAuthScope = "all:read"

// Credentials identify the OAuth client and tailnet. Scopes lists the OAuth
// scopes requested for the access token; an empty list requests
// DefaultOAuthScope.
type Credentials struct {
	Tailnet, ClientID, ClientSecret string
	Scopes                          []string
}

// CollectionLimits bound the aggregate amount of data retained while a
// paginated collection is assembled. The per-response limit in get is still
// applied independently; these limits protect the process from a sequence of
// individually valid but collectively oversized pages.
type CollectionLimits struct {
	MaxItems int
	MaxBytes int64
}

const (
	defaultCollectionItems = 10_000
	defaultCollectionBytes = 64 << 20
	deviceDetailWorkers    = 8
)

// DefaultCollectionLimits returns the aggregate collection guardrails used by
// newly created clients.
func DefaultCollectionLimits() CollectionLimits {
	return CollectionLimits{MaxItems: defaultCollectionItems, MaxBytes: defaultCollectionBytes}
}

type Client struct {
	base, tokenURL, version string
	credentials             Credentials
	http                    *http.Client
	collectionLimits        CollectionLimits
	mu                      sync.Mutex
	deviceCacheMu           sync.RWMutex
	deviceCache             []map[string]any
	token                   string
	expires                 time.Time
	// detailMu guards the device-detail refresh order. detailAttempt records
	// the poll sequence in which each device's detail requests last ran to
	// completion so a deadline-limited poll starts with the stalest devices
	// and every device is eventually refreshed.
	detailMu      sync.Mutex
	detailPoll    int64
	detailAttempt map[string]int64
}

type HTTPError struct {
	Status int
	URL    string
	Body   string
}

// PartialError reports a collector response that contained usable resources
// but could not complete every related request. Count is the number of
// resources missing from the response, including resources that were never
// requested because a deadline expired. Callers may apply the returned
// resources while preserving existing snapshots for missing items.
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

// UnsupportedReason returns a bounded, operator-facing label for an
// unsupported collector response. A 403 is what Tailscale returns both for a
// plan without the feature and for an access token that lacks the scope, so
// the label names both; a 404 means the endpoint or feature is not available
// for this tailnet. Provider response text is never included.
func UnsupportedReason(err error) string {
	var e *HTTPError
	if errors.As(err, &e) && e.Status == http.StatusForbidden {
		return "unsupported (insufficient OAuth scope or plan: HTTP 403)"
	}
	if errors.As(err, &e) && e.Status == http.StatusNotFound {
		return "unsupported (not available for this tailnet: HTTP 404)"
	}
	return "unsupported"
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
	return &Client{base: strings.TrimRight(base, "/"), tokenURL: tokenURL, version: version, credentials: credentials, collectionLimits: DefaultCollectionLimits(), http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: noRedirect}}
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
		return c.collection(ctx, c.tailnet("users?type=all"), "users", collector, "user", []string{"id", "userId", "userID", "loginName"})
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
	case "services":
		// Per-service hosts and approvals are not collected: Tailscale requires
		// the write-capable "services" scope for those endpoints, which a
		// read-only monitor must not hold.
		return c.collection(ctx, c.tailnet("services"), "vipServices", collector, "service", []string{"name"})
	case "oauth_apps":
		return c.collection(ctx, c.tailnet("oauth-apps"), "oauthApps", collector, "oauth_app", []string{"id"})
	default:
		return nil, fmt.Errorf("unknown collector %q", collector)
	}
}

// dns reads the combined DNS configuration endpoint, which also reports
// per-resolver useWithExitNode and the overrideLocalDNS preference. A 404
// (an API without the endpoint) falls back to the four legacy endpoints. The
// store compares the two shapes on the fields both can express, so switching
// between them never reports drift by itself.
func (c *Client) dns(ctx context.Context) ([]model.Resource, error) {
	value, err := c.getObject(ctx, c.tailnet("dns/configuration"), "DNS configuration")
	if err == nil {
		return []model.Resource{{ID: "dns", Type: "dns", Name: "DNS configuration", Collector: "dns", Data: value}}, nil
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound {
		return c.legacyDNS(ctx)
	}
	return nil, err
}

func (c *Client) legacyDNS(ctx context.Context) ([]model.Resource, error) {
	data := map[string]any{}
	supported := 0
	for _, endpoint := range []string{"nameservers", "preferences", "searchpaths", "split-dns"} {
		value, err := c.getObject(ctx, c.tailnet("dns/"+endpoint), "DNS "+endpoint)
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
	object, err := c.getObject(ctx, c.tailnet("acl"), "policy")
	if err != nil {
		return nil, err
	}
	sections := map[string]any{}
	for key, section := range object {
		raw, _, _ := model.CanonicalForSection("policy", key, section)
		sum := sha256.Sum256(raw)
		sections[key] = hex.EncodeToString(sum[:])
	}
	return []model.Resource{{ID: "policy", Type: "policy", Name: "Tailnet policy", Collector: "policy", Data: sections}}, nil
}

// logStreaming collects both log-streaming kinds. Tailscale documents a 404
// from /logging/{kind}/stream as "log streaming has not been configured" (the
// same status is also used for an unsupported kind or insufficient access),
// so a 404 is recorded as an explicit, diffable {"configured": false} state
// rather than as a plan capability. Disabling a stream therefore produces a
// change event instead of silently demoting the collector. Only a 403 for
// every kind is treated as an unsupported collector.
func (c *Client) logStreaming(ctx context.Context) ([]model.Resource, error) {
	data := map[string]any{}
	forbidden := 0
	for _, kind := range []string{"configuration", "network"} {
		stream, err := c.getObject(ctx, c.tailnet("logging/"+kind+"/stream"), kind+" log stream")
		if err != nil {
			var httpErr *HTTPError
			switch {
			case errors.As(err, &httpErr) && httpErr.Status == http.StatusNotFound:
				data[kind] = map[string]any{"configured": false}
				continue
			case errors.As(err, &httpErr) && httpErr.Status == http.StatusForbidden:
				forbidden++
				data[kind] = map[string]any{"configured": false}
				continue
			}
			return nil, err
		}
		var status any
		status, err = c.getObject(ctx, c.tailnet("logging/"+kind+"/stream/status"), kind+" log stream status")
		if err != nil {
			// The stream configuration was read successfully; a missing
			// status or an unreachable logging backend must not discard it.
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || (httpErr.Status != http.StatusNotFound && httpErr.Status != http.StatusForbidden && httpErr.Status != http.StatusBadGateway) {
				return nil, err
			}
			status = map[string]any{"state": logStreamStatusUnavailable}
		}
		data[kind] = map[string]any{"stream": stream, "status": status}
	}
	if forbidden == len(data) {
		return nil, &HTTPError{Status: http.StatusForbidden, URL: "logging", Body: "log streaming endpoints forbidden"}
	}
	return []model.Resource{{ID: "log_streaming", Type: "log_streaming", Name: "Log streaming configuration", Collector: "log_streaming", Data: data}}, nil
}

// logStreamStatusUnavailable mirrors model.HealthStatusUnavailable; the
// model package keeps it through status normalization.
const logStreamStatusUnavailable = model.HealthStatusUnavailable

func (c *Client) single(ctx context.Context, endpoint, collector, typ, name string) ([]model.Resource, error) {
	value, err := c.getObject(ctx, endpoint, collector)
	if err != nil {
		return nil, err
	}
	return []model.Resource{{ID: collector, Type: typ, Name: name, Collector: collector, Data: value}}, nil
}

// getObject fetches a single-object endpoint. Settings, contacts, policy, the
// DNS configuration and legacy DNS sub-endpoints, and log-streaming
// configuration are always JSON objects;
// an empty body, null, an array or a scalar is an invalid upstream response.
// Returning an error keeps the last snapshot instead of replacing a baseline
// with a degenerate value (and reporting the flip back as drift later).
func (c *Client) getObject(ctx context.Context, endpoint, name string) (map[string]any, error) {
	value, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, fmt.Errorf("tailscale %s response was not a JSON object", name)
	}
	return object, nil
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
