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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

var CoreCollectors = []string{"devices"}
var InventoryCollectors = []string{"device_details", "users", "user_invites", "dns", "policy", "keys", "webhooks", "log_streaming", "contacts", "posture", "settings"}

type Credentials struct{ Tailnet, ClientID, ClientSecret string }

type Client struct {
	base, tokenURL, version string
	credentials             Credentials
	http                    *http.Client
	mu                      sync.Mutex
	token                   string
	expires                 time.Time
}

type HTTPError struct {
	Status int
	URL    string
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("Tailscale GET returned %d", e.Status) }
func IsUnsupported(err error) bool {
	var e *HTTPError
	return errors.As(err, &e) && (e.Status == http.StatusForbidden || e.Status == http.StatusNotFound)
}

func New(base, tokenURL, version string, credentials Credentials) *Client {
	return &Client{base: strings.TrimRight(base, "/"), tokenURL: tokenURL, version: version, credentials: credentials, http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) Test(ctx context.Context) error { _, err := c.Collect(ctx, "devices"); return err }

func (c *Client) Collect(ctx context.Context, collector string) ([]model.Resource, error) {
	switch collector {
	case "devices":
		return c.collection(ctx, c.tailnet("devices?fields=all"), "devices", collector, "device", []string{"id", "nodeId", "nodeID"})
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
	devices, err := c.allPages(ctx, c.tailnet("devices?fields=all"), "devices")
	if err != nil {
		return nil, err
	}
	out := make([]model.Resource, 0, len(devices))
	for _, device := range devices {
		id := idFor(device, []string{"id", "nodeId", "nodeID"})
		if id == "" {
			continue
		}
		combined := map[string]any{}
		for key, path := range map[string]string{"routes": "routes", "postureAttributes": "attributes", "deviceInvites": "device-invites"} {
			value, e := c.get(ctx, c.global("device/"+url.PathEscape(id)+"/"+path))
			if e != nil {
				if IsUnsupported(e) {
					combined[key] = map[string]any{"unsupported": true}
					continue
				}
				return nil, e
			}
			combined[key] = value
		}
		out = append(out, model.Resource{ID: id, Type: "device_details", Name: nameFor(device, id), Collector: "device_details", Data: combined})
	}
	return out, nil
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
			raw, _, _ := model.Canonical(section)
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
	values, err := c.allPages(ctx, endpoint, arrayKey)
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
	next := endpoint
	var out []map[string]any
	for page := 0; page < 100; page++ {
		value, err := c.get(ctx, next)
		if err != nil {
			return nil, err
		}
		object, objectOK := value.(map[string]any)
		var items []any
		if objectOK {
			items, _ = object[arrayKey].([]any)
		} else {
			items, _ = value.([]any)
		}
		if items == nil {
			return nil, fmt.Errorf("%s response has no %s array", arrayKey, arrayKey)
		}
		for _, item := range items {
			if obj, ok := item.(map[string]any); ok {
				out = append(out, obj)
			}
		}
		candidate := ""
		if objectOK {
			candidate = nextURL(object)
		}
		if candidate == "" {
			return out, nil
		}
		parsed, err := url.Parse(candidate)
		if err != nil {
			return nil, err
		}
		if !parsed.IsAbs() {
			base, _ := url.Parse(next)
			candidate = base.ResolveReference(parsed).String()
		}
		next = candidate
	}
	return nil, errors.New("tailscale pagination exceeded 100 pages")
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
	for attempt := 0; attempt < 4; attempt++ {
		token, err := c.accessToken(ctx)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "tailstate/"+c.version)
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < 3 {
				if !sleep(ctx, time.Duration(1<<attempt)*time.Second) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, err
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode == 401 && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		}
		if resp.StatusCode == 429 && attempt < 3 {
			delay := retryAfter(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*time.Second)
			if !sleep(ctx, delay) {
				return nil, ctx.Err()
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
			return string(body), nil
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
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
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return max(time.Until(when), 0)
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
func safeBody(body []byte) string {
	value := strings.TrimSpace(string(body))
	if len(value) > 200 {
		value = value[:200] + "…"
	}
	return value
}
