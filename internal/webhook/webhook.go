// Package webhook verifies and classifies Tailscale webhook deliveries.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	MaxBodyBytes    = 1 << 20
	maxEvents       = 100
	maxEventTypeLen = 128
	maxSignatureAge = 24 * time.Hour
	maxFutureSkew   = 5 * time.Minute
)

// Event is the non-sensitive metadata TailState needs to choose a targeted
// reconciliation. The provider data is deliberately not retained.
type Event struct {
	Timestamp string          `json:"timestamp"`
	Version   json.RawMessage `json:"version"`
	Type      string          `json:"type"`
	Tailnet   string          `json:"tailnet"`
	Message   string          `json:"message"`
	Data      json.RawMessage `json:"data"`
}

// Delivery contains the verified event metadata and a stable hash of the
// original request body. The hash is safe to persist and use for deduplication.
type Delivery struct {
	Events     []Event
	BodyHash   string
	EventTypes []string
	Collectors []string
}

// Verify validates a Tailscale-Webhook-Signature header, parses the documented
// event-array body, and returns only metadata needed by the monitor. It accepts
// retries for up to 24 hours while rejecting timestamps too far in the future;
// the persisted body hash prevents replaying an already accepted body.
func Verify(body []byte, signature, secret string, now time.Time) (Delivery, error) {
	if len(body) == 0 {
		return Delivery{}, errors.New("webhook body is empty")
	}
	if len(body) > MaxBodyBytes {
		return Delivery{}, errors.New("webhook body is too large")
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return Delivery{}, errors.New("webhook secret is not configured")
	}
	timestamp, signatures, err := parseSignature(signature)
	if err != nil {
		return Delivery{}, err
	}
	when := time.Unix(timestamp, 0)
	if when.After(now.Add(maxFutureSkew)) || now.Sub(when) > maxSignatureAge {
		return Delivery{}, errors.New("webhook signature timestamp is outside the accepted window")
	}
	message := strconv.FormatInt(timestamp, 10) + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(message))
	want := mac.Sum(nil)
	valid := false
	for _, encoded := range signatures {
		provided, decodeErr := decodeSignature(encoded)
		if decodeErr == nil && hmac.Equal(provided, want) {
			valid = true
			break
		}
	}
	if !valid {
		return Delivery{}, errors.New("webhook signature is invalid")
	}

	var events []Event
	if err := json.Unmarshal(body, &events); err != nil {
		return Delivery{}, errors.New("webhook body is not a JSON event array")
	}
	if len(events) == 0 || len(events) > maxEvents {
		return Delivery{}, fmt.Errorf("webhook event count must be between 1 and %d", maxEvents)
	}
	eventTypes := make([]string, 0, len(events))
	for i := range events {
		events[i].Type = strings.TrimSpace(events[i].Type)
		if events[i].Type == "" {
			return Delivery{}, errors.New("webhook event type is missing")
		}
		if len(events[i].Type) > maxEventTypeLen {
			return Delivery{}, fmt.Errorf("webhook event type exceeds %d bytes", maxEventTypeLen)
		}
		eventTypes = append(eventTypes, events[i].Type)
	}
	sum := sha256.Sum256(body)
	return Delivery{
		Events:     events,
		BodyHash:   hex.EncodeToString(sum[:]),
		EventTypes: uniqueSorted(eventTypes),
		Collectors: CollectorsFor(events),
	}, nil
}

func parseSignature(value string) (int64, []string, error) {
	var timestamp int64
	var foundTimestamp bool
	var signatures []string
	for _, part := range strings.Split(value, ",") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "t":
			if foundTimestamp {
				return 0, nil, errors.New("webhook signature has duplicate timestamp")
			}
			parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil || parsed <= 0 {
				return 0, nil, errors.New("webhook signature timestamp is invalid")
			}
			timestamp, foundTimestamp = parsed, true
		case "v1":
			if strings.TrimSpace(raw) != "" {
				signatures = append(signatures, strings.TrimSpace(raw))
			}
		}
	}
	if !foundTimestamp || len(signatures) == 0 {
		return 0, nil, errors.New("webhook signature is missing")
	}
	return timestamp, signatures, nil
}

func decodeSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	return nil, errors.New("webhook signature encoding is invalid")
}

// CollectorsFor maps documented Tailscale event types to the smallest useful
// collector set. Unknown events deliberately trigger a complete reconciliation
// so a newly introduced provider event cannot leave stale state behind.
func CollectorsFor(events []Event) []string {
	collectors := map[string]struct{}{}
	for _, event := range events {
		switch strings.ToLower(strings.TrimSpace(event.Type)) {
		case "nodeapproved", "nodeauthorized", "nodecreated", "nodedeleted", "nodekeyexpired", "nodekeyexpiringinoneday", "nodeneedsapproval", "nodeneedsauthorization", "nodeneedssignature", "nodesigned", "exitnodeipforwardingnotenabled", "subnetipforwardingnotenabled":
			collectors["devices"] = struct{}{}
			collectors["device_details"] = struct{}{}
		case "userapproved", "usercreated", "userneedsapproval", "userroleupdated":
			collectors["users"] = struct{}{}
			collectors["user_invites"] = struct{}{}
		case "policyupdate":
			collectors["policy"] = struct{}{}
		case "webhookcreated", "webhookdeleted", "webhookupdated":
			collectors["webhooks"] = struct{}{}
		default:
			return nil
		}
	}
	out := make([]string, 0, len(collectors))
	for collector := range collectors {
		out = append(out, collector)
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// SignatureForTest returns the documented signature format for unit tests and
// local integration tests. Production callers should never need this helper.
func SignatureForTest(body []byte, secret string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "." + string(body)))
	return "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Method reports whether a request uses the only supported webhook method.
func Method(rMethod string) bool { return rMethod == http.MethodPost }
