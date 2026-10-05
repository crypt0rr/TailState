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
	"unicode"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

// Verification errors are classified so the HTTP handler can answer with the
// right status: ErrUnauthenticated (401) for signature or timestamp failures,
// ErrBodyTooLarge (413), and ErrMalformedBody (400) for an empty body or one
// that is not a JSON event array.
var (
	ErrUnauthenticated = errors.New("webhook signature verification failed")
	ErrBodyTooLarge    = errors.New("webhook body is too large")
	ErrMalformedBody   = errors.New("webhook body is malformed")
)

// Content fallback reasons. A delivery whose signature is valid but whose
// content falls outside TailState's bounds is still accepted; it requests a
// full reconciliation instead of a targeted one.
const (
	FallbackEventCount       = "event_count"
	FallbackEventTypeMissing = "event_type_missing"
	FallbackEventTypeLength  = "event_type_length"
	FallbackEventTypeInvalid = "event_type_invalid"
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
	// FallbackReason is set when the authentic content exceeded TailState's
	// bounds. Collectors is then nil (a full reconciliation) and EventTypes
	// holds only bounded, sanitized metadata.
	FallbackReason string
}

// Verify validates a Tailscale-Webhook-Signature header, parses the documented
// event-array body, and returns only metadata needed by the monitor. It accepts
// retries for up to 24 hours while rejecting timestamps too far in the future;
// the persisted body hash prevents replaying an already accepted body.
func Verify(body []byte, signature, secret string, now time.Time) (Delivery, error) {
	if len(body) == 0 {
		return Delivery{}, fmt.Errorf("%w: webhook body is empty", ErrMalformedBody)
	}
	if len(body) > MaxBodyBytes {
		return Delivery{}, ErrBodyTooLarge
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return Delivery{}, fmt.Errorf("%w: webhook secret is not configured", ErrUnauthenticated)
	}
	timestamp, signatures, err := parseSignature(signature)
	if err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	when := time.Unix(timestamp, 0)
	if when.After(now.Add(maxFutureSkew)) || now.Sub(when) > maxSignatureAge {
		return Delivery{}, fmt.Errorf("%w: webhook signature timestamp is outside the accepted window", ErrUnauthenticated)
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
		return Delivery{}, fmt.Errorf("%w: webhook signature is invalid", ErrUnauthenticated)
	}

	// From here on the request is authentic. Content TailState cannot map to
	// a targeted reconciliation is not an authentication failure: it is
	// accepted and falls back to a full reconciliation.
	var events []Event
	if err := json.Unmarshal(body, &events); err != nil {
		return Delivery{}, fmt.Errorf("%w: webhook body is not a JSON event array", ErrMalformedBody)
	}
	sum := sha256.Sum256(body)
	delivery := Delivery{Events: events, BodyHash: hex.EncodeToString(sum[:])}
	if len(events) == 0 || len(events) > maxEvents {
		delivery.FallbackReason = FallbackEventCount
	}
	eventTypes := make([]string, 0, min(len(events), maxEvents))
	for i := range events {
		events[i].Type = strings.TrimSpace(events[i].Type)
		eventType := events[i].Type
		switch {
		case eventType == "":
			if delivery.FallbackReason == "" {
				delivery.FallbackReason = FallbackEventTypeMissing
			}
			continue
		case strings.IndexFunc(eventType, unicode.IsControl) >= 0:
			if delivery.FallbackReason == "" {
				delivery.FallbackReason = FallbackEventTypeInvalid
			}
			continue
		case len(eventType) > maxEventTypeLen:
			if delivery.FallbackReason == "" {
				delivery.FallbackReason = FallbackEventTypeLength
			}
			eventType = textutil.Truncate(eventType, maxEventTypeLen)
		}
		eventTypes = append(eventTypes, eventType)
	}
	eventTypes = uniqueSorted(eventTypes)
	if len(eventTypes) > maxEvents {
		eventTypes = eventTypes[:maxEvents]
	}
	delivery.EventTypes = eventTypes
	if delivery.FallbackReason == "" {
		delivery.Collectors = CollectorsFor(events)
	}
	return delivery, nil
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
