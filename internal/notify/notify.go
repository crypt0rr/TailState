// Package notify provides the notification transport used by TailState.
//
// Shoutrrr owns provider parsing and payload delivery. This package keeps the
// application-specific safety guarantees around it: bounded HTTP requests,
// redirects disabled, and no service credentials in returned errors.
package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nicholas-fedor/shoutrrr"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"

	"github.com/crypt0rr/tailstate/internal/textutil"
)

const (
	defaultTimeout = 15 * time.Second
	legacyUser     = "TailState"
	legacyIcon     = ":satellite:"
)

// Sender is the injectable delivery boundary used by the monitor.
type Sender interface {
	Send(ctx context.Context, serviceURL, message string) error
	Test(ctx context.Context, serviceURL string) error
}

// SenderImpl sends one message to one Shoutrrr destination.
type SenderImpl struct {
	client  *http.Client
	timeout time.Duration
}

// New returns a sender with bounded requests and redirects disabled.
func New() *SenderImpl {
	return &SenderImpl{
		client: &http.Client{
			Timeout:   defaultTimeout,
			Transport: rejectRedirectTransport{base: http.DefaultTransport},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		timeout: defaultTimeout,
	}
}

type rejectRedirectTransport struct{ base http.RoundTripper }

func (t rejectRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("redirect response %s", response.Status)
	}
	return response, nil
}

// Validate checks that a URL belongs to a service registered by the pinned
// Shoutrrr module. It does not make a network request.
func Validate(serviceURL string) error {
	serviceURL = strings.TrimSpace(serviceURL)
	if serviceURL == "" {
		return errors.New("notification URL is required")
	}
	if _, err := shoutrrr.CreateSenderWithOptions(types.SenderOptions{Timeout: defaultTimeout}, serviceURL); err != nil {
		return fmt.Errorf("invalid notification URL (%s): %s", RedactURL(serviceURL), sanitize(err.Error(), serviceURL))
	}
	return nil
}

// Send delivers message to exactly one destination. Shoutrrr's sender is
// created per call so a failure in one destination cannot affect another.
func (s *SenderImpl) Send(ctx context.Context, serviceURL, message string) error {
	if err := Validate(serviceURL); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sender, err := shoutrrr.CreateSenderWithOptions(types.SenderOptions{HTTPClient: s.client, Timeout: s.timeout}, serviceURL)
	if err != nil {
		return fmt.Errorf("create notification sender (%s): %s", RedactURL(serviceURL), sanitize(err.Error(), serviceURL))
	}
	errs := sender.Send(message, nil)
	for _, sendErr := range errs {
		if sendErr != nil {
			return &DeliveryError{Status: statusCode(sendErr.Error()), Message: sanitize(sendErr.Error(), serviceURL)}
		}
	}
	// A cancellation that arrives after Shoutrrr has returned successfully
	// means the provider accepted the message. Reporting that cancellation as
	// a send failure would leave the outbox pending and duplicate the alert on
	// restart. The pre-send check above still prevents new work after shutdown;
	// bookkeeping owns the result once the transport has completed.
	return nil
}

// Test validates and sends a small explicit message to a destination.
func (s *SenderImpl) Test(ctx context.Context, serviceURL string) error {
	return s.Send(ctx, serviceURL, "**TailState test**: notifications are configured correctly.")
}

// DeliveryError is a retryable transport error. All Shoutrrr delivery errors
// are retried by the durable outbox until its 24-hour horizon expires.
type DeliveryError struct {
	Status     int
	Message    string
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string { return e.Message }

// SafeDeliveryError converts an upstream delivery error into a bounded,
// provider-independent reason suitable for logs and durable outbox history.
// Provider messages may contain response bodies, request URLs, or arbitrary
// secrets; none of that text is trusted at the persistence boundary.
func SafeDeliveryError(err error) string {
	if err == nil {
		return "notification delivery failed"
	}
	var delivery *DeliveryError
	if errors.As(err, &delivery) && delivery != nil && delivery.Status >= 100 {
		return fmt.Sprintf("notification delivery failed with HTTP %d", delivery.Status)
	}
	if status := statusCode(err.Error()); status >= 100 {
		return fmt.Sprintf("notification delivery failed with HTTP %d", status)
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "deadline exceeded"), strings.Contains(message, "timeout"):
		return "notification delivery timed out"
	case strings.Contains(message, "canceled"), strings.Contains(message, "cancelled"):
		return "notification delivery canceled"
	default:
		return "notification delivery failed"
	}
}

// SafeDeliveryMessage applies the same trusted-reason policy when a caller
// only has an error string, such as a store retry boundary or a legacy caller.
func SafeDeliveryMessage(message string) string {
	message = strings.TrimSpace(message)
	switch message {
	case "destination disabled", "destination removed", "delivery retry window expired", "no notification destination configured", "monitoring identity changed", "collector reconciliation failed", "reconciliation retry window expired", "notification delivery failed", "notification delivery timed out", "notification delivery canceled":
		return message
	default:
		return SafeDeliveryError(errors.New(message))
	}
}

// SafeTestError keeps local validation errors useful in the Settings page
// while replacing provider delivery bodies with the same bounded,
// provider-independent reason used by durable outbox history. Shoutrrr may
// include arbitrary response text in DeliveryError, so callers must not
// render that error directly. When the destination URL is supplied, any
// non-delivery error is redacted against it before it is rendered. The
// variadic form preserves compatibility for callers that only have an error;
// those callers receive the same bounded fallback used by delivery history.
func SafeTestError(err error, serviceURLs ...string) string {
	if err == nil {
		return ""
	}
	var delivery *DeliveryError
	if errors.As(err, &delivery) {
		return SafeDeliveryError(err)
	}
	if isValidationError(err) {
		message := strings.TrimSpace(err.Error())
		if len(serviceURLs) > 0 && strings.TrimSpace(serviceURLs[0]) != "" {
			return RedactError(message, serviceURLs[0])
		}
		// The empty-URL validation error is already a fixed, non-sensitive
		// message. Keep it actionable when a test request is missing its
		// destination instead of collapsing it into a delivery failure.
		if message == "notification URL is required" {
			return message
		}
		// Other validation errors may contain provider parser details. Do not
		// echo those when the caller did not supply the URL for redaction.
		return "notification configuration is invalid"
	}
	return SafeDeliveryError(err)
}

func isValidationError(err error) bool {
	message := strings.TrimSpace(err.Error())
	return message == "notification URL is required" || strings.HasPrefix(message, "invalid notification URL") || strings.HasPrefix(message, "create notification sender")
}

var statusPattern = regexp.MustCompile(`\b([3-5][0-9]{2})\b`)

func statusCode(message string) int {
	match := statusPattern.FindStringSubmatch(message)
	if len(match) != 2 {
		return 0
	}
	var status int
	_, _ = fmt.Sscanf(match[1], "%d", &status)
	return status
}

// RedactURL returns scheme and host information while hiding credentials,
// paths, queries, fragments, and tokens.
func RedactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return "<redacted>"
	}
	host := u.Hostname()
	if host == "" {
		return u.Scheme + "://<redacted>"
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// ConvertLegacyMattermostURL upgrades an old raw Mattermost webhook URL to a
// Shoutrrr URL. Standard /hooks/<token> paths use native Mattermost; any other
// path is represented by generic JSON so no webhook routing information is
// lost.
func ConvertLegacyMattermostURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Mattermost webhook URL (%s)", RedactURL(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("mattermost webhook must use http or https (%s)", RedactURL(raw))
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 2 && segments[0] == "hooks" && segments[1] != "" && u.RawQuery == "" && u.Fragment == "" {
		out := &url.URL{Scheme: "mattermost", Host: u.Host, User: url.User(legacyUser), Path: "/" + segments[1], RawQuery: "icon=" + url.QueryEscape(legacyIcon)}
		if u.Scheme == "http" {
			out.RawQuery += "&disabletls=true"
		}
		return out.String(), nil
	}
	q := u.Query()
	q.Set("template", "json")
	q.Set("messagekey", "text")
	q.Set("$username", legacyUser)
	q.Set("$icon_emoji", legacyIcon)
	if u.Scheme == "http" {
		q.Set("disabletls", "true")
	}
	u.Scheme = "generic"
	u.User = nil
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String(), nil
}

func sanitize(message, rawURL string) string {
	type replacement struct{ from, to string }
	replacements := make([]replacement, 0, 12)
	add := func(from, to string) {
		if from == "" {
			return
		}
		for _, existing := range replacements {
			if existing.from == from {
				return
			}
		}
		replacements = append(replacements, replacement{from: from, to: to})
	}
	add(rawURL, RedactURL(rawURL))
	if parsed, err := url.Parse(rawURL); err == nil {
		add(parsed.String(), RedactURL(rawURL))
		add(parsed.RawQuery, "<redacted>")
		// URL parsing exposes a decoded Path/Fragment, but provider errors often
		// echo the escaped spelling from the request line. Replace both forms so
		// an encoded slash, space, or credential cannot bypass redaction.
		add(parsed.EscapedPath(), "/<redacted>")
		add(parsed.RawPath, "/<redacted>")
		addEncodedVariants(add, parsed.Fragment)
		addEncodedVariants(add, parsed.RawFragment)
		if parsed.User != nil {
			addEncodedVariants(add, parsed.User.String())
			addEncodedVariants(add, parsed.User.Username())
			if password, ok := parsed.User.Password(); ok {
				addEncodedVariants(add, password)
			}
		}
		add(parsed.Host, "<redacted>")
		add(parsed.Path, "/<redacted>")
		for _, segment := range strings.Split(strings.Trim(parsed.Path, "/"), "/") {
			add(segment, "<redacted>")
		}
		for _, segment := range strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/") {
			addEncodedVariants(add, segment)
		}
		// Errors do not consistently preserve URL formatting. Some providers
		// include the complete RawQuery, while others echo only an encoded
		// parameter value (for example, `token=secret%2Fpart`). Add both the
		// raw and decoded forms of every query component so neither form can
		// bypass the replacement set.
		for _, component := range strings.FieldsFunc(parsed.RawQuery, func(r rune) bool { return r == '&' || r == ';' }) {
			rawKey, rawValue, hasValue := strings.Cut(component, "=")
			add(rawKey, "<redacted>")
			if !hasValue {
				add(component, "<redacted>")
				continue
			}
			if rawValue == "" {
				continue
			}
			addEncodedVariants(add, rawValue)
		}
		for _, values := range parsed.Query() {
			for _, value := range values {
				addEncodedVariants(add, value)
			}
		}
	}
	sort.SliceStable(replacements, func(i, j int) bool { return len(replacements[i].from) > len(replacements[j].from) })
	for _, replacement := range replacements {
		message = strings.ReplaceAll(message, replacement.from, replacement.to)
	}
	return truncate(message, 500)
}

// addEncodedVariants adds bounded URL-encoding and decoding variants for an
// untrusted credential. Providers do not agree on whether an echoed URL is
// decoded once, repeatedly, or re-escaped with query/path rules. Covering a
// small number of layers prevents a double-encoded token from reaching the
// durable error boundary without turning sanitization into unbounded parsing.
func addEncodedVariants(add func(string, string), value string) {
	type candidate struct {
		value string
		depth int
	}
	queue := []candidate{{value: value}}
	seen := map[string]struct{}{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.value == "" || current.depth > 3 {
			continue
		}
		if _, exists := seen[current.value]; exists {
			continue
		}
		seen[current.value] = struct{}{}
		add(current.value, "<redacted>")
		add(url.QueryEscape(current.value), "<redacted>")
		add(url.PathEscape(current.value), "<redacted>")
		for _, decode := range []func(string) (string, error){url.QueryUnescape, url.PathUnescape} {
			decoded, err := decode(current.value)
			if err == nil && decoded != current.value {
				queue = append(queue, candidate{value: decoded, depth: current.depth + 1})
			}
		}
	}
}

// RedactError removes destination-specific credentials and routing details
// from an upstream error before it is persisted or rendered by another
// package. It is intentionally the same sanitizer used at the transport
// boundary so injected senders receive the same protection as Shoutrrr.
func RedactError(message, serviceURL string) string {
	return sanitize(message, serviceURL)
}

func truncate(value string, n int) string {
	return textutil.Truncate(value, n)
}
