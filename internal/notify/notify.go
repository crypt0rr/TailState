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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nicholas-fedor/shoutrrr"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/discord"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/matrix"
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

// PreparedSender is implemented by senders that deliver a prepared message's
// title as a separate field (see Prepared). SenderImpl implements it.
type PreparedSender interface {
	SendPrepared(ctx context.Context, serviceURL string, message Prepared) error
}

// Deliver sends a prepared message through sender: with its separate title
// when sender supports it, otherwise as the complete text.
func Deliver(ctx context.Context, sender Sender, serviceURL string, message Prepared) error {
	if prepared, ok := sender.(PreparedSender); ok {
		return prepared.SendPrepared(ctx, serviceURL, message)
	}
	return sender.Send(ctx, serviceURL, message.Text)
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

// rejectRedirectTransport refuses redirects and, when record is set, notes
// the status and Retry-After of every response so a failed send can be
// classified from the real HTTP outcome instead of from provider text.
type rejectRedirectTransport struct {
	base   http.RoundTripper
	record *responseRecord
}

func (t rejectRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	t.record.observe(response)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		return nil, fmt.Errorf("redirect response %s", response.Status)
	}
	return response, nil
}

// maxRetryAfter caps a provider's Retry-After hint so a hostile or buggy
// response cannot park a notification for most of its 24-hour retry window.
const maxRetryAfter = time.Hour

// responseRecord holds the last HTTP response observed during one Send call.
// Each call owns its own record, so concurrent sends never share outcomes.
type responseRecord struct {
	mu         sync.Mutex
	status     int
	retryAfter time.Duration
}

func (r *responseRecord) observe(response *http.Response) {
	if r == nil {
		return
	}
	retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now())
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = response.StatusCode
	r.retryAfter = retryAfter
}

// failure returns the final response's status and Retry-After when that
// response was not successful. A successful final response (for example a
// Matrix login followed by a network failure) is not a delivery status.
func (r *responseRecord) failure() (int, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status < 300 {
		return 0, 0
	}
	return r.status, r.retryAfter
}

// parseRetryAfter accepts both Retry-After forms (delay-seconds and
// HTTP-date) and returns a positive delay capped at maxRetryAfter, or zero.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds >= int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(value); err == nil {
		delay = when.Sub(now)
	}
	return min(max(delay, 0), maxRetryAfter)
}

// clientFor returns a per-send copy of the bounded client whose transport
// records responses into record.
func (s *SenderImpl) clientFor(record *responseRecord) *http.Client {
	client := *s.client
	base := client.Transport
	if reject, ok := base.(rejectRedirectTransport); ok {
		base = reject.base
	}
	client.Transport = rejectRedirectTransport{base: base, record: record}
	return &client
}

// messageSender is the part of a Shoutrrr sender TailState uses.
type messageSender interface {
	Send(message string, params *types.Params) []error
}

// newSender constructs the Shoutrrr sender for one destination. Construction
// is not always local: Shoutrrr's Matrix service logs in to the homeserver
// while it is initialised when the URL carries a user and password, and the
// router only injects a custom HTTP client after initialisation. Matrix is
// therefore built directly with client in place first, so its login uses
// TailState's bounded, redirect-rejecting transport like every other request.
// Discord is also built directly, so its body can be sent as embeds of whole
// lines (see newDiscordSender).
func newSender(serviceURL string, client *http.Client, timeout time.Duration) (messageSender, error) {
	if parsed, err := url.Parse(serviceURL); err == nil && parsed.Scheme == matrix.Scheme {
		service := &matrix.Service{}
		service.SetHTTPClient(client)
		if err := service.Initialize(parsed, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", matrix.Scheme, err)
		}
		return matrixSender{service: service, timeout: timeout}, nil
	} else if err == nil && parsed.Scheme == discord.Scheme {
		return newDiscordSender(parsed, client, timeout)
	}
	return shoutrrr.CreateSenderWithOptions(types.SenderOptions{HTTPClient: client, Timeout: timeout}, serviceURL)
}

// matrixSender applies the router's per-send deadline to a directly
// constructed Matrix service.
type matrixSender struct {
	service *matrix.Service
	timeout time.Duration
}

func (m matrixSender) Send(message string, params *types.Params) []error {
	if params == nil {
		params = &types.Params{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	return []error{m.service.SendWithContext(ctx, message, params)}
}

// Validate checks that a URL belongs to a service registered by the pinned
// Shoutrrr module by constructing its sender. For most services this is a
// local parse, but a Matrix URL with a user and password logs in to the
// homeserver during construction, so validating one makes network requests
// through TailState's bounded transport. Access-token Matrix URLs do not log
// in.
func Validate(serviceURL string) error {
	serviceURL = strings.TrimSpace(serviceURL)
	if serviceURL == "" {
		return errors.New("notification URL is required")
	}
	if _, err := newSender(serviceURL, New().client, defaultTimeout); err != nil {
		return fmt.Errorf("invalid notification URL (%s): %s", RedactURL(serviceURL), sanitize(err.Error(), serviceURL))
	}
	return nil
}

// Send delivers a complete, pre-rendered message to exactly one destination.
// It sends no separate title; see SendPrepared.
func (s *SenderImpl) Send(ctx context.Context, serviceURL, message string) error {
	return s.SendPrepared(ctx, serviceURL, Prepared{Text: message})
}

// SendPrepared delivers message to exactly one destination. Shoutrrr's
// sender is created per call so a failure in one destination cannot affect
// another. The sender is constructed exactly once per call, and that
// construction is also the URL validation, so a Matrix password URL logs in
// once per delivery rather than once for validation and again for sending.
//
// Only allowlisted Shoutrrr parameters are passed (see serviceParams): the
// title when the destination receives it separately, never overriding a
// value set in the destination URL.
func (s *SenderImpl) SendPrepared(ctx context.Context, serviceURL string, message Prepared) error {
	serviceURL = strings.TrimSpace(serviceURL)
	if serviceURL == "" {
		return errors.New("notification URL is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	record := &responseRecord{}
	sender, err := newSender(serviceURL, s.clientFor(record), s.timeout)
	if err != nil {
		// A construction that reached the provider (a Matrix login) is a
		// delivery outcome: classify it like any other HTTP response so a
		// rejected password dead-letters and a rate limit honours Retry-After.
		if status, retryAfter := record.failure(); status != 0 {
			return &DeliveryError{Status: status, Message: sanitize(err.Error(), serviceURL), RetryAfter: retryAfter, Permanent: permanentDeliveryFailure(err.Error(), status)}
		}
		return fmt.Errorf("invalid notification URL (%s): %s", RedactURL(serviceURL), sanitize(err.Error(), serviceURL))
	}
	params := parseDestination(serviceURL).params(message.Title)
	errs := sender.Send(FitMessage(message.Message(), MessageLimit(serviceURL)), params)
	for _, sendErr := range errs {
		if sendErr != nil {
			// The status comes only from the response TailState's transport
			// observed. Provider error text is never parsed for a status: it
			// contains port numbers, SMTP codes, and other unrelated digits.
			status, retryAfter := record.failure()
			return &DeliveryError{Status: status, Message: sanitize(sendErr.Error(), serviceURL), RetryAfter: retryAfter, Permanent: permanentDeliveryFailure(sendErr.Error(), status)}
		}
	}
	// A cancellation that arrives after Shoutrrr has returned successfully
	// means the provider accepted the message. Reporting that cancellation as
	// a send failure would leave the outbox pending and duplicate the alert on
	// restart. The pre-send check above still prevents new work after shutdown;
	// bookkeeping owns the result once the transport has completed.
	return nil
}

// Test validates and sends a small explicit message to a destination. The
// Settings page sends Context.Test instead, which also names the instance,
// tailnet, and version.
func (s *SenderImpl) Test(ctx context.Context, serviceURL string) error {
	return s.SendPrepared(ctx, serviceURL, PrepareMessage(Context{}.Test(time.Now()), serviceURL, ""))
}

// DeliveryError is a transport error. Retryable errors are retried by the
// durable outbox until its 24-hour horizon expires; Permanent errors (for
// example a message the provider rejects as too large) can never succeed on
// retry and are dead-lettered immediately.
type DeliveryError struct {
	Status     int
	Message    string
	RetryAfter time.Duration
	Permanent  bool
}

// messageTooLargeReason is the persisted reason for a payload a provider
// rejected as too large.
const messageTooLargeReason = "notification rejected by provider: message too large for this destination"

// permanentStatusReasons are the persisted reasons for HTTP statuses that no
// retry can fix: a malformed request, revoked or missing credentials, or a
// deleted webhook. 413 uses messageTooLargeReason.
var permanentStatusReasons = map[int]string{
	http.StatusBadRequest:   "notification rejected by provider (HTTP 400)",
	http.StatusUnauthorized: "notification rejected by provider (HTTP 401)",
	http.StatusForbidden:    "notification rejected by provider (HTTP 403)",
	http.StatusNotFound:     "notification rejected by provider (HTTP 404)",
}

// permanentDeliveryFailure reports provider responses that no retry of the
// same payload can fix.
func permanentDeliveryFailure(message string, status int) bool {
	if _, ok := permanentStatusReasons[status]; ok || status == http.StatusRequestEntityTooLarge {
		return true
	}
	return messageTooLarge(message)
}

// messageTooLarge recognises Shoutrrr's local size rejections, which happen
// before any HTTP request is made.
func messageTooLarge(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "exceeds the max length") || strings.Contains(lower, "exceeds max size") || strings.Contains(lower, "message too long")
}

// IsPermanent reports whether err is a delivery failure that retrying the
// same payload cannot fix.
func IsPermanent(err error) bool {
	var delivery *DeliveryError
	return errors.As(err, &delivery) && delivery != nil && delivery.Permanent
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
	if errors.As(err, &delivery) && delivery != nil {
		if delivery.Permanent {
			if reason, ok := permanentStatusReasons[delivery.Status]; ok {
				return reason
			}
			if delivery.Status == http.StatusRequestEntityTooLarge || messageTooLarge(delivery.Message) {
				return messageTooLargeReason
			}
		}
		if delivery.Status >= 100 && delivery.Status <= 599 {
			return httpFailureReason(delivery.Status)
		}
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
	case "destination disabled", "destination removed", "delivery retry window expired", "no notification destination configured", "monitoring identity changed", "collector reconciliation failed", "reconciliation retry window expired", "notification delivery failed", "notification delivery timed out", "notification delivery canceled", messageTooLargeReason,
		permanentStatusReasons[http.StatusBadRequest], permanentStatusReasons[http.StatusUnauthorized], permanentStatusReasons[http.StatusForbidden], permanentStatusReasons[http.StatusNotFound]:
		return message
	}
	// Only the exact reason SafeDeliveryError writes for an HTTP status is
	// trusted; a status is never extracted from arbitrary text.
	if match := httpFailurePattern.FindStringSubmatch(message); match != nil {
		status, _ := strconv.Atoi(match[1])
		return httpFailureReason(status)
	}
	return SafeDeliveryError(errors.New(message))
}

var httpFailurePattern = regexp.MustCompile(`^notification delivery failed with HTTP ([1-5][0-9]{2})$`)

func httpFailureReason(status int) string {
	return fmt.Sprintf("notification delivery failed with HTTP %d", status)
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
