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
	"strings"
	"time"

	"github.com/nicholas-fedor/shoutrrr"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
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
	if err := ctx.Err(); err != nil {
		return err
	}
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

// Permanent is retained for callers of the previous transport. Shoutrrr
// delivery failures remain retryable until the outbox's 24-hour horizon.
func (e *DeliveryError) Permanent() bool { return false }

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
	message = strings.ReplaceAll(message, rawURL, RedactURL(rawURL))
	if parsed, err := url.Parse(rawURL); err == nil {
		message = strings.ReplaceAll(message, parsed.String(), RedactURL(rawURL))
		if parsed.User != nil {
			message = strings.ReplaceAll(message, parsed.User.String(), "<redacted>")
		}
		if parsed.Host != "" {
			message = strings.ReplaceAll(message, parsed.Host, "<redacted>")
		}
		if parsed.Path != "" && parsed.Path != "/" {
			message = strings.ReplaceAll(message, parsed.Path, "/<redacted>")
			message = strings.ReplaceAll(message, "/hooks"+parsed.Path, "/hooks/<redacted>")
		}
	}
	return truncate(message, 500)
}

func truncate(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n] + "…"
}
