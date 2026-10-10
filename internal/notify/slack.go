package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/slack"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Slack Block Kit limits.
const (
	slackSectionRunes = 3000 // characters per section text
	slackHeaderRunes  = 150  // characters per header text
	slackMaxBlocks    = 50   // blocks per message
	slackResponseMax  = 64 << 10
)

// slackAPIPostMessage is the Web API endpoint Shoutrrr uses for bot and user
// tokens.
const slackAPIPostMessage = "https://slack.com/api/chat.postMessage"

// slackIconURL recognises an icon given as a URL, as Shoutrrr does.
var slackIconURL = regexp.MustCompile(`https?://`)

type slackText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type slackBlock struct {
	Type string    `json:"type"`
	Text slackText `json:"text"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks"`
}

// slackPayload is a chat.postMessage / incoming-webhook message: a short
// top-level text (the notification and fallback text) and the body as Block
// Kit sections. An operator colour wraps the blocks in one attachment.
type slackPayload struct {
	Text        string            `json:"text"`
	Blocks      []slackBlock      `json:"blocks,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	ThreadTS    string            `json:"thread_ts,omitempty"`
}

// slackPayloadFor builds the native Slack message for a prepared
// notification and a destination parsed by Shoutrrr's own Slack URL parser.
//
// Shoutrrr's Slack service sends every line as its own legacy attachment
// with an empty top-level text; this payload is one message instead. A body
// rendered as Slack mrkdwn stays mrkdwn (tenant values already have &, <, and
// > escaped and cannot mention or link). Any other body (an explicit Markdown
// or plain override, or a legacy pre-rendered row) is not escaped for Slack,
// so it is sent as plain_text sections, which Slack never parses for
// mentions or links.
func slackPayloadFor(message Prepared, config *slack.Config) slackPayload {
	payload := slackPayload{Username: config.BotName, ThreadTS: config.ThreadTS}
	if config.Channel != "webhook" {
		payload.Channel = config.Channel
	}
	if config.Icon != "" {
		if slackIconURL.MatchString(config.Icon) {
			payload.IconURL = config.Icon
		} else {
			payload.IconEmoji = config.Icon
		}
	}
	body := message.Message()
	var blocks []slackBlock
	switch {
	case message.Title != "":
		// TailState's title: a header block, and the summary for push
		// previews.
		payload.Text = escapeSlack(message.Title, false)
		blocks = append(blocks, slackBlock{Type: "header", Text: slackText{Type: "plain_text", Text: truncateRunes(message.Title, slackHeaderRunes), Emoji: true}})
	case config.Title != "":
		// An operator title from the URL is used as given, as Shoutrrr does.
		payload.Text = config.Title
	default:
		// A legacy pre-rendered row: its first line is the summary.
		first, _, _ := strings.Cut(body, "\n")
		payload.Text = escapeSlack(truncateRunes(strings.TrimSpace(strings.TrimPrefix(first, "### ")), slackHeaderRunes), false)
	}
	textType := "plain_text"
	if message.Format == FormatSlack {
		textType = "mrkdwn"
	}
	for _, chunk := range partitionLines(body, slackSectionRunes) {
		if len(blocks) == slackMaxBlocks {
			break
		}
		blocks = append(blocks, slackBlock{Type: "section", Text: slackText{Type: textType, Text: chunk}})
	}
	// An operator colour from the URL wins over the severity's colour; a
	// legacy row without a severity has neither.
	color := config.Color
	if color == "" {
		color = severityParams["slack"][paramColor][model.Severity(message.Severity)]
	}
	if color != "" {
		payload.Attachments = []slackAttachment{{Color: color, Blocks: blocks}}
	} else {
		payload.Blocks = blocks
	}
	return payload
}

// sendSlack delivers a prepared notification to a slack:// destination
// through TailState's bounded, redirect-rejecting client, replacing
// Shoutrrr's per-line attachments. Webhook and token URLs are parsed by
// Shoutrrr's Slack config, so both forms keep their meaning; responses are
// checked as Shoutrrr checks them.
func (s *SenderImpl) sendSlack(ctx context.Context, parsed *url.URL, message Prepared, client *http.Client) error {
	config, err := slack.CreateConfigFromURL(parsed)
	if err != nil {
		return fmt.Errorf("%s: %w", slack.Scheme, err)
	}
	encoded, err := json.Marshal(slackPayloadFor(message, config))
	if err != nil {
		return fmt.Errorf("%s: encode message: %w", slack.Scheme, err)
	}
	// Like Shoutrrr's router, the request is bounded by the send timeout
	// only: once started, a send is not abandoned by a shutdown, because the
	// provider may already have accepted it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()
	target := config.Token.WebhookURL()
	if config.Token.IsAPIToken() {
		target = slackAPIPostMessage
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("%s: create request: %w", slack.Scheme, err)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	if config.Token.IsAPIToken() {
		request.Header.Set("Authorization", config.Token.Authorization())
	}
	response, err := client.Do(request)
	if err != nil {
		// The request URL of a webhook is its credential; keep only the
		// cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("%s: post message: %w", slack.Scheme, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, slackResponseMax))
	if err != nil {
		return fmt.Errorf("%s: read response: %w", slack.Scheme, err)
	}
	if config.Token.IsAPIToken() {
		return slackAPIResult(response.StatusCode, raw)
	}
	return slackWebhookResult(response.StatusCode, raw)
}

var errSlackRejected = errors.New("slack: message rejected")

// slackRejectedReason is the persisted reason for a Slack error code that no
// retry can fix; a code TailState knows is named in parentheses.
const slackRejectedReason = "notification rejected by Slack"

// slackRetryableErrors are the Slack error codes for temporary server-side
// failures, which are retried. Every other code is permanent.
var slackRetryableErrors = map[string]bool{"ratelimited": true, "rate_limited": true, "internal_error": true, "fatal_error": true, "service_unavailable": true, "request_timeout": true}

// slackErrorReasons maps the permanent Slack error codes TailState names to
// their persisted reasons. Reasons are built only from this list, never from
// response text.
var slackErrorReasons = func() map[string]string {
	reasons := map[string]string{"msg_too_long": messageTooLargeReason}
	for _, code := range []string{
		"invalid_auth", "not_authed", "account_inactive", "token_revoked", "token_expired", "no_permission", "missing_scope",
		"not_allowed_token_type", "team_access_not_granted", "ekm_access_denied", "invalid_token",
		"channel_not_found", "not_in_channel", "is_archived", "channel_is_archived", "restricted_action", "action_prohibited",
		"posting_to_general_channel_denied", "user_not_found", "no_service", "no_service_id", "no_team", "team_disabled",
		"invalid_blocks", "invalid_blocks_format", "invalid_attachments", "too_many_attachments", "invalid_arguments", "invalid_payload", "no_text",
	} {
		reasons[code] = slackRejectedReason + " (" + code + ")"
	}
	return reasons
}()

// slackReason reports whether reason is one SafeDeliveryError may persist
// for a Slack error.
func slackReason(reason string) bool {
	if reason == slackRejectedReason {
		return true
	}
	for _, known := range slackErrorReasons {
		if reason == known {
			return true
		}
	}
	return false
}

// slackError classifies a Slack error code. A temporary failure is a plain,
// retryable error. Any other code is a permanent DeliveryError with a fixed
// reason, except that an unknown code stays retryable unless
// unknownPermanent is set: a Web API response is always Slack's own JSON,
// but a webhook body may come from something in between.
func slackError(code string, unknownPermanent bool) error {
	code = strings.TrimSpace(code)
	err := fmt.Errorf("%w: %s", errSlackRejected, truncate(stripControl(code), 100))
	reason, known := slackErrorReasons[code]
	if slackRetryableErrors[code] || (!known && !unknownPermanent) {
		return err
	}
	if !known {
		reason = slackRejectedReason
	}
	return &DeliveryError{Message: err.Error(), Permanent: true, Reason: reason}
}

// slackWebhookResult accepts "ok", or an empty 200 response, like Shoutrrr.
// A known error code in a 200 response is classified like an API error;
// other statuses are classified by SendPrepared (for example 410 for an
// archived channel).
func slackWebhookResult(status int, raw []byte) error {
	body := string(raw)
	if body == "ok" || (body == "" && status == http.StatusOK) {
		return nil
	}
	if status == http.StatusOK {
		return slackError(body, false)
	}
	return fmt.Errorf("%w: HTTP %d: %s", errSlackRejected, status, truncate(stripControl(body), 200))
}

// slackAPIResult requires a successful status and {"ok": true}, like
// Shoutrrr's API client. An {"ok": false} error is classified by its code
// (see slackError).
func slackAPIResult(status int, raw []byte) error {
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("%w: HTTP %d", errSlackRejected, status)
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("%w: invalid API response", errSlackRejected)
	}
	if !result.OK {
		return slackError(result.Error, true)
	}
	return nil
}
