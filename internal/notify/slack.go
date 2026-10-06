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
	if config.Color != "" {
		payload.Attachments = []slackAttachment{{Color: config.Color, Blocks: blocks}}
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

// slackWebhookResult accepts "ok", or an empty 200 response, like Shoutrrr.
func slackWebhookResult(status int, raw []byte) error {
	body := string(raw)
	if body == "ok" || (body == "" && status == http.StatusOK) {
		return nil
	}
	return fmt.Errorf("%w: HTTP %d: %s", errSlackRejected, status, truncate(stripControl(body), 200))
}

// slackAPIResult requires a successful status and {"ok": true}, like
// Shoutrrr's API client.
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
		return fmt.Errorf("%w: %s", errSlackRejected, truncate(stripControl(result.Error), 100))
	}
	return nil
}
