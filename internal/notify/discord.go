package notify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/discord"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// discordEmbedRunes is the largest embed description TailState sends,
// matching Shoutrrr's Discord chunk size. Discord allows 4,096 characters
// per description and 6,000 per message; the message budget (see
// serviceMessageLimits) keeps the whole message within the latter.
const discordEmbedRunes = discord.ChunkSize

// errDiscordTimeout reports a Discord send that did not finish within the
// sender's deadline, like the Shoutrrr router's service timeout.
var errDiscordTimeout = errors.New("discord: service send timeout")

// discordSender sends to a directly constructed Shoutrrr Discord service.
//
// By default the body is sent as embeds of whole lines that TailState
// partitions itself, all in one webhook request. Shoutrrr's own partitioning
// either splits a line between two embeds at the nearest space
// (splitlines=no) or, with its default splitlines=yes, loses and repeats
// lines of messages longer than ten lines (see serviceDefaults). An operator
// who set splitlines in the URL keeps Shoutrrr's behaviour, and JSON mode
// sends the body as is.
type discordSender struct {
	service *discord.Service
	timeout time.Duration
	items   bool
}

func newDiscordSender(parsed *url.URL, client *http.Client, timeout time.Duration) (messageSender, error) {
	service := &discord.Service{}
	service.SetHTTPClient(client)
	if err := service.Initialize(parsed, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", discord.Scheme, err)
	}
	destination := parseDestination(parsed.String())
	_, operatorSplitLines := destination.query[paramSplitLines]
	items := !operatorSplitLines && !service.Config.JSON
	return discordSender{service: service, timeout: timeout, items: items}, nil
}

func (d discordSender) Send(message string, params *types.Params) []error {
	result := make(chan error, 1)
	go func() {
		if d.items {
			result <- d.service.SendItems(discordItems(message), params)
			return
		}
		result <- d.service.Send(message, params)
	}()
	select {
	case err := <-result:
		return []error{err}
	case <-time.After(d.timeout):
		return []error{errDiscordTimeout}
	}
}

// discordItems partitions body into embeds of whole lines, each at most
// discordEmbedRunes long, in order. A single longer line is split at a rune
// boundary. Blank lines at the edge of an embed are dropped because Discord
// rejects an empty description.
func discordItems(body string) []types.MessageItem {
	chunks := partitionLines(body, discordEmbedRunes)
	items := make([]types.MessageItem, 0, len(chunks))
	for _, chunk := range chunks {
		items = append(items, types.MessageItem{Text: chunk})
	}
	return items
}
