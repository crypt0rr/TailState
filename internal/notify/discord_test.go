package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/discord"

	"github.com/crypt0rr/tailstate/internal/model"
)

// discordDelivery returns the embed title of the first request and every
// body line Discord received, across all webhook requests.
func discordDelivery(t *testing.T, requests []captured) (string, []string) {
	t.Helper()
	title := ""
	var lines []string
	for index, request := range requests {
		var payload struct {
			Embeds []struct {
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"embeds"`
		}
		if err := json.Unmarshal([]byte(request.body), &payload); err != nil {
			t.Fatalf("discord payload: %v", err)
		}
		for embedIndex, embed := range payload.Embeds {
			if index == 0 && embedIndex == 0 {
				title = embed.Title
			}
			lines = append(lines, strings.Split(embed.Description, "\n")...)
		}
	}
	return title, lines
}

// TestDiscordDeliversEveryLineExactlyOnce is the R-046 invariant: a
// notification longer than ten lines reaches Discord with every line exactly
// once and in order, in a single webhook request when it fits the budget,
// and with the title in the embed title instead of a heading line.
// Shoutrrr's default splitlines=yes lost the first lines of such messages
// and repeated later ones.
func TestDiscordDeliversEveryLineExactlyOnce(t *testing.T) {
	lines := make([]Line, 0, 25)
	want := make([]string, 0, 25)
	for i := 1; i <= 25; i++ {
		lines = append(lines, line(lit(fmt.Sprintf("line-%02d", i))))
		want = append(want, fmt.Sprintf("line-%02d", i))
	}
	digest := Message{Icon: "🔔", Title: "Digest", Scope: "example.com", Lines: lines}
	for name, message := range map[string]Message{"25-line digest": digest, "sample digest": sampleDigest()} {
		t.Run(name, func(t *testing.T) {
			prepared := PrepareMessage(message, discordURL, "")
			mock := &mockProviders{}
			if err := senderWithTransport(mock).SendPrepared(context.Background(), discordURL, prepared); err != nil {
				t.Fatalf("send: %v", err)
			}
			requests := mock.all()
			if len(requests) != 1 {
				t.Fatalf("a fitting digest took %d webhook requests", len(requests))
			}
			title, got := discordDelivery(t, requests)
			if title != plainTitle(message) {
				t.Fatalf("embed title=%q", title)
			}
			expected := want
			if name != "25-line digest" {
				expected = strings.Split(prepared.Body, "\n")
			}
			if !slices.Equal(got, expected) {
				t.Fatalf("Discord received\n%q\nwant\n%q", got, expected)
			}
			for _, received := range got {
				if strings.HasPrefix(received, "###") {
					t.Fatalf("duplicate heading in the body: %q", received)
				}
			}
		})
	}
}

// TestDiscordOversizedDigestIsOneRequest covers a digest fitted to the
// Discord budget: it still arrives in one request, ending with the
// shortening note.
func TestDiscordOversizedDigestIsOneRequest(t *testing.T) {
	changes := make([]model.Change, 0, 200)
	for i := 0; i < 200; i++ {
		changes = append(changes, model.Change{Kind: "created", Collector: "devices", Name: fmt.Sprintf("ephemeral-ci-runner-%03d.tail1234.ts.net", i)})
	}
	prepared := PrepareMessage(Context{Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes}), discordURL, "")
	mock := &mockProviders{}
	if err := senderWithTransport(mock).SendPrepared(context.Background(), discordURL, prepared); err != nil {
		t.Fatal(err)
	}
	requests := mock.all()
	_, got := discordDelivery(t, requests)
	// The shortening note precedes the kept context line.
	if len(requests) != 1 || !slices.Equal(got, strings.Split(prepared.Body, "\n")) || !strings.Contains(got[len(got)-3], "Shortened for this destination") || got[len(got)-1] != "5 Oct 2026 12:00 UTC" {
		t.Fatalf("requests=%d last line=%q", len(requests), got[len(got)-1])
	}
}

// TestDiscordSplitLinesParameter covers R-046's operator control: TailState
// sends splitlines=no unless the URL sets it, and a forced splitlines=yes is
// kept but warned about.
func TestDiscordSplitLinesParameter(t *testing.T) {
	if params := parseDestination(discordURL).params(Prepared{}); params == nil || (*params)["splitlines"] != "no" {
		t.Fatalf("default params=%v", params)
	}
	for serviceURL, warn := range map[string]bool{
		discordURL + "?splitlines=yes":           true,
		discordURL + "?SplitLines=Y":             true,
		discordURL + "?splitlines=true&json=yes": false,
		discordURL + "?splitlines=no":            false,
		discordURL + "?splitlines=0":             false,
	} {
		if params := parseDestination(serviceURL).params(Prepared{Title: "title"}); params != nil {
			if _, set := (*params)["splitlines"]; set {
				t.Fatalf("%s: operator splitlines overridden: %v", serviceURL, *params)
			}
		}
		if got := SplitLinesWarning(serviceURL) != ""; got != warn {
			t.Fatalf("%s warning=%t, want %t", serviceURL, got, warn)
		}
	}
	for _, serviceURL := range []string{discordURL, slackURL, "generic://example.com/hook?splitlines=yes"} {
		if warning := SplitLinesWarning(serviceURL); warning != "" {
			t.Fatalf("%s warned: %s", serviceURL, warning)
		}
	}
	if got := CountSplitLinesWarnings([]string{discordURL, discordURL + "?splitlines=yes", slackURL}); got != 1 {
		t.Fatalf("count=%d", got)
	}
	if warning := SplitLinesWarning(discordURL + "?splitlines=yes"); strings.Contains(warning, "token") || strings.Contains(warning, "123456789") {
		t.Fatalf("warning names the URL: %s", warning)
	}
	// An operator's splitlines=yes is passed through to Shoutrrr unchanged.
	mock := &mockProviders{}
	serviceURL := discordURL + "?splitlines=yes"
	if err := senderWithTransport(mock).SendPrepared(context.Background(), serviceURL, PrepareMessage(Context{}.Test(testObservedAt), serviceURL, "")); err != nil {
		t.Fatal(err)
	}
	if _, got := discordDelivery(t, mock.all()); len(got) < 3 {
		t.Fatalf("splitlines=yes did not send one embed per line: %q", got)
	}
}

// TestShoutrrrDiscordSplitLinesStillCorruptsLongMessages pins the upstream
// defect TailState works around. When a Shoutrrr update fixes
// util.MessageItemsFromLines, this test fails: then drop SplitLinesWarning,
// its diagnostics finding, and the note in docs/notifications.md.
func TestShoutrrrDiscordSplitLinesStillCorruptsLongMessages(t *testing.T) {
	lines := make([]string, 0, 25)
	for i := 1; i <= 25; i++ {
		lines = append(lines, fmt.Sprintf("line-%02d", i))
	}
	var got []string
	for _, batch := range discord.CreateItemsFromPlain(strings.Join(lines, "\n"), true) {
		for _, item := range batch {
			got = append(got, item.Text)
		}
	}
	if slices.Equal(got, lines) {
		t.Fatal("Shoutrrr's splitlines=yes now delivers every line once; remove the splitlines warning")
	}
	if !slices.Equal(got[:5], lines[20:25]) || slices.Contains(got, "line-01") {
		t.Fatalf("the upstream corruption changed shape: %q", got)
	}
}

// TestDiscordItemsKeepLinesWhole covers bodies larger than one embed: no line
// is split between embeds unless it is longer than an embed on its own, and
// nothing is lost or repeated.
func TestDiscordItemsKeepLinesWhole(t *testing.T) {
	var lines []string
	for i := 0; i < 120; i++ {
		lines = append(lines, fmt.Sprintf("🔴 ✏️ change line %03d %s", i, strings.Repeat("x", i%40)))
	}
	items := discordItems("\n" + strings.Join(lines, "\n") + "\n\n")
	if len(items) < 2 || len(items) > discord.ChunkCount {
		t.Fatalf("items=%d", len(items))
	}
	var got []string
	for _, item := range items {
		if utf8.RuneCountInString(item.Text) > discordEmbedRunes || strings.HasPrefix(item.Text, "\n") || strings.HasSuffix(item.Text, "\n") {
			t.Fatalf("embed of %d runes or with edge blank lines", utf8.RuneCountInString(item.Text))
		}
		got = append(got, strings.Split(item.Text, "\n")...)
	}
	if !slices.Equal(got, lines) {
		t.Fatalf("lines changed:\n%q", got)
	}
	long := strings.Repeat("é", discordEmbedRunes*2+5)
	items = discordItems("head\n" + long + "\ntail")
	// The rest of an over-long line shares an embed with the next line.
	if len(items) != 4 || items[0].Text != "head" || items[1].Text+items[2].Text+items[3].Text != long+"\ntail" {
		t.Fatalf("long line partition: %d items", len(items))
	}
	if items := discordItems("\n\n"); len(items) != 1 || items[0].Text != "\n\n" {
		t.Fatalf("blank body items=%+v", items)
	}
}

// TestDiscordSendTimesOutAndRejectsInvalidURLs covers the direct Discord
// sender's deadline and construction errors.
func TestDiscordSendTimesOutAndRejectsInvalidURLs(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	blocking := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		<-release
		return nil, context.Canceled
	})
	sender := senderWithTransport(blocking)
	sender.timeout = 20 * time.Millisecond
	err := sender.Send(context.Background(), discordURL, "message")
	if err == nil || SafeDeliveryError(err) != "notification delivery timed out" {
		t.Fatalf("err=%v safe=%q", err, SafeDeliveryError(err))
	}
	if err := Validate("discord://@"); err == nil {
		t.Fatal("invalid Discord URL accepted")
	}
}
