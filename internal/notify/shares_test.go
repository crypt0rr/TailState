package notify

import (
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/model"
)

// shareInvite returns one invite in the shape of Tailscale's DeviceInvite
// (GET /api/v2/device/{id}/device-invites). The values are illustrative.
func shareInvite(id, login string) map[string]any {
	invite := map[string]any{
		"id":              id,
		"created":         "2026-05-29T18:27:54.581818425Z",
		"tailnetId":       "T1000EXAMPLE",
		"deviceId":        "654495373136127",
		"sharerId":        "u1000EXAMPLE",
		"multiUse":        false,
		"allowExitNode":   false,
		"email":           "",
		"lastEmailSentAt": "2026-05-29T18:27:55Z",
		"inviteUrl":       "https://login.tailscale.com/admin/invite/example-" + id,
		"accepted":        login != "",
	}
	if login != "" {
		invite["acceptedBy"] = map[string]any{"id": float64(1250252329925020), "loginName": login, "profilePicUrl": "https://avatars.example.com/a.png"}
	}
	return invite
}

// with returns a copy of invite with the given fields replaced.
func with(invite map[string]any, fields ...any) map[string]any {
	out := make(map[string]any, len(invite))
	for key, value := range invite {
		out[key] = value
	}
	for index := 0; index+1 < len(fields); index += 2 {
		out[fields[index].(string)] = fields[index+1]
	}
	return out
}

// shareChange records a device_details change the way the store does: the
// keyed diff of the canonical snapshots, with the invites for context.
func shareChange(t *testing.T, device string, before, after []map[string]any) model.Change {
	t.Helper()
	canonical := func(invites []map[string]any) []byte {
		list := make([]any, len(invites))
		for index, invite := range invites {
			list[index] = invite
		}
		raw, _, err := model.CanonicalFor("device_details", map[string]any{"deviceInvites": list, "postureAttributes": map[string]any{"attributes": map[string]any{}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	oldRaw, newRaw := canonical(before), canonical(after)
	diff := model.DiffDetailedFor("device_details", oldRaw, newRaw)
	return model.Change{Kind: "changed", Collector: "device_details", ResourceID: device, Type: "device_details", Name: device + ".tail1234.ts.net", Fields: diff.Fields, FieldsTruncated: diff.FieldsTruncated, TotalFields: diff.TotalFields, Invites: model.DeviceInvites(oldRaw, newRaw)}
}

// The real case behind R-049 and E-038: two devices, each shared with the
// same user through one invite accepted months earlier, whose invites change
// only an identifier.
const realShareUser = "octo-user@github"

func realShareDigest(t *testing.T, field string) Message {
	t.Helper()
	ludus, spraakwater := shareInvite("5861427050514914", realShareUser), shareInvite("5861427050519876", realShareUser)
	changes := []model.Change{
		shareChange(t, "ludus", []map[string]any{ludus}, []map[string]any{with(ludus, field, "T2000EXAMPLE")}),
		shareChange(t, "spraakwater", []map[string]any{spraakwater}, []map[string]any{with(spraakwater, field, "T2000EXAMPLE")}),
	}
	return Context{Label: "prod", Tailnet: "example.com"}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes})
}

// TestIdentifierOnlyShareChangesAreOneLowLine is E-038's second acceptance
// criterion on the real digest: an identifier-only change on two accepted
// shares is low severity and one grouped line, not two JSON blobs.
func TestIdentifierOnlyShareChangesAreOneLowLine(t *testing.T) {
	for _, field := range []string{"tailnetId", "sharerId"} {
		message := realShareDigest(t, field)
		golden := map[string]string{
			FormatPlain: "⚪ 2 Tailscale changes · prod (example.com)\n" +
				"2 changed · ⚪ 2 low\n" +
				"\n" +
				"⚪ 🔗 2 device shares with octo-user@github (ludus, spraakwater): " + field + " changed\n" +
				"\n" +
				"5 Oct 2026 12:00 UTC",
			FormatMarkdown: "### ⚪ 2 Tailscale changes · prod (example.com)\n" +
				"2 changed · ⚪ 2 low\n" +
				"\n" +
				"⚪ 🔗 2 device shares with octo-user@github (ludus, spraakwater): `" + field + "` changed\n" +
				"\n" +
				"5 Oct 2026 12:00 UTC",
		}
		for format, want := range golden {
			if got := Render(message, format); got != want {
				t.Fatalf("%s %s rendering mismatch\n got: %q\nwant: %q", field, format, got, want)
			}
		}
		if message.Severity != string(model.SeverityLow) {
			t.Fatalf("%s change severity = %s", field, message.Severity)
		}
	}
}

// shareGoldenDigest covers every share transition E-038 phrases: created
// (invite link and e-mail), accepted, removed, exit node enabled, e-mail
// resent, and an identifier change on two accepted shares.
func shareGoldenDigest(t *testing.T) Message {
	t.Helper()
	accepted := shareInvite("5861427050514914", "alice@example.com")
	pending := shareInvite("7000000000000001", "")
	emailed := with(shareInvite("7000000000000002", ""), "email", "carol@example.com")
	second := shareInvite("5861427050519876", "alice@example.com")
	changes := []model.Change{
		shareChange(t, "nas", nil, []map[string]any{with(pending, "multiUse", true, "allowExitNode", true)}),
		shareChange(t, "printer", nil, []map[string]any{emailed}),
		shareChange(t, "build-01", []map[string]any{pending}, []map[string]any{with(pending, "accepted", true, "acceptedBy", map[string]any{"id": float64(9), "loginName": "bob@example.com"})}),
		shareChange(t, "camera", []map[string]any{accepted}, nil),
		shareChange(t, "gateway", []map[string]any{accepted}, []map[string]any{with(accepted, "allowExitNode", true)}),
		shareChange(t, "kiosk", []map[string]any{emailed}, []map[string]any{with(emailed, "lastEmailSentAt", "2026-10-01T08:00:00Z")}),
		shareChange(t, "ludus", []map[string]any{accepted}, []map[string]any{with(accepted, "tailnetId", "T2000EXAMPLE")}),
		shareChange(t, "spraakwater", []map[string]any{second}, []map[string]any{with(second, "tailnetId", "T2000EXAMPLE")}),
	}
	return Context{Label: "prod", Tailnet: "example.com", PublicURL: "https://tailstate.example"}.Digest(DigestInput{BatchID: 7, ObservedAt: testObservedAt, Changes: changes})
}

// TestDeviceShareLinesAreGolden is E-038's golden test in every format.
func TestDeviceShareLinesAreGolden(t *testing.T) {
	lines := []string{
		"🔴 🔗 *build-01* share accepted by bob@example.com",
		"🔴 🔗 *gateway* share with alice@example.com: exit node allowed",
		"🔴 🔗 *nas* shared via a new invite link (multi-use, exit node allowed)",
		"🟠 🔗 *camera* share with alice@example.com removed",
		"🟠 🔗 *printer* shared via a new invite to carol@example.com",
		"⚪ 🔗 2 device shares with alice@example.com (ludus, spraakwater): `tailnetId` changed",
		"⚪ 🔗 *kiosk* share with carol@example.com: invite e-mail resent",
	}
	// render writes the share lines with a format's bold and code markers.
	render := func(open, close, codeOpen, codeClose string) string {
		replacer := strings.NewReplacer("*", "\x00", "`", "\x01")
		out := make([]string, len(lines))
		for index, current := range lines {
			current = replacer.Replace(current)
			for _, marker := range []struct{ token, open, close string }{{"\x00", open, close}, {"\x01", codeOpen, codeClose}} {
				for strings.Contains(current, marker.token) {
					current = strings.Replace(current, marker.token, marker.open, 1)
					current = strings.Replace(current, marker.token, marker.close, 1)
				}
			}
			out[index] = current
		}
		return strings.Join(out, "\n")
	}
	const counts = "8 changed · 🔴 3 high, 🟠 2 medium, ⚪ 3 low\n\n"
	golden := map[string]string{
		FormatMarkdown: "### 🔴 8 Tailscale changes (3 high) · prod (example.com)\n" + counts + render("**", "**", "`", "`") +
			"\n\n5 Oct 2026 12:00 UTC · [Batch 7 in History](https://tailstate.example/history?batch=7)",
		FormatSlack: "*🔴 8 Tailscale changes (3 high) · prod (example.com)*\n" + counts + render("*", "*", "`", "`") +
			"\n\n5 Oct 2026 12:00 UTC · <https://tailstate.example/history?batch=7|Batch 7 in History>",
		FormatPlain: "🔴 8 Tailscale changes (3 high) · prod (example.com)\n" + counts + render("", "", "", "") +
			"\n\n5 Oct 2026 12:00 UTC · Batch 7 in History: https://tailstate.example/history?batch=7",
		FormatTeams: "**🔴 8 Tailscale changes (3 high) · prod (example.com)**\n" + counts + render("**", "**", "", "") +
			"\n\n5 Oct 2026 12:00 UTC · [Batch 7 in History](https://tailstate.example/history?batch=7)",
		FormatHTML: "<b>🔴 8 Tailscale changes (3 high) · prod (example.com)</b>\n" + counts + render("<b>", "</b>", "<code>", "</code>") +
			"\n\n5 Oct 2026 12:00 UTC · <a href=\"https://tailstate.example/history?batch=7\">Batch 7 in History</a>",
	}
	message := shareGoldenDigest(t)
	for _, format := range Formats {
		if got := Render(message, format); got != golden[format] {
			t.Fatalf("%s rendering mismatch\n got: %q\nwant: %q", format, got, golden[format])
		}
	}
	if strings.Contains(Render(message, FormatPlain), "{") {
		t.Fatal("a share change was rendered as JSON")
	}
}

// TestShareAcceptanceIsHighSeverity is E-038's invariant: a share accepted
// by a user (accepted false→true, or acceptedBy set to another user) is high
// severity, and its line names that user, also when the invite list was
// recorded as one whole-list field by an earlier release.
func TestShareAcceptanceIsHighSeverity(t *testing.T) {
	pending := shareInvite("7000000000000001", "")
	acceptedBy := map[string]any{"id": float64(9), "loginName": "mallory@example.net"}
	keyed := shareChange(t, "build-01", []map[string]any{pending}, []map[string]any{with(pending, "accepted", true, "acceptedBy", acceptedBy)})
	legacy := model.Change{Kind: "changed", Collector: "device_details", Name: "build-01", Fields: []model.FieldChange{{
		Field: "deviceInvites", OldPresent: true, NewPresent: true,
		Old: []any{map[string]any{"id": "7000000000000001", "accepted": false}},
		New: []any{map[string]any{"id": "7000000000000001", "accepted": true, "acceptedBy": acceptedBy}},
	}}}
	accepted := shareInvite("5861427050514914", "alice@example.com")
	reassigned := shareChange(t, "build-01", []map[string]any{accepted}, []map[string]any{with(accepted, "acceptedBy", acceptedBy)})
	for name, change := range map[string]model.Change{"keyed": keyed, "legacy": legacy, "reassigned": reassigned} {
		if severity := model.Classify(change); severity != model.SeverityHigh {
			t.Fatalf("%s acceptance severity = %s", name, severity)
		}
		got := Render(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: []model.Change{change}}), FormatPlain)
		if !strings.Contains(got, "🔴 🔗 build-01 share") || !strings.Contains(got, "mallory@example.net") {
			t.Fatalf("%s acceptance is not a high line naming the user:\n%s", name, got)
		}
	}
}

// TestShareLinesDescribeEveryTransition covers the remaining phrasing:
// actors, long device lists, invite links, invites without a snapshot,
// switched-off flags, and other device detail fields kept on the device.
func TestShareLinesDescribeEveryTransition(t *testing.T) {
	accepted := shareInvite("5861427050514914", "alice@example.com")
	link := shareInvite("7000000000000001", "")
	flagged := with(accepted, "multiUse", true, "allowExitNode", true)
	actor := &model.Attribution{ActorLogin: "admin@example.com"}
	var changes []model.Change
	for _, device := range []string{"d1", "d2", "d3", "d4"} {
		change := shareChange(t, device, []map[string]any{link}, []map[string]any{with(link, "lastEmailSentAt", "2026-10-01T00:00:00Z")})
		change.Attribution = actor
		changes = append(changes, change)
	}
	posture := shareChange(t, "gw", []map[string]any{flagged}, []map[string]any{with(accepted, "inviteUrl", "https://login.tailscale.com/admin/invite/example-new")})
	posture.Fields = append(posture.Fields, set("postureAttributes.custom:tier", "a", "b"))
	acceptedWithEmail := with(link, "accepted", true, "acceptedBy", map[string]any{"id": float64(5), "loginName": "dave@example.com"}, "allowExitNode", true, "email", "dave@example.com")
	changes = append(changes,
		posture,
		shareChange(t, "lab", []map[string]any{flagged}, nil),
		shareChange(t, "lab2", []map[string]any{link}, []map[string]any{acceptedWithEmail}),
		shareChange(t, "lab3", []map[string]any{accepted}, []map[string]any{with(accepted, "accepted", false)}),
		shareChange(t, "lab4", []map[string]any{accepted}, []map[string]any{with(accepted, "acceptedBy", map[string]any{"id": float64(5), "loginName": "erin@example.com"})}),
		model.Change{Kind: "changed", Collector: "device_details", Name: "bare", Fields: []model.FieldChange{
			{Field: "deviceInvites[9]", New: "{\"accepted\":false…", NewPresent: true},
			{Field: "deviceInvites[8]", Old: "{\"accepted\":true…", OldPresent: true},
			set("deviceInvites[7].tailnetId", "a", "b"),
			set("deviceInvites[6].accepted", false, true),
		}},
		model.Change{Kind: "changed", Collector: "device_details", Name: "cut", FieldsTruncated: true, TotalFields: 30, Fields: []model.FieldChange{set("deviceInvites[5].multiUse", false, true)}},
	)
	got := Render(Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes, Attributed: true}), FormatPlain)
	for _, want := range []string{
		"⚪ 🔗 4 device shares by invite link (d1, d2, d3 and 1 more): invite e-mail resent · by admin@example.com",
		"🟠 🔗 gw share with alice@example.com: exit node no longer allowed, invite link changed, multi-use disabled\n",
		"🟠 ✏️ gw (device) changed\n  • postureAttributes.custom:tier: a → b",
		"🟠 🔗 lab share with alice@example.com removed (multi-use, exit node allowed)",
		"🔴 🔗 lab2 share accepted by dave@example.com (exit node allowed); email (empty) → dave@example.com",
		"🟠 🔗 lab3 share with alice@example.com: no longer accepted",
		"🔴 🔗 lab4 share now accepted by erin@example.com\n",
		"🟠 🔗 bare shared via a new invite 9",
		"🟠 🔗 bare share 8 removed",
		"⚪ 🔗 bare share 7: tailnetId changed",
		"🔴 🔗 bare share accepted (invite 6)",
		"🟠 🔗 cut share 5: multi-use enabled",
		"🟠 ✏️ cut (device) changed\n  Additional field changes omitted; total: 30.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("digest lacks %q:\n%s", want, got)
		}
	}
}

// TestShareRecipientsAreEscaped keeps injection safety for share lines:
// recipients and device names are tenant values in every format.
func TestShareRecipientsAreEscaped(t *testing.T) {
	hostile := `[x](https://evil.example) <b>*bold*</b> <!channel>`
	accepted := shareInvite("5861427050514914", hostile)
	second := shareInvite("5861427050519876", hostile)
	pending := shareInvite("7000000000000001", "")
	changes := []model.Change{
		shareChange(t, hostile, []map[string]any{accepted}, []map[string]any{with(accepted, "tailnetId", "T2")}),
		shareChange(t, "nas", []map[string]any{second}, []map[string]any{with(second, "tailnetId", "T2")}),
		shareChange(t, "printer", []map[string]any{pending}, []map[string]any{with(pending, "accepted", true, "acceptedBy", map[string]any{"id": float64(1), "loginName": hostile})}),
	}
	message := Context{}.Digest(DigestInput{ObservedAt: testObservedAt, Changes: changes})
	want := map[string]string{
		FormatMarkdown: `\[x\](https://evil.example) \<b>\*bold\*\</b> \<!channel>`,
		FormatSlack:    "[x](https://evil.example) &lt;b&gt;∗bold∗&lt;/b&gt; &lt;!channel&gt;",
		FormatHTML:     "[x](https://evil.example) &lt;b&gt;*bold*&lt;/b&gt; &lt;!channel&gt;",
		FormatTeams:    "[x］(https://evil.example) <b>∗bold∗</b> <!channel>",
	}
	for format, escaped := range want {
		got := Render(message, format)
		// The acceptor, the grouped recipient, and the grouped device name.
		if strings.Count(got, escaped) != 3 || strings.Contains(got, hostile) {
			t.Fatalf("%s: recipient not escaped as %q on every share line:\n%s", format, escaped, got)
		}
	}
}
