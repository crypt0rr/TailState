package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/crypt0rr/tailstate/internal/model"
)

// Device shares. A device's share invites are described by their recipient
// and flags instead of as raw invite fields: "ludus share accepted by
// alice@example.com", "ludus shared via a new invite link (multi-use)". The
// same bookkeeping transition (an e-mail resend, identifier churn) on
// several shares with the same recipient is one line, "2 device shares with
// alice@example.com (ludus, spraakwater): `tailnetId` changed". History, the
// API, and evidence packs keep the recorded invite fields.

// shareIcon marks device-share lines.
const shareIcon = "🔗"

// maxShareDevices bounds the device names listed on a grouped share line.
const maxShareDevices = 3

// shareLine is one device-share line of a digest.
type shareLine struct {
	severity model.Severity
	line     Line
	// changes are the indices of the described changes in the digest input.
	changes []int
	// sortKey orders share lines: grouped lines first, then by device.
	sortKey string
}

// shareItem is one invite transition of one listed change.
type shareItem struct {
	change     int
	device     string
	transition model.ShareTransition
}

// shareLines describes the share invite fields of the batch's changed
// device_details resources and marks those fields in removed, so the
// resources are listed only with their other fields.
func shareLines(in DigestInput, removed map[fieldRef]bool) []shareLine {
	var items []shareItem
	for changeIndex, change := range in.Changes {
		if change.Collector != "device_details" || change.Kind != "changed" {
			continue
		}
		transitions, others := model.ShareTransitions(change)
		if len(transitions) == 0 {
			continue
		}
		other := map[int]bool{}
		for _, fieldIndex := range others {
			other[fieldIndex] = true
		}
		for fieldIndex := range change.Fields {
			if !other[fieldIndex] {
				removed[fieldRef{changeIndex, fieldIndex}] = true
			}
		}
		device := displayName(change.Collector, change.Name)
		for _, transition := range transitions {
			items = append(items, shareItem{change: changeIndex, device: device, transition: transition})
		}
	}

	// Identical bookkeeping on two or more shares with the same recipient
	// is one line.
	groups := map[string][]int{}
	var order []string
	for index, item := range items {
		if !item.transition.Bookkeeping() {
			continue
		}
		key := recipientKey(item.transition) + "\x00" + strings.Join(bookkeepingText(item.transition.Fields), "\x00")
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], index)
	}
	grouped := map[int]bool{}
	var lines []shareLine
	for _, key := range order {
		indices := groups[key]
		if len(indices) < 2 {
			continue
		}
		members := make([]shareItem, len(indices))
		for position, index := range indices {
			members[position] = items[index]
			grouped[index] = true
		}
		lines = append(lines, groupedShareLine(members))
	}
	for index, item := range items {
		if !grouped[index] {
			lines = append(lines, singleShareLine(item))
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].sortKey < lines[j].sortKey })
	return lines
}

// recipientKey identifies a share's recipient for grouping.
func recipientKey(transition model.ShareTransition) string {
	if !transition.InviteKnown {
		return "?"
	}
	return "=" + transition.Invite.Recipient
}

// bookkeepingText is the sorted descriptions of bookkeeping fields, the
// grouping key of a bookkeeping transition.
func bookkeepingText(fields []model.FieldChange) []string {
	var out []string
	for _, field := range fields {
		if model.ShareFieldName(field.Field) == model.ShareFieldResent {
			out = append(out, "resent")
		} else {
			out = append(out, field.Field)
		}
	}
	sort.Strings(out)
	return out
}

// groupedShareLine is "⚪ 🔗 2 device shares with alice@example.com (ludus,
// spraakwater): `tailnetId` changed".
func groupedShareLine(members []shareItem) shareLine {
	transition := members[0].transition
	severity := model.SeverityLow
	var changes []int
	devices := map[string]bool{}
	var names []string
	for _, member := range members {
		if current := member.transition.Severity(); current.Rank() > severity.Rank() {
			severity = current
		}
		if len(changes) == 0 || changes[len(changes)-1] != member.change {
			changes = append(changes, member.change)
		}
		if !devices[member.device] {
			devices[member.device] = true
			names = append(names, member.device)
		}
	}
	sort.Strings(names)
	spans := []Span{lit(severityIcons[severity] + " " + shareIcon + " " + plural(len(members), "device share", "device shares"))}
	switch {
	case !transition.InviteKnown:
	case transition.Invite.Recipient == "":
		spans = append(spans, lit(" by invite link"))
	default:
		spans = append(spans, lit(" with "), txt(transition.Invite.Recipient))
	}
	spans = append(spans, lit(" ("))
	for index, name := range names {
		if index == maxShareDevices {
			spans = append(spans, lit(fmt.Sprintf(" and %d more", len(names)-index)))
			break
		}
		if index > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, txt(name))
	}
	spans = append(spans, lit("): "))
	spans = append(spans, shareFieldSpans(transition, transition.Fields)...)
	return shareLine{severity: severity, line: line(spans...), changes: changes, sortKey: "0" + names[0]}
}

// singleShareLine describes one invite transition on its device.
func singleShareLine(item shareItem) shareLine {
	transition := item.transition
	severity := transition.Severity()
	spans := []Span{lit(severityIcons[severity] + " " + shareIcon + " "), bold(item.device)}
	invite := transition.Invite
	switch transition.Kind {
	case model.ShareCreated:
		spans = append(spans, lit(" shared via a new invite"))
		switch {
		case !transition.InviteKnown:
			spans = append(spans, lit(" "), code(transition.ID))
		case invite.Recipient == "":
			spans = append(spans, lit(" link"))
		case invite.Accepted:
			spans = append(spans, lit(", accepted by "), txt(invite.Recipient))
		default:
			spans = append(spans, lit(" to "), txt(invite.Recipient))
		}
		spans = append(spans, shareFlags(transition)...)
	case model.ShareRemoved:
		spans = append(spans, shareSubject(transition)...)
		spans = append(spans, lit(" removed"))
		spans = append(spans, shareFlags(transition)...)
	default:
		reassigned := acceptorChanged(transition)
		if transition.ShareAccepted() || reassigned {
			if reassigned && !transition.ShareAccepted() {
				spans = append(spans, lit(" share now accepted"))
			} else {
				spans = append(spans, lit(" share accepted"))
			}
			if transition.InviteKnown && invite.Recipient != "" {
				spans = append(spans, lit(" by "), txt(invite.Recipient))
			} else {
				spans = append(spans, lit(" (invite "), code(transition.ID), lit(")"))
			}
			spans = append(spans, shareFlags(transition)...)
			if rest := shareFieldSpans(transition, acceptanceRest(transition)); len(rest) > 0 {
				spans = append(spans, lit("; "))
				spans = append(spans, rest...)
			}
			break
		}
		spans = append(spans, shareSubject(transition)...)
		spans = append(spans, lit(": "))
		spans = append(spans, shareFieldSpans(transition, transition.Fields)...)
	}
	return shareLine{severity: severity, line: line(spans...), changes: []int{item.change}, sortKey: "1" + item.device + "\x00" + transition.ID}
}

// shareSubject names a share on its device: " share with
// alice@example.com", " invite-link share", or " share `<invite id>`" when
// the invite is not known.
func shareSubject(transition model.ShareTransition) []Span {
	switch {
	case !transition.InviteKnown:
		return []Span{lit(" share "), code(transition.ID)}
	case transition.Invite.Recipient == "":
		return []Span{lit(" invite-link share")}
	}
	return []Span{lit(" share with "), txt(transition.Invite.Recipient)}
}

// shareFlags is " (multi-use, exit node allowed)" for a share with those
// flags, or nothing.
func shareFlags(transition model.ShareTransition) []Span {
	if !transition.InviteKnown {
		return nil
	}
	var flags []string
	if transition.Invite.MultiUse {
		flags = append(flags, "multi-use")
	}
	if transition.Invite.AllowExitNode {
		flags = append(flags, "exit node allowed")
	}
	if len(flags) == 0 {
		return nil
	}
	return []Span{lit(" (" + strings.Join(flags, ", ") + ")")}
}

// acceptorChanged reports a share whose acceptor's login name was set or
// changed: it is now accepted by someone else.
func acceptorChanged(transition model.ShareTransition) bool {
	for _, field := range transition.Fields {
		if name := model.ShareFieldName(field.Field); (name == "acceptedby" || name == "acceptedby.loginname") && valueOf(field.New, field.NewPresent).set {
			return true
		}
	}
	return false
}

// acceptanceRest returns the fields of an accepted share that its
// "share accepted by … (flags)" line does not already say: not the
// acceptance itself, the acceptor, a flag the line shows, or the invite
// link and e-mail bookkeeping that come with an acceptance.
func acceptanceRest(transition model.ShareTransition) []model.FieldChange {
	var rest []model.FieldChange
	for _, field := range transition.Fields {
		name := model.ShareFieldName(field.Field)
		flagShown := (name == "multiuse" || name == "allowexitnode") && transition.InviteKnown && isFlag(valueOf(field.New, field.NewPresent), true)
		if flagShown || name == "accepted" || name == "acceptedby" || strings.HasPrefix(name, "acceptedby.") || name == "inviteurl" || name == model.ShareFieldResent {
			continue
		}
		rest = append(rest, field)
	}
	return rest
}

// shareFieldSpans describes changed invite fields, separated by commas:
// "exit node allowed", "invite e-mail resent", "`tailnetId` changed", or a
// presented value change for any other field.
func shareFieldSpans(transition model.ShareTransition, fields []model.FieldChange) []Span {
	var spans []Span
	for index, field := range fields {
		if index > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, shareFieldSpan(transition, field)...)
	}
	return spans
}

func shareFieldSpan(transition model.ShareTransition, field model.FieldChange) []Span {
	old, current := valueOf(field.Old, field.OldPresent), valueOf(field.New, field.NewPresent)
	enabled, disabled := isFlag(current, true), isFlag(current, false) || (!current.set && isFlag(old, true))
	switch name := model.ShareFieldName(field.Field); {
	case name == "allowexitnode" && enabled:
		return []Span{lit("exit node allowed")}
	case name == "allowexitnode" && disabled:
		return []Span{lit("exit node no longer allowed")}
	case name == "multiuse" && enabled:
		return []Span{lit("multi-use enabled")}
	case name == "multiuse" && disabled:
		return []Span{lit("multi-use disabled")}
	case name == "accepted" && disabled:
		return []Span{lit("no longer accepted")}
	case name == model.ShareFieldResent:
		return []Span{lit("invite e-mail resent")}
	case name == "inviteurl":
		return []Span{lit("invite link changed")}
	}
	if transition.FieldSeverity(field) == model.SeverityLow {
		// Identifiers are bookkeeping; their values mean nothing to a
		// reader (History keeps them).
		return []Span{code(field.Field), lit(" changed")}
	}
	return presentFieldInline("device_details", field)
}

// isFlag reports whether a presented value is the boolean want.
func isFlag(value fieldValue, want bool) bool {
	flag, ok := value.value.(bool)
	return value.set && ok && flag == want
}
