package model

import (
	"encoding/json"
	"strings"
)

// Device sharing. A device_details resource holds the device's share
// invites (Tailscale's DeviceInvite: id, created, tailnetId, deviceId,
// sharerId, multiUse, allowExitNode, email, lastEmailSentAt, inviteUrl,
// accepted, acceptedBy {id, loginName}). Their fields carry very different
// risk: a new or newly accepted share grants an outside user access, and
// allowExitNode lets that user route traffic through the device, while
// lastEmailSentAt and identifier changes are bookkeeping. This file reads
// invite changes for severity and notifications; History, the API, and
// evidence packs keep the recorded fields unchanged.

// DeviceInvite is the notification view of one share invite.
type DeviceInvite struct {
	// Recipient is acceptedBy.loginName, else the invited e-mail address,
	// else empty for an invite link.
	Recipient     string
	Accepted      bool
	MultiUse      bool
	AllowExitNode bool
}

// Share transition kinds.
const (
	ShareCreated = "created"
	ShareRemoved = "removed"
	ShareChanged = "changed"
)

// ShareTransition is the change of one invite in a device_details change.
type ShareTransition struct {
	ID   string
	Kind string
	// Fields are the invite's changed fields, relative to the invite
	// ("tailnetId", "acceptedBy.id"); set for a changed invite only.
	Fields []FieldChange
	// Invite is the invite's state after the change (before it, for a
	// removed invite) when known.
	Invite      DeviceInvite
	InviteKnown bool
}

// shareMetadataFields are invite fields whose change is bookkeeping: they
// identify the share but do not change who has access or how.
var shareMetadataFields = map[string]struct{}{
	"tailnetid":     {},
	"sharerid":      {},
	"deviceid":      {},
	"acceptedby.id": {},
	"created":       {},
}

// ShareFieldResent is the compact path of the invite e-mail timestamp.
const ShareFieldResent = "lastemailsentat"

// CompactField is the compact, lower-case form of a field path used to
// compare field names: "acceptedBy.id" becomes "acceptedby.id".
func CompactField(path string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(path))
}

// ShareFieldName is the compact name of a changed invite field. A redacted
// value is diffed inside its fingerprint object, so the invite URL's change
// is recorded as "inviteUrl.redacted_sha256"; its name is "inviteurl".
func ShareFieldName(path string) string {
	return strings.TrimSuffix(CompactField(path), ".redactedsha256")
}

// DeviceInvites returns the invites of a device_details change by ID: each
// invite's state after the change, and for an invite that was removed, its
// state before. Values that are not device_details snapshots yield none.
func DeviceInvites(before, after []byte) map[string]DeviceInvite {
	out := map[string]DeviceInvite{}
	for _, raw := range [][]byte{after, before} {
		var snapshot map[string]any
		if json.Unmarshal(raw, &snapshot) != nil {
			continue
		}
		for key, value := range snapshot {
			list, ok := value.([]any)
			if CompactField(key) != "deviceinvites" || !ok {
				continue
			}
			for _, element := range list {
				id, ok := elementIdentity("id", element)
				if _, seen := out[id]; !ok || seen {
					continue
				}
				out[id] = inviteOf(element.(map[string]any))
			}
		}
	}
	return out
}

func inviteOf(object map[string]any) DeviceInvite {
	invite := DeviceInvite{}
	invite.Accepted, _ = object["accepted"].(bool)
	invite.MultiUse, _ = object["multiUse"].(bool)
	invite.AllowExitNode, _ = object["allowExitNode"].(bool)
	if by, ok := object["acceptedBy"].(map[string]any); ok {
		invite.Recipient, _ = by["loginName"].(string)
	}
	if strings.TrimSpace(invite.Recipient) == "" {
		invite.Recipient, _ = object["email"].(string)
	}
	invite.Recipient = strings.TrimSpace(invite.Recipient)
	return invite
}

// ShareTransitions splits the device invite fields of a changed
// device_details resource into one transition per invite, in the order the
// fields name them, and returns the indices of the change's other fields. A
// whole-list deviceInvites field (recorded by releases before element paths,
// or a list that appeared or disappeared) is compared by invite ID; one that
// cannot be (a truncated value, an unsupported marker) is another field.
func ShareTransitions(change Change) (transitions []ShareTransition, others []int) {
	if change.Collector != "device_details" || change.Kind != "changed" {
		for index := range change.Fields {
			others = append(others, index)
		}
		return nil, others
	}
	index := map[string]int{}
	// listed are the invites of whole-list fields, for context when the
	// change carries none.
	listed := map[string]DeviceInvite{}
	add := func(id, kind string, field *FieldChange, element any) {
		position, seen := index[id]
		if !seen {
			position = len(transitions)
			index[id] = position
			transitions = append(transitions, ShareTransition{ID: id, Kind: kind})
			if invite, known := change.Invites[id]; known {
				transitions[position].Invite, transitions[position].InviteKnown = invite, true
			} else if invite, known := listed[id]; known {
				transitions[position].Invite, transitions[position].InviteKnown = invite, true
			} else if object, ok := element.(map[string]any); ok {
				transitions[position].Invite, transitions[position].InviteKnown = inviteOf(object), true
			}
		}
		if field != nil {
			transitions[position].Fields = append(transitions[position].Fields, *field)
		}
	}
	var visit func(field FieldChange) bool
	visit = func(field FieldChange) bool {
		root := FieldRoot(field.Field)
		if CompactField(root) != "deviceinvites" {
			return false
		}
		remainder := field.Field[len(root):]
		if remainder == "" {
			expanded, invites, ok := expandInviteList(root, field)
			if !ok {
				return false
			}
			for id, invite := range invites {
				listed[id] = invite
			}
			for _, element := range expanded {
				visit(element)
			}
			return true
		}
		closing := strings.IndexByte(remainder, ']')
		if remainder[0] != '[' || closing < 2 {
			return false
		}
		id, inner := remainder[1:closing], remainder[closing+1:]
		switch {
		case inner == "" && !field.OldPresent && field.NewPresent:
			add(id, ShareCreated, nil, field.New)
		case inner == "" && field.OldPresent && !field.NewPresent:
			add(id, ShareRemoved, nil, field.Old)
		case strings.HasPrefix(inner, ".") && len(inner) > 1:
			relative := field
			relative.Field = inner[1:]
			add(id, ShareChanged, &relative, nil)
		default:
			return false
		}
		return true
	}
	for fieldIndex, field := range change.Fields {
		if !visit(field) {
			others = append(others, fieldIndex)
		}
	}
	for position := range transitions {
		if !transitions[position].InviteKnown {
			transitions[position].Invite, transitions[position].InviteKnown = inviteFromFields(transitions[position].Fields)
		}
	}
	return transitions, others
}

// inviteFromFields reads what a changed invite's own fields say about it
// when no snapshot is available: the acceptor's login name or the invited
// e-mail address, and whether it is accepted.
func inviteFromFields(fields []FieldChange) (DeviceInvite, bool) {
	object := map[string]any{}
	for _, field := range fields {
		if !field.NewPresent {
			continue
		}
		switch CompactField(field.Field) {
		case "accepted":
			object["accepted"] = field.New
		case "acceptedby":
			object["acceptedBy"] = field.New
		case "acceptedby.loginname":
			object["acceptedBy"] = map[string]any{"loginName": field.New}
		case "email":
			object["email"] = field.New
		}
	}
	invite := inviteOf(object)
	return invite, invite.Recipient != ""
}

// expandInviteList compares a whole-list deviceInvites change by invite ID,
// and returns the invites the lists describe. An absent or null list is
// empty.
func expandInviteList(path string, field FieldChange) ([]FieldChange, map[string]DeviceInvite, bool) {
	oldList, oldOK := inviteList(field.Old, field.OldPresent)
	newList, newOK := inviteList(field.New, field.NewPresent)
	if !oldOK || !newOK || !identifiedBy("id", oldList) || !identifiedBy("id", newList) {
		return nil, nil, false
	}
	invites := map[string]DeviceInvite{}
	for _, list := range [][]any{newList, oldList} {
		for _, element := range list {
			id, _ := elementIdentity("id", element)
			if _, seen := invites[id]; !seen {
				invites[id] = inviteOf(element.(map[string]any))
			}
		}
	}
	d := differ{}
	d.diffKeyed(path, "id", oldList, newList)
	return d.result.Fields, invites, len(d.result.Fields) > 0 && !d.result.FieldsTruncated
}

func inviteList(value any, present bool) ([]any, bool) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var decoded any
	if json.Unmarshal(raw, &decoded) != nil {
		return nil, false
	}
	if decoded == nil || !present {
		return []any{}, true
	}
	list, ok := decoded.([]any)
	return list, ok
}

// Severity is the built-in severity of one invite transition: a new share
// is medium, or high when it is multi-use, allows the exit node, or is
// already accepted; a removed share is medium; a share accepted (or
// accepted by another user) or newly allowed to use the exit node is high;
// an e-mail resend and identifier changes (tailnetId, sharerId, deviceId,
// created, acceptedBy.id, and the invite URL fingerprint of an accepted
// share) are low; anything else is medium.
func (t ShareTransition) Severity() Severity {
	switch t.Kind {
	case ShareCreated:
		if t.InviteKnown && (t.Invite.MultiUse || t.Invite.AllowExitNode || t.Invite.Accepted) {
			return SeverityHigh
		}
		return SeverityMedium
	case ShareRemoved:
		return SeverityMedium
	}
	severity := SeverityLow
	for _, field := range t.Fields {
		if current := t.FieldSeverity(field); current.Rank() > severity.Rank() {
			severity = current
		}
	}
	return severity
}

// FieldSeverity is the severity of one changed field of a changed invite.
func (t ShareTransition) FieldSeverity(field FieldChange) Severity {
	name := ShareFieldName(field.Field)
	switch {
	case name == "accepted" || name == "allowexitnode":
		if isFalse(field.Old, field.OldPresent) && isTrue(field.New) {
			return SeverityHigh
		}
	case name == "acceptedby" || name == "acceptedby.loginname":
		if field.NewPresent && field.New != nil {
			return SeverityHigh
		}
	case name == ShareFieldResent:
		return SeverityLow
	case name == "inviteurl":
		if t.InviteKnown && t.Invite.Accepted {
			return SeverityLow
		}
	default:
		if _, metadata := shareMetadataFields[name]; metadata {
			return SeverityLow
		}
	}
	return SeverityMedium
}

// ShareAccepted reports whether the transition is the acceptance of a
// share: accepted switched from false (or absent) to true.
func (t ShareTransition) ShareAccepted() bool {
	for _, field := range t.Fields {
		if CompactField(field.Field) == "accepted" && isFalse(field.Old, field.OldPresent) && isTrue(field.New) {
			return true
		}
	}
	return false
}

// Bookkeeping reports whether every changed field of a changed invite is
// low severity (an e-mail resend or identifier change).
func (t ShareTransition) Bookkeeping() bool {
	if t.Kind != ShareChanged || len(t.Fields) == 0 {
		return false
	}
	for _, field := range t.Fields {
		if t.FieldSeverity(field) != SeverityLow {
			return false
		}
	}
	return true
}

// classifyDeviceDetails is the severity of a changed device_details
// resource: the highest of its invite transitions, and medium for any other
// field (posture attributes).
func classifyDeviceDetails(change Change) Severity {
	if len(change.Fields) == 0 {
		return SeverityMedium
	}
	transitions, others := ShareTransitions(change)
	severity := SeverityLow
	if len(others) > 0 {
		severity = SeverityMedium
	}
	for _, transition := range transitions {
		if current := transition.Severity(); current.Rank() > severity.Rank() {
			severity = current
		}
	}
	if change.FieldsTruncated && severity == SeverityLow {
		return SeverityMedium
	}
	return severity
}
