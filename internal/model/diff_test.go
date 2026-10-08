package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// deviceInvite returns one invite in the shape of Tailscale's DeviceInvite
// (GET /api/v2/device/{id}/device-invites). The values are illustrative.
func deviceInvite(id string, accepted bool) map[string]any {
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
		"accepted":        accepted,
	}
	if accepted {
		invite["acceptedBy"] = map[string]any{
			"id":            float64(1250252329925020),
			"loginName":     "alice@example.com",
			"profilePicUrl": "https://avatars.example.com/alice.png",
		}
	}
	return invite
}

// detailsJSON canonicalizes a device_details value holding invites.
func detailsJSON(t *testing.T, invites ...map[string]any) []byte {
	t.Helper()
	list := make([]any, len(invites))
	for index, invite := range invites {
		list[index] = invite
	}
	raw, _, err := CanonicalFor("device_details", map[string]any{"deviceInvites": list})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fieldPaths(fields []FieldChange) []string {
	paths := make([]string, len(fields))
	for index, field := range fields {
		paths[index] = field.Field
	}
	return paths
}

// TestKeyedDiffReportsListElementFieldPaths is R-049's invariant: a change
// inside one identified list element is reported at that element's field
// path, an added or removed element is one change naming the element, and a
// reorder of identified elements is not a change.
func TestKeyedDiffReportsListElementFieldPaths(t *testing.T) {
	first, second := deviceInvite("5861427050514914", true), deviceInvite("5861427050514999", false)
	before := detailsJSON(t, first, second)

	changed := deviceInvite("5861427050514914", true)
	changed["tailnetId"] = "T2000EXAMPLE"
	diff := DiffDetailedFor("device_details", before, detailsJSON(t, second, changed))
	want := []FieldChange{{Field: "deviceInvites[5861427050514914].tailnetId", Old: "T1000EXAMPLE", New: "T2000EXAMPLE", OldPresent: true, NewPresent: true}}
	if !reflect.DeepEqual(diff.Fields, want) || diff.TotalFields != 1 || diff.FieldsTruncated {
		t.Fatalf("one invite field change = %#v", diff)
	}

	nested := deviceInvite("5861427050514914", true)
	nested["acceptedBy"].(map[string]any)["id"] = float64(42)
	if got := fieldPaths(DiffDetailed(before, detailsJSON(t, nested, second)).Fields); !reflect.DeepEqual(got, []string{"deviceInvites[5861427050514914].acceptedBy.id"}) {
		t.Fatalf("nested invite field paths = %v", got)
	}

	added := deviceInvite("7000000000000001", false)
	diff = DiffDetailed(before, detailsJSON(t, first, second, added))
	if len(diff.Fields) != 1 || diff.Fields[0].Field != "deviceInvites[7000000000000001]" || diff.Fields[0].OldPresent || !diff.Fields[0].NewPresent || diff.Fields[0].New == nil {
		t.Fatalf("added invite = %#v", diff.Fields)
	}
	diff = DiffDetailed(before, detailsJSON(t, first))
	if len(diff.Fields) != 1 || diff.Fields[0].Field != "deviceInvites[5861427050514999]" || !diff.Fields[0].OldPresent || diff.Fields[0].NewPresent || diff.Fields[0].Old == nil {
		t.Fatalf("removed invite = %#v", diff.Fields)
	}
	diff = DiffDetailed(detailsJSON(t), detailsJSON(t, added))
	if got := fieldPaths(diff.Fields); !reflect.DeepEqual(got, []string{"deviceInvites[7000000000000001]"}) {
		t.Fatalf("first invite = %v", got)
	}

	if diff := DiffDetailed(before, detailsJSON(t, second, first)); len(diff.Fields) != 0 || diff.TotalFields != 0 {
		t.Fatalf("reordered invites reported %#v", diff)
	}

	// Paths are reported in identity order, whatever the arrays' order.
	moved, kept := deviceInvite("5861427050514914", true), deviceInvite("5861427050514999", false)
	moved["multiUse"], kept["allowExitNode"] = true, true
	if got := fieldPaths(DiffDetailed(before, detailsJSON(t, kept, moved)).Fields); !reflect.DeepEqual(got, []string{"deviceInvites[5861427050514914].multiUse", "deviceInvites[5861427050514999].allowExitNode"}) {
		t.Fatalf("multi-element field paths = %v", got)
	}
}

func TestKeyedDiffFallsBackToWholeValueWithoutUsableIdentity(t *testing.T) {
	cases := map[string][2]string{
		"scalars":              {`{"tags":["tag:a"]}`, `{"tags":["tag:a","tag:b"]}`},
		"no identity":          {`{"items":[{"name":"a"}]}`, `{"items":[{"name":"b"}]}`},
		"duplicate identity":   {`{"items":[{"id":"1","v":1},{"id":"1","v":2}]}`, `{"items":[{"id":"1","v":1},{"id":"1","v":3}]}`},
		"missing on one":       {`{"items":[{"id":"1","v":1},{"v":2}]}`, `{"items":[{"id":"1","v":1},{"v":3}]}`},
		"object identity":      {`{"items":[{"id":{"a":1},"v":1}]}`, `{"items":[{"id":{"a":1},"v":2}]}`},
		"boolean identity":     {`{"items":[{"id":true,"v":1}]}`, `{"items":[{"id":true,"v":2}]}`},
		"empty identity":       {`{"items":[{"id":"","v":1}]}`, `{"items":[{"id":"","v":2}]}`},
		"bracketed identity":   {`{"items":[{"id":"a]b","v":1}]}`, `{"items":[{"id":"a]b","v":2}]}`},
		"control in identity":  {`{"items":[{"id":"a\nb","v":1}]}`, `{"items":[{"id":"a\nb","v":2}]}`},
		"mixed elements":       {`{"items":[{"id":"1","v":1},"x"]}`, `{"items":[{"id":"1","v":2},"x"]}`},
		"identity on one side": {`{"items":[{"id":"1"}]}`, `{"items":[{"name":"x"}]}`},
		"top-level identities": {`[{"id":"1","v":1}]`, `[{"id":"1","v":1},{"id":"1","v":2}]`},
	}
	for name, values := range cases {
		diff := DiffDetailed([]byte(values[0]), []byte(values[1]))
		if len(diff.Fields) != 1 {
			t.Fatalf("%s: fields = %#v", name, diff.Fields)
		}
		if field := diff.Fields[0].Field; field != "tags" && field != "items" && field != "value" {
			t.Fatalf("%s: whole-value path = %q", name, field)
		}
	}
	long := fmt.Sprintf(`{"items":[{"id":"%0129d","v":1}]}`, 0)
	if diff := DiffDetailed([]byte(long), []byte(long[:len(long)-3]+"2}]}")); len(diff.Fields) != 1 || diff.Fields[0].Field != "items" {
		t.Fatalf("over-long identity = %#v", diff.Fields)
	}
}

func TestKeyedDiffUsesFallbackIdentitiesAndKeepsOrderedLists(t *testing.T) {
	nodes := DiffDetailed([]byte(`{"peers":[{"nodeId":"n1","v":1},{"nodeId":"n2","v":1}]}`), []byte(`{"peers":[{"nodeId":"n1","v":2},{"nodeId":"n2","v":1}]}`))
	if got := fieldPaths(nodes.Fields); !reflect.DeepEqual(got, []string{"peers[n1].v"}) {
		t.Fatalf("nodeId identity paths = %v", got)
	}
	// An "id" shared by elements is not an identity; "address" is used.
	resolvers := DiffDetailed([]byte(`{"r":[{"id":1,"address":"1.1.1.1","x":false},{"id":1,"address":"9.9.9.9","x":false}]}`), []byte(`{"r":[{"id":1,"address":"1.1.1.1","x":true},{"id":1,"address":"9.9.9.9","x":false}]}`))
	if got := fieldPaths(resolvers.Fields); !reflect.DeepEqual(got, []string{"r[1.1.1.1].x"}) {
		t.Fatalf("address identity paths = %v", got)
	}
	numeric := DiffDetailed([]byte(`{"r":[{"id":1250252329925020,"v":1}]}`), []byte(`{"r":[{"id":1250252329925020,"v":2}]}`))
	if got := fieldPaths(numeric.Fields); !reflect.DeepEqual(got, []string{"r[1250252329925020].v"}) {
		t.Fatalf("numeric identity paths = %v", got)
	}

	// DNS resolvers are ordered: a reorder is reported as the whole list,
	// exactly as before keyed diffs.
	oldDNS := `{"nameservers":[{"address":"1.1.1.1"},{"address":"8.8.8.8"}],"splitDNS":{"corp":[{"address":"10.0.0.53","useWithExitNode":false}]}}`
	newDNS := `{"nameservers":[{"address":"8.8.8.8"},{"address":"1.1.1.1"}],"splitDNS":{"corp":[{"address":"10.0.0.53","useWithExitNode":true}]}}`
	diff := DiffDetailedFor("dns", []byte(oldDNS), []byte(newDNS))
	if got := fieldPaths(diff.Fields); !reflect.DeepEqual(got, []string{"nameservers", "splitDNS.corp[10.0.0.53].useWithExitNode"}) {
		t.Fatalf("DNS paths = %v", got)
	}
}

func TestKeyedDiffKeepsFieldBoundAndPresence(t *testing.T) {
	var before, after []map[string]any
	for index := 0; index < 30; index++ {
		id := fmt.Sprintf("%016d", index)
		before = append(before, deviceInvite(id, false))
		changed := deviceInvite(id, false)
		changed["multiUse"] = true
		after = append(after, changed)
	}
	diff := DiffDetailed(detailsJSON(t, before...), detailsJSON(t, after...))
	if len(diff.Fields) != maxDiffFields || !diff.FieldsTruncated || diff.TotalFields != 30 {
		t.Fatalf("bound: %d fields, truncated=%v, total=%d", len(diff.Fields), diff.FieldsTruncated, diff.TotalFields)
	}

	old := `{"items":[{"id":"1","note":null}]}`
	diff = DiffDetailed([]byte(old), []byte(`{"items":[{"id":"1"}]}`))
	if len(diff.Fields) != 1 || diff.Fields[0].Field != "items[1].note" || !diff.Fields[0].OldPresent || diff.Fields[0].NewPresent {
		t.Fatalf("null to absent inside an element = %#v", diff.Fields)
	}
	raw, _ := json.Marshal(diff.Fields[0])
	if string(raw) != `{"field":"items[1].note","old":null,"old_present":true}` {
		t.Fatalf("element field encoding = %s", raw)
	}
}

func TestFieldPathHelpers(t *testing.T) {
	for path, want := range map[string]string{
		"deviceInvites[5861427050514914].tailnetId": "deviceInvites",
		"deviceInvites[1]":                          "deviceInvites",
		"postureAttributes.custom:x":                "postureAttributes",
		"tags":                                      "tags",
	} {
		if got := FieldRoot(path); got != want {
			t.Fatalf("FieldRoot(%q) = %q", path, got)
		}
	}
	for path, want := range map[string]string{
		"deviceInvites[5861427050514914].acceptedBy.id": "deviceInvites[].acceptedBy.id",
		"splitDNS.corp[10.0.0.53]":                      "splitDNS.corp[]",
		"tags":                                          "tags",
	} {
		if got := GenericPath(path); got != want {
			t.Fatalf("GenericPath(%q) = %q", path, got)
		}
	}
	if list, id, ok := ElementPathParts("splitDNS.corp[10.0.0.53]"); !ok || list != "splitDNS.corp" || id != "10.0.0.53" {
		t.Fatalf("ElementPathParts = %q %q %v", list, id, ok)
	}
	for _, path := range []string{"deviceInvites[1].tailnetId", "tags", "[1]", "x[]"} {
		if _, _, ok := ElementPathParts(path); ok {
			t.Fatalf("ElementPathParts(%q) accepted a non-element path", path)
		}
	}
	if fieldRoot("Device_Invites[1].tailnetId") != "deviceinvites" {
		t.Fatal("severity root of an element path")
	}
}
