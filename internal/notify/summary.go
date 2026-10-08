package notify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/crypt0rr/tailstate/internal/model"
)

// FleetSummaryMinimum is the number of resources that must share the same
// field transition in one batch before the digest reports it as one summary
// line (for example a client rollout) instead of one line per resource.
const FleetSummaryMinimum = 5

// schemaChangeMinimum is the smallest collector population for which a field
// appearing or disappearing on every resource is reported as an upstream
// schema change.
const schemaChangeMinimum = 2

type schemaChange struct {
	collector string
	field     string
	added     bool
	count     int
	sample    model.FieldChange
	// changes are the indices of the summarised changes in the digest input.
	changes []int
}

// fleetTransition is one or more field transitions shared by the same set
// of resources: a client rollout that also flips updateAvailable on the same
// devices is one summary.
type fleetTransition struct {
	collector string
	fields    []model.FieldChange
	count     int
	// changes are the indices of the summarised changes in the digest input.
	changes []int
}

// summarize collapses upstream schema changes and fleet-wide transitions.
// It returns the summaries and the changes with summarized fields removed; a
// changed resource left without fields is not listed individually. History
// still lists every resource and field.
func summarize(in DigestInput) ([]schemaChange, []fleetTransition, []model.Change) {
	type fieldRef struct{ change, field int }
	removed := map[fieldRef]bool{}
	// resources returns the distinct change indices of refs, in order.
	resources := func(refs []fieldRef) []int {
		var out []int
		for _, ref := range refs {
			if len(out) == 0 || out[len(out)-1] != ref.change {
				out = append(out, ref.change)
			}
		}
		return out
	}

	// A field newly present (or absent) on every resource the collector
	// returned is an upstream schema change, not drift of each resource.
	schemaGroups := map[string]*schemaChange{}
	schemaRefs := map[string][]fieldRef{}
	for changeIndex, change := range in.Changes {
		if change.Kind != "changed" {
			continue
		}
		for fieldIndex, field := range change.Fields {
			if field.OldPresent == field.NewPresent || removed[fieldRef{changeIndex, fieldIndex}] || isElement(field.Field) {
				continue
			}
			// A field inside list elements ("deviceInvites[5861…].note") is
			// grouped by its generic path ("deviceInvites[].note").
			path := model.GenericPath(field.Field)
			key := change.Collector + "\x00" + path + "\x00" + fmt.Sprint(field.NewPresent)
			group := schemaGroups[key]
			if group == nil {
				sample := field
				sample.Field = path
				group = &schemaChange{collector: change.Collector, field: path, added: field.NewPresent, sample: sample}
				schemaGroups[key] = group
			}
			if refs := schemaRefs[key]; len(refs) == 0 || refs[len(refs)-1].change != changeIndex {
				group.count++
			}
			schemaRefs[key] = append(schemaRefs[key], fieldRef{changeIndex, fieldIndex})
		}
	}
	var schema []schemaChange
	for key, group := range schemaGroups {
		population := in.ResourceCounts[group.collector]
		if population >= schemaChangeMinimum && group.count == population {
			group.changes = resources(schemaRefs[key])
			schema = append(schema, *group)
			for _, ref := range schemaRefs[key] {
				removed[ref] = true
			}
		}
	}
	sort.Slice(schema, func(i, j int) bool {
		if schema[i].collector != schema[j].collector {
			return schema[i].collector < schema[j].collector
		}
		return schema[i].field < schema[j].field
	})

	// The same field transition on many resources (a client rollout, an
	// updateAvailable flip) becomes one line.
	type transition struct {
		collector string
		field     model.FieldChange
		count     int
	}
	fleetGroups := map[string]*transition{}
	fleetRefs := map[string][]fieldRef{}
	for changeIndex, change := range in.Changes {
		if change.Kind != "changed" {
			continue
		}
		for fieldIndex, field := range change.Fields {
			if removed[fieldRef{changeIndex, fieldIndex}] || isElement(field.Field) {
				continue
			}
			oldJSON, _ := json.Marshal(field.Old)
			newJSON, _ := json.Marshal(field.New)
			path := model.GenericPath(field.Field)
			key := fmt.Sprintf("%s\x00%s\x00%t%s\x00%t%s", change.Collector, path, field.OldPresent, oldJSON, field.NewPresent, newJSON)
			group := fleetGroups[key]
			if group == nil {
				sample := field
				sample.Field = path
				group = &transition{collector: change.Collector, field: sample}
				fleetGroups[key] = group
			}
			// Count resources, not field occurrences.
			if refs := fleetRefs[key]; len(refs) == 0 || refs[len(refs)-1].change != changeIndex {
				group.count++
			}
			fleetRefs[key] = append(fleetRefs[key], fieldRef{changeIndex, fieldIndex})
		}
	}
	// Transitions that cover exactly the same resources are merged into one
	// summary, their fields in name order.
	merged := map[string]*fleetTransition{}
	for key, group := range fleetGroups {
		if group.count < FleetSummaryMinimum {
			continue
		}
		changes := resources(fleetRefs[key])
		setKey := group.collector + "\x00" + fmt.Sprint(changes)
		summary := merged[setKey]
		if summary == nil {
			summary = &fleetTransition{collector: group.collector, count: group.count, changes: changes}
			merged[setKey] = summary
		}
		summary.fields = append(summary.fields, group.field)
		for _, ref := range fleetRefs[key] {
			removed[ref] = true
		}
	}
	fleet := make([]fleetTransition, 0, len(merged))
	for _, summary := range merged {
		sort.Slice(summary.fields, func(i, j int) bool { return fieldSortKey(summary.fields[i]) < fieldSortKey(summary.fields[j]) })
		fleet = append(fleet, *summary)
	}
	sort.Slice(fleet, func(i, j int) bool {
		if fleet[i].count != fleet[j].count {
			return fleet[i].count > fleet[j].count
		}
		if fleet[i].collector != fleet[j].collector {
			return fleet[i].collector < fleet[j].collector
		}
		return fieldSortKey(fleet[i].fields[0]) < fieldSortKey(fleet[j].fields[0])
	})

	if len(removed) == 0 {
		return schema, fleet, in.Changes
	}
	remaining := make([]model.Change, 0, len(in.Changes))
	for changeIndex, change := range in.Changes {
		kept := make([]model.FieldChange, 0, len(change.Fields))
		for fieldIndex, field := range change.Fields {
			if !removed[fieldRef{changeIndex, fieldIndex}] {
				kept = append(kept, field)
			}
		}
		if len(kept) == len(change.Fields) {
			remaining = append(remaining, change)
			continue
		}
		if len(kept) == 0 && !change.FieldsTruncated {
			continue
		}
		change.Fields = kept
		remaining = append(remaining, change)
	}
	return schema, fleet, remaining
}

// isElement reports a whole list element added or removed (a path such as
// "deviceInvites[5861427050514914]"). Such a change names one element, so
// it is listed with its resource instead of being summarised.
func isElement(path string) bool {
	_, _, ok := model.ElementPathParts(path)
	return ok
}

// fieldSortKey orders field transitions by field name, then by value, so
// summaries are deterministic.
func fieldSortKey(field model.FieldChange) string {
	oldJSON, _ := json.Marshal(field.Old)
	newJSON, _ := json.Marshal(field.New)
	return strings.Join([]string{field.Field, string(oldJSON), string(newJSON)}, "\x00")
}

// severity is the built-in severity of the summarised field change.
func (s schemaChange) severity() model.Severity {
	return model.Classify(model.Change{Kind: "changed", Collector: s.collector, Fields: []model.FieldChange{s.sample}})
}

// severity is the built-in severity of the summarised field transitions:
// the highest of them.
func (f fleetTransition) severity() model.Severity {
	return model.Classify(model.Change{Kind: "changed", Collector: f.collector, Fields: f.fields})
}

func (c Context) schemaLine(change schemaChange) Line {
	presence := " newly present on all "
	if !change.added {
		presence = " no longer present on any of the "
	}
	spans := []Span{lit(severityIcons[change.severity()] + " 🧩 Upstream schema change: "), code(change.field), lit(presence)}
	return line(append(spans, countSpans(change.collector, change.count)...)...)
}

// fleetLine is one summary such as "12 devices: `clientVersion` `1.80.2` →
// `1.82.1`, `updateAvailable` `true` → `false`".
func (c Context) fleetLine(transition fleetTransition) Line {
	spans := []Span{lit(severityIcons[transition.severity()] + " 📦 ")}
	spans = append(spans, countSpans(transition.collector, transition.count)...)
	spans = append(spans, lit(": "))
	for index, field := range transition.fields {
		if index > 0 {
			spans = append(spans, lit(", "))
		}
		spans = append(spans, presentFieldInline(transition.collector, field)...)
	}
	return line(spans...)
}
