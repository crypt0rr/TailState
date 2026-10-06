package notify

import (
	"encoding/json"
	"fmt"
	"sort"

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
}

type fleetTransition struct {
	collector string
	field     model.FieldChange
	count     int
}

// summarize collapses upstream schema changes and fleet-wide transitions.
// It returns the summaries and the changes with summarized fields removed; a
// changed resource left without fields is not listed individually. History
// still lists every resource and field.
func summarize(in DigestInput) ([]schemaChange, []fleetTransition, []model.Change) {
	type fieldRef struct{ change, field int }
	removed := map[fieldRef]bool{}

	// A field newly present (or absent) on every resource the collector
	// returned is an upstream schema change, not drift of each resource.
	schemaGroups := map[string]*schemaChange{}
	schemaRefs := map[string][]fieldRef{}
	for changeIndex, change := range in.Changes {
		if change.Kind != "changed" {
			continue
		}
		for fieldIndex, field := range change.Fields {
			if field.OldPresent == field.NewPresent {
				continue
			}
			key := change.Collector + "\x00" + field.Field + "\x00" + fmt.Sprint(field.NewPresent)
			group := schemaGroups[key]
			if group == nil {
				group = &schemaChange{collector: change.Collector, field: field.Field, added: field.NewPresent, sample: field}
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
	fleetGroups := map[string]*fleetTransition{}
	fleetRefs := map[string][]fieldRef{}
	for changeIndex, change := range in.Changes {
		if change.Kind != "changed" {
			continue
		}
		for fieldIndex, field := range change.Fields {
			if removed[fieldRef{changeIndex, fieldIndex}] {
				continue
			}
			oldJSON, _ := json.Marshal(field.Old)
			newJSON, _ := json.Marshal(field.New)
			key := fmt.Sprintf("%s\x00%s\x00%t%s\x00%t%s", change.Collector, field.Field, field.OldPresent, oldJSON, field.NewPresent, newJSON)
			group := fleetGroups[key]
			if group == nil {
				group = &fleetTransition{collector: change.Collector, field: field}
				fleetGroups[key] = group
			}
			// Count resources, not field occurrences.
			if refs := fleetRefs[key]; len(refs) == 0 || refs[len(refs)-1].change != changeIndex {
				group.count++
			}
			fleetRefs[key] = append(fleetRefs[key], fieldRef{changeIndex, fieldIndex})
		}
	}
	var fleet []fleetTransition
	for key, group := range fleetGroups {
		if group.count >= FleetSummaryMinimum {
			fleet = append(fleet, *group)
			for _, ref := range fleetRefs[key] {
				removed[ref] = true
			}
		}
	}
	sort.Slice(fleet, func(i, j int) bool {
		if fleet[i].count != fleet[j].count {
			return fleet[i].count > fleet[j].count
		}
		if fleet[i].collector != fleet[j].collector {
			return fleet[i].collector < fleet[j].collector
		}
		return fleet[i].field.Field < fleet[j].field.Field
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

// severity is the built-in severity of the summarised field change.
func (s schemaChange) severity() model.Severity {
	return model.Classify(model.Change{Kind: "changed", Collector: s.collector, Fields: []model.FieldChange{s.sample}})
}

// severity is the built-in severity of the summarised field transition.
func (f fleetTransition) severity() model.Severity {
	return model.Classify(model.Change{Kind: "changed", Collector: f.collector, Fields: []model.FieldChange{f.field}})
}

func (c Context) schemaLine(change schemaChange, batchID int64) Line {
	severity := change.severity()
	presence := " newly present on all "
	if !change.added {
		presence = " no longer present on any of the "
	}
	l := line(lit(severityIcons[severity]+" 🧩 "), strong("Upstream schema change:"), lit(" "), code(change.field), lit(fmt.Sprintf("%s%d ", presence, change.count)), txt(change.collector), lit(" resources"))
	return c.withDetails(l, batchID)
}

func (c Context) fleetLine(transition fleetTransition, batchID int64) Line {
	severity := transition.severity()
	spans := append([]Span{lit(severityIcons[severity] + " 📦 ")}, presentField(transition.collector, transition.field)...)
	l := line(append(spans, lit(fmt.Sprintf(" on %d resources (", transition.count)), txt(transition.collector), lit(")"))...)
	return c.withDetails(l, batchID)
}

func (c Context) withDetails(l Line, batchID int64) Line {
	if batchURL := c.HistoryBatchURL(batchID); batchURL != "" {
		l.Spans = append(l.Spans, lit(" "), link("details", batchURL))
	}
	return l
}
