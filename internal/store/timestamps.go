package store

import "time"

// timestampLayout is the format of every timestamp the store writes: UTC
// with exactly nine fractional digits. Because every value has the same
// width, SQL string comparisons (lease_until<=?, expires_at<=?,
// next_attempt<=?) and indexes order them chronologically.
//
// Releases before schema 17 wrote time.RFC3339Nano, which drops trailing
// fractional zeros: "…:00Z" sorts after "…:00.1Z" because 'Z' sorts after
// '.', so two times within the same second could compare the wrong way
// round. Schema 17 rewrites those values in operational tables (see
// migrateSchemaV16ToV17). Observation times covered by the signed evidence
// ledger keep their original text and are compared only against
// whole-second bounds (observationBound), which order both forms correctly.
//
// time.Parse(time.RFC3339Nano, …) reads both forms.
const timestampLayout = "2006-01-02T15:04:05.000000000Z"

// formatTimestamp renders t in timestampLayout.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(timestampLayout)
}

// observationBound renders a whole-second range boundary for comparison with
// a stored observation time (events.observed_at, event_batches.observed_at).
// Those values are part of signed evidence and are never rewritten, so a
// database can hold both the legacy RFC 3339 form and timestampLayout. The
// bound deliberately omits the zone designator and fractional seconds: every
// stored value within that second, in either form, has the bound as a prefix
// and therefore sorts at or after it, and every value in an earlier second
// sorts before it. "observed_at >= bound" and "observed_at < bound" are
// therefore exact for the truncated second.
func observationBound(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05")
}
