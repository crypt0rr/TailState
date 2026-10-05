package web

import (
	"fmt"
	"html/template"
	"time"
)

// Template helpers. Every timestamp the interface shows is rendered in UTC
// with an explicit "UTC" label, a machine-readable datetime attribute, and a
// relative description computed at render time.

const displayTimeLayout = "2006-01-02 15:04:05 UTC"

type timeView struct {
	Valid    bool
	ISO      string
	UTC      string
	Relative string
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"when":    when,
		"mib":     formatMiB,
		"percent": formatPercent,
	}
}

// when describes value (a time.Time or *time.Time) relative to now. A nil
// pointer or zero time yields an invalid view, rendered as a dash.
func when(value any, now time.Time) timeView {
	var at time.Time
	switch typed := value.(type) {
	case time.Time:
		at = typed
	case *time.Time:
		if typed != nil {
			at = *typed
		}
	}
	if at.IsZero() {
		return timeView{}
	}
	at = at.UTC()
	return timeView{Valid: true, ISO: at.Format(time.RFC3339), UTC: at.Format(displayTimeLayout), Relative: relativeTime(at, now)}
}

func relativeTime(at, now time.Time) string {
	delta := now.Sub(at)
	future := delta < 0
	if future {
		delta = -delta
	}
	var amount string
	switch {
	case delta < 5*time.Second:
		return "just now"
	case delta < time.Minute:
		amount = fmt.Sprintf("%d s", int(delta/time.Second))
	case delta < time.Hour:
		amount = fmt.Sprintf("%d min", int(delta/time.Minute))
	case delta < 48*time.Hour:
		amount = fmt.Sprintf("%d h", int(delta/time.Hour))
	default:
		amount = fmt.Sprintf("%d days", int(delta/(24*time.Hour)))
	}
	if future {
		return "in " + amount
	}
	return amount + " ago"
}

func formatMiB(bytes int64) string {
	return fmt.Sprintf("%.2f MiB", float64(bytes)/(1<<20))
}

func formatPercent(ratio float64) string {
	return fmt.Sprintf("%.1f%%", ratio*100)
}
