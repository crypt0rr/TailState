package notify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

func Digest(changes []model.Change) string {
	counts := map[string]int{}
	for _, c := range changes {
		counts[c.Kind]++
	}
	var b strings.Builder
	b.WriteString("### Tailscale inventory changed\n")
	fmt.Fprintf(&b, "**%d change(s):** %d created, %d changed, %d removed\n\n", len(changes), counts["created"], counts["changed"], counts["removed"])
	for _, c := range changes {
		icon := map[string]string{"created": "➕", "changed": "✏️", "removed": "➖"}[c.Kind]
		line := fmt.Sprintf("%s **%s** `%s` (%s)\n", icon, escape(c.Name), c.Kind, escape(c.Collector))
		if b.Len()+len(line) > 11500 {
			fmt.Fprintf(&b, "\n_Additional changes omitted; total: %d._", len(changes))
			break
		}
		b.WriteString(line)
		for _, field := range c.Fields {
			detail := fmt.Sprintf("  - `%s`: `%s` → `%s`\n", escape(field.Field), short(field.Old), short(field.New))
			if b.Len()+len(detail) > 11800 {
				break
			}
			b.WriteString(detail)
		}
	}
	if b.Len() > 12000 {
		return b.String()[:11999] + "…"
	}
	return b.String()
}

func SourceHealth(collector string, recovered bool) string {
	if recovered {
		return fmt.Sprintf("### ✅ Tailscale API collector recovered\n`%s` is responding successfully again.", escape(collector))
	}
	return fmt.Sprintf("### ⚠️ Tailscale API collector unhealthy\n`%s` failed three consecutive polls. TailState will keep retrying.", escape(collector))
}

func Update(previous, current string) string {
	return fmt.Sprintf("### 🚀 TailState updated\n**Previous version:** `%s`\n**Current version:** `%s`", escape(previous), escape(current))
}

func escape(value string) string {
	return strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(value)
}

func short(value any) string {
	raw, _ := json.Marshal(value)
	text := string(raw)
	if len(text) > 180 {
		text = text[:179] + "…"
	}
	return escape(text)
}

func retryAfter(value string) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return max(time.Until(when), 0)
	}
	return 0
}
