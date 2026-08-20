package notify

import (
	"encoding/json"
	"fmt"
	"strings"

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
		if c.FieldsTruncated {
			total := c.TotalFields
			if total <= len(c.Fields) {
				total = len(c.Fields) + 1
			}
			fmt.Fprintf(&b, "  _Additional field changes omitted; total: %d._\n", total)
		}
	}
	if b.Len() > 12000 {
		return truncate(b.String(), 11999)
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
	value = strings.NewReplacer("\n", " ", "\r", " ").Replace(value)
	value = strings.NewReplacer(
		"\\", "\\\\",
		"`", "'",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"#", "\\#",
		"|", "\\|",
		"~", "\\~",
		">", "\\>",
	).Replace(value)
	return truncate(value, 256)
}

func short(value any) string {
	raw, _ := json.Marshal(value)
	text := string(raw)
	if len(text) > 180 {
		text = truncate(text, 179)
	}
	return escape(text)
}
