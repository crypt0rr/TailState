package notify

import (
	"strings"
	"testing"
	"time"
)

func TestAdminChangeNamesActionFieldsAndClientOnly(t *testing.T) {
	observed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	message := Context{Tailnet: "example.ts.net", PublicURL: "https://tailstate.example"}.AdminChange("Notification destination disabled", []string{"enabled", "routing"}, "destination:3", "192.0.2.4", observed)
	for _, format := range []string{FormatMarkdown, FormatSlack, FormatPlain} {
		rendered := Render(message, format)
		for _, want := range []string{"TailState configuration changed", "Notification destination disabled", "enabled", "routing", "destination:3", "192.0.2.4", "Observed at 6 Oct 2026 12:00 UTC", "https://tailstate.example/settings"} {
			if !strings.Contains(rendered, want) {
				t.Fatalf("%s rendering lacks %q:\n%s", format, want, rendered)
			}
		}
	}
	minimal := Render(Context{}.AdminChange("Signed out", nil, "", "", observed), FormatMarkdown)
	if strings.Contains(minimal, "Changed:") || strings.Contains(minimal, "Client:") || strings.Contains(minimal, "Object:") || strings.Contains(minimal, "/settings") {
		t.Fatalf("empty details rendered: %s", minimal)
	}
}
