package mattermost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

type Sender struct{ client *http.Client }

func New() *Sender { return &Sender{client: &http.Client{Timeout: 15 * time.Second}} }

type DeliveryError struct {
	Status     int
	RetryAfter time.Duration
	Message    string
}

func (e *DeliveryError) Error() string { return e.Message }
func (e *DeliveryError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 408 && e.Status != 429
}

func (s *Sender) Send(ctx context.Context, webhookURL, text string) error {
	payload, _ := json.Marshal(map[string]any{"text": text, "username": "TailState", "icon_emoji": ":satellite:"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		retry := time.Duration(0)
		if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil {
			retry = time.Duration(seconds) * time.Second
		}
		return &DeliveryError{Status: resp.StatusCode, RetryAfter: retry, Message: fmt.Sprintf("Mattermost returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return nil
}
func (s *Sender) Test(ctx context.Context, url string) error {
	return s.Send(ctx, url, "### ✅ TailState connection test\nMattermost notifications are configured correctly.")
}

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
