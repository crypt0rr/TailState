package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crypt0rr/tailstate/internal/model"
)

// ConfigurationAuditScope is the OAuth scope of the configuration audit log
// endpoint (covered by all:read).
const ConfigurationAuditScope = "logs:configuration:read"

// MaxAuditEntries bounds the configuration audit entries kept from one
// response. Entries are chronological, so the newest are kept.
const MaxAuditEntries = 5000

// configurationAuditLog is the subset of Tailscale's ConfigurationAuditLog
// schema that TailState reads. The old and new values, action details, and
// deferral metadata are deliberately absent: the decoder discards them, so
// policy text or other configuration values are never held in a typed value
// or persisted.
type configurationAuditLog struct {
	EventTime string `json:"eventTime"`
	Type      string `json:"type"`
	Origin    string `json:"origin"`
	Actor     struct {
		Type        string `json:"type"`
		LoginName   string `json:"loginName"`
		DisplayName string `json:"displayName"`
	} `json:"actor"`
	Target struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Property string `json:"property"`
	} `json:"target"`
	Action string `json:"action"`
	Error  string `json:"error"`
}

// ConfigurationAuditLogs lists the configuration audit log entries between
// start and end (GET /tailnet/{tailnet}/logging/configuration). The window
// is widened to whole seconds. A 403 (missing logs:configuration:read scope
// or plan) or 404 (logging not supported) is returned as an *HTTPError for
// which IsUnsupported reports true. At most MaxAuditEntries entries are
// returned; entries with an unparsable timestamp are skipped.
func (c *Client) ConfigurationAuditLogs(ctx context.Context, start, end time.Time) ([]model.AuditEntry, error) {
	if !end.After(start) {
		return nil, errors.New("configuration audit window is empty")
	}
	query := url.Values{}
	query.Set("start", start.UTC().Truncate(time.Second).Format(time.RFC3339))
	query.Set("end", end.UTC().Add(time.Second-1).Truncate(time.Second).Format(time.RFC3339))
	body, err := c.getBody(ctx, c.tailnet("logging/configuration?"+query.Encode()))
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("tailscale configuration audit response was empty")
	}
	var response struct {
		Logs []configurationAuditLog `json:"logs"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("tailscale configuration audit response was not valid: %w", err)
	}
	logs := response.Logs
	if len(logs) > MaxAuditEntries {
		logs = logs[len(logs)-MaxAuditEntries:]
	}
	entries := make([]model.AuditEntry, 0, len(logs))
	for _, item := range logs {
		if kind := strings.TrimSpace(item.Type); kind != "" && !strings.EqualFold(kind, "CONFIG") {
			continue
		}
		eventTime, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(item.EventTime))
		if parseErr != nil {
			continue
		}
		entries = append(entries, model.AuditEntry{
			EventTime:  eventTime.UTC(),
			Origin:     item.Origin,
			ActorType:  item.Actor.Type,
			ActorLogin: item.Actor.LoginName,
			ActorName:  item.Actor.DisplayName,
			TargetID:   item.Target.ID,
			TargetName: item.Target.Name,
			TargetType: item.Target.Type,
			Property:   item.Target.Property,
			Action:     item.Action,
			Failed:     strings.TrimSpace(item.Error) != "",
		})
	}
	return entries, nil
}
