package web

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/secret"
	"github.com/crypt0rr/tailstate/internal/store"
)

// TestUndecryptableDestinationStaysManageable guards R-055 in the UI: with
// one destination sealed under another master key, Settings and Status
// still load, both name the affected destination, and it can be disabled
// and removed.
func TestUndecryptableDestinationStaysManageable(t *testing.T) {
	server, st, db, cookies := webServerWithDatabase(t)
	ctx := context.Background()
	csrf := coverageCSRF(t, cookies)
	if _, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Healthy hook", ServiceURL: "generic://healthy.example/path?token=secret", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	bad, err := st.SaveDestination(ctx, store.NotificationDestination{Name: "Stale hook", ServiceURL: "generic://stale.example/path", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := secret.NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := foreign.Seal("notification_destinations.service_url_enc:"+strconv.FormatInt(bad, 10), "generic://stale.example/path")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE notification_destinations SET service_url_enc=? WHERE id=?", sealed, bad); err != nil {
		t.Fatal(err)
	}
	if err := st.EnqueueSystem(ctx, "queued"); err != nil {
		t.Fatal(err)
	}

	settingsPage := authenticatedGet(t, server, "/settings", cookies)
	body := settingsPage.Body.String()
	if settingsPage.Code != http.StatusOK || !strings.Contains(body, "Stale hook") || !strings.Contains(body, "cannot be decrypted with the current master key") || !strings.Contains(body, "generic://healthy.example") {
		t.Fatalf("settings with an undecryptable destination status=%d body=%s", settingsPage.Code, body)
	}
	statusPage := authenticatedGet(t, server, "/status", cookies)
	if statusPage.Code != http.StatusOK || !strings.Contains(statusPage.Body.String(), "service URL cannot be decrypted") {
		t.Fatalf("status with an undecryptable destination status=%d body=%s", statusPage.Code, statusPage.Body.String())
	}

	id := strconv.FormatInt(bad, 10)
	if disable := coveragePost(t, server, "/settings/destinations/disable", url.Values{"_csrf": {csrf}, "id": {id}}, cookies); disable.Code != http.StatusSeeOther || !strings.Contains(followFlash(t, server, cookies, disable), "Notification destination disabled") {
		t.Fatalf("disable undecryptable destination status=%d", disable.Code)
	}
	list, err := st.ListDestinations(ctx)
	if err != nil || len(list) != 2 || list[1].ID != bad || list[1].Enabled {
		t.Fatalf("after disable destinations=%#v err=%v", list, err)
	}
	if removed := coveragePost(t, server, "/settings/destinations/remove", url.Values{"_csrf": {csrf}, "id": {id}, "confirm": {"remove"}}, cookies); removed.Code != http.StatusSeeOther || !strings.Contains(followFlash(t, server, cookies, removed), "Removed Stale hook") {
		t.Fatalf("remove undecryptable destination status=%d", removed.Code)
	}
	list, err = st.ListDestinations(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "Healthy hook" || list[0].ServiceURLUnreadable {
		t.Fatalf("after removal destinations=%#v err=%v", list, err)
	}
}
