package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/notify"
)

func TestMonitoringOptionsPersistInMetaWithoutSchemaChange(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	in := settings()
	if _, err := st.SaveSettings(ctx, in); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ExpiryWarningDays) != 2 || loaded.ExpiryWarningDays[0] != 14 || loaded.ExpiryWarningDays[1] != 3 || loaded.ExpiryTagFilter != nil {
		t.Fatalf("default options=%v %v", loaded.ExpiryWarningDays, loaded.ExpiryTagFilter)
	}
	revision := loaded.Revision
	loaded.ExpiryWarningDays = []int{3, 30, 3}
	loaded.ExpiryTagFilter = []string{"tag:server", " tag:Server ", "", "tag:ci"}
	if _, err := st.SaveSettings(ctx, loaded); err != nil {
		t.Fatal(err)
	}
	updated, err := st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.ExpiryWarningDays) != 2 || updated.ExpiryWarningDays[0] != 30 || updated.ExpiryWarningDays[1] != 3 {
		t.Fatalf("windows=%v", updated.ExpiryWarningDays)
	}
	if strings.Join(updated.ExpiryTagFilter, ",") != "tag:ci,tag:server" {
		t.Fatalf("tags=%v", updated.ExpiryTagFilter)
	}
	if updated.Revision == revision {
		t.Fatal("changing an option did not change the settings revision")
	}
	var version int
	if err := st.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 14 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}

	// A database configured by an older release has no options row.
	if _, err := st.db.Exec("DELETE FROM meta WHERE key=?", monitoringOptionsMeta); err != nil {
		t.Fatal(err)
	}
	legacy, err := st.Settings(ctx)
	if err != nil || len(legacy.ExpiryWarningDays) != 2 {
		t.Fatalf("legacy options=%v err=%v", legacy.ExpiryWarningDays, err)
	}
	// A damaged value falls back to the defaults instead of failing.
	for _, damaged := range []string{"{", `{"expiry_warning_days":[0],"expiry_tag_filter":["bad"]}`} {
		if _, err := st.db.Exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", monitoringOptionsMeta, damaged); err != nil {
			t.Fatal(err)
		}
		recovered, err := st.Settings(ctx)
		if err != nil || len(recovered.ExpiryWarningDays) != 2 || recovered.ExpiryTagFilter != nil {
			t.Fatalf("damaged %q options=%#v err=%v", damaged, recovered, err)
		}
	}
	// An explicitly empty window list disables warnings and survives a reload.
	legacy.ExpiryWarningDays = []int{}
	if _, err := st.SaveSettings(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if disabled, err := st.Settings(ctx); err != nil || disabled.ExpiryWarningDays == nil || len(disabled.ExpiryWarningDays) != 0 {
		t.Fatalf("disabled windows=%#v err=%v", disabled.ExpiryWarningDays, err)
	}
}

func TestMonitoringOptionValidation(t *testing.T) {
	for _, days := range [][]int{{0}, {366}, {-1}, {1, 2, 3, 4, 5}} {
		in := settings()
		in.ExpiryWarningDays = days
		if err := ValidateSettings(in); err == nil {
			t.Fatalf("windows %v were accepted", days)
		}
		if _, err := testStore(t).SaveSettings(context.Background(), in); err == nil {
			t.Fatalf("windows %v were persisted", days)
		}
	}
	tooMany := make([]string, MaxExpiryTagFilters+1)
	for i := range tooMany {
		tooMany[i] = "tag:t" + strings.Repeat("x", i+1)
	}
	for _, tags := range [][]string{{"server"}, {"tag:"}, {"tag:a b"}, {"tag:a,b"}, {"tag:" + strings.Repeat("x", 200)}, tooMany} {
		in := settings()
		in.ExpiryTagFilter = tags
		if err := ValidateSettings(in); err == nil {
			t.Fatalf("tags %v were accepted", tags)
		}
	}
	if days, err := NormalizeExpiryWarningDays([]int{1, 365}); err != nil || days[0] != 365 {
		t.Fatalf("bounds rejected: %v %v", days, err)
	}
}

func TestCommitExpiryWarningsIsAtomicWithState(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	generation, err := st.SaveSettings(ctx, settings())
	if err != nil {
		t.Fatal(err)
	}
	if state, err := st.ExpiryWarningState(ctx); err != nil || state != "" {
		t.Fatalf("initial state=%q err=%v", state, err)
	}
	committed, err := st.CommitExpiryWarnings(ctx, generation, []notify.Message{notify.Text("warning")}, `{"generation":1}`)
	if err != nil || !committed {
		t.Fatalf("commit=%v err=%v", committed, err)
	}
	var pending int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM outbox WHERE payload='warning' AND batch_id IS NULL").Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending=%d err=%v", pending, err)
	}
	if state, err := st.ExpiryWarningState(ctx); err != nil || state != `{"generation":1}` {
		t.Fatalf("state=%q err=%v", state, err)
	}
	// A structured warning is stored format-neutral, as a system notification
	// outside any change batch, and rendered per destination at send time.
	warning := notify.Context{Tailnet: "example.com"}.ExpiryWarning(3, []notify.ExpiryLine{{Kind: "Device node key", Name: "server", Expires: time.Now().Add(48 * time.Hour), DaysLeft: 2}}, time.Now())
	if committed, err := st.CommitExpiryWarnings(ctx, generation, []notify.Message{warning}, `{"generation":1}`); err != nil || !committed {
		t.Fatalf("structured commit=%v err=%v", committed, err)
	}
	var structured int
	if err := st.db.QueryRow("SELECT COUNT(*) FROM outbox WHERE payload_format=? AND batch_id IS NULL AND payload LIKE '%expiring within 3 day%'", notify.PayloadMessage).Scan(&structured); err != nil || structured != 1 {
		t.Fatalf("structured=%d err=%v", structured, err)
	}
	// A failing enqueue must not record the state as sent.
	if _, err := st.db.Exec(`CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'outbox unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitExpiryWarnings(ctx, generation, []notify.Message{notify.Text("second")}, `{"generation":2}`); err == nil {
		t.Fatal("failed enqueue was reported as committed")
	}
	if state, _ := st.ExpiryWarningState(ctx); state != `{"generation":1}` {
		t.Fatalf("state advanced without its notification: %q", state)
	}
	records, err := st.CollectorSnapshots(ctx, generation, "devices")
	if err != nil || len(records) != 0 {
		t.Fatalf("records=%v err=%v", records, err)
	}
}
