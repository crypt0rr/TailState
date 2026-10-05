package web

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/crypt0rr/tailstate/internal/store"
)

// TestHistoryExportOffersNextPart checks the operator path for a history
// larger than one pack: each partial download names its next cursor (file
// name, header, and rel="next" link keeping the filters and limit), the
// History page offers "Download next part" with the active filters, and the
// chain covers every matching batch exactly once with verifiable parts.
func TestHistoryExportOffersNextPart(t *testing.T) {
	ctx := context.Background()
	server, _, db, cookies := webServerWithDatabase(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var want []int64
	for index := 0; index < 5; index++ {
		result, err := db.ExecContext(ctx, "INSERT INTO event_batches(generation,observed_at,change_count,created_at) VALUES(1,?,1,?)", now, now)
		if err != nil {
			t.Fatal(err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO events(batch_id,generation,observed_at,collector,event_type,resource_id,name,changes_json) VALUES(?,1,?,'devices','changed','device-1','server','[]')", id, now); err != nil {
			t.Fatal(err)
		}
		want = append([]int64{id}, want...)
	}

	page := authGet(t, server, "/history?resource=device-1", cookies).Body.String()
	if !strings.Contains(page, "Download next part") || !strings.Contains(page, `action="/history/export"`) || !strings.Contains(page, `<input type="hidden" name="resource" value="device-1">`) || !strings.Contains(page, `name="cursor"`) {
		t.Fatal("history page does not offer the next-part form with the active filters")
	}

	linkPattern := regexp.MustCompile(`^<(/history/export\?[^>]+)>; rel="next"$`)
	target := "/history/export?resource=device-1&limit=2"
	var got []int64
	for part := 0; part < 10; part++ {
		response := authGet(t, server, target, cookies)
		if response.Code != http.StatusOK {
			t.Fatalf("part %d status=%d body=%s", part, response.Code, response.Body.String())
		}
		if err := store.VerifyEvidencePack(response.Body.Bytes()); err != nil {
			t.Fatalf("part %d did not verify: %v", part, err)
		}
		var pack store.EvidencePack
		if err := json.Unmarshal(response.Body.Bytes(), &pack); err != nil {
			t.Fatal(err)
		}
		for _, batch := range pack.Batches {
			got = append(got, batch.ID)
		}
		next := response.Header().Get("X-TailState-Evidence-Next-Cursor")
		disposition := response.Header().Get("Content-Disposition")
		if !pack.Truncated {
			if next != "" || response.Header().Get("Link") != "" || strings.Contains(disposition, "-next-") {
				t.Fatalf("final part advertises a continuation: next=%q disposition=%q", next, disposition)
			}
			break
		}
		if next != strconv.FormatInt(pack.NextCursor, 10) || !strings.Contains(disposition, "-next-"+next+".json") {
			t.Fatalf("part %d next=%q disposition=%q, want cursor %d", part, next, disposition, pack.NextCursor)
		}
		match := linkPattern.FindStringSubmatch(response.Header().Get("Link"))
		if match == nil || !strings.Contains(match[1], "cursor="+next) || !strings.Contains(match[1], "limit=2") || !strings.Contains(match[1], "resource=device-1") {
			t.Fatalf("part %d Link=%q", part, response.Header().Get("Link"))
		}
		target = match[1]
	}
	if !slices.Equal(got, want) {
		t.Fatalf("web export chain=%v, want %v", got, want)
	}

	// Without a limit the export uses the full pack size, not the page size.
	full := authGet(t, server, "/history/export", cookies)
	var pack store.EvidencePack
	if err := json.Unmarshal(full.Body.Bytes(), &pack); err != nil {
		t.Fatal(err)
	}
	if pack.Truncated || pack.Filter.Limit != 100 || len(pack.Batches) != 5 {
		t.Fatalf("default export truncated=%t limit=%d batches=%d", pack.Truncated, pack.Filter.Limit, len(pack.Batches))
	}
}
