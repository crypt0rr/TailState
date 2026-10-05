package diagnostics

import (
	"strings"
	"testing"

	"github.com/crypt0rr/tailstate/internal/boot"
)

// TestFreePagesAreReportedAsCompactionNotAsUnenforcedLimit distinguishes a
// budget lowered below a file that only holds free pages (fixed by admin
// compact) from a genuinely unenforced ceiling.
func TestFreePagesAreReportedAsCompactionNotAsUnenforcedLimit(t *testing.T) {
	config := boot.Config{ListenAddr: "127.0.0.1:8080"}
	compaction := Build(config, Runtime{Configured: true, Storage: StorageRuntime{DatabaseLimitBytes: 8 << 20, DatabaseBytes: 12 << 20, DatabaseUsedBytes: 1 << 20, DatabaseFreeBytes: 11 << 20, DatabaseFreelistPages: 2816, StoragePressure: 0.125, LimitNotEnforced: true}}, nil)
	if f, ok := finding(compaction, "storage_compaction_needed"); !ok || f.Severity != SeverityWarning || !strings.Contains(f.Remediation, "admin compact") {
		t.Fatalf("compaction finding missing: %#v", compaction)
	}
	if _, ok := finding(compaction, "storage_limit_not_enforced"); ok {
		t.Fatalf("free pages reported as an unenforced limit: %#v", compaction)
	}
	reclaimable := Build(config, Runtime{Configured: true, Storage: StorageRuntime{DatabaseLimitBytes: 512 << 20, DatabaseBytes: 32 << 20, DatabaseUsedBytes: 16 << 20, DatabaseFreeBytes: 16 << 20, StoragePressure: 0.03}}, nil)
	if f, ok := finding(reclaimable, "storage_reclaimable"); !ok || f.Severity != SeverityInfo {
		t.Fatalf("reclaimable finding missing: %#v", reclaimable)
	}
	small := Build(config, Runtime{Configured: true, Storage: StorageRuntime{DatabaseLimitBytes: 512 << 20, DatabaseBytes: 2 << 20, DatabaseUsedBytes: 1 << 20, DatabaseFreeBytes: 1 << 20}}, nil)
	if _, ok := finding(small, "storage_reclaimable"); ok {
		t.Fatalf("small free space reported as reclaimable: %#v", small)
	}
}
