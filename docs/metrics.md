# Metrics and alerting

TailState exposes Prometheus metrics at `/metrics`. Liveness and readiness
probes (`/healthz`, `/readyz`) are described in
[Operations](operations.md#health-and-readiness).

## Scraping `/metrics`

`/metrics` needs a bearer token whenever the scraper is outside the TailState
process's own loopback. Under Compose (or plain `docker run -p`), a host request
to the published port reaches the container from the Docker bridge, not from
loopback, so with an empty token `/metrics` returns `401`. Set a strong token
in `.env` and recreate the container so it takes effect:

```console
openssl rand -hex 32   # put the output in TAILSTATE_METRICS_TOKEN= in .env
docker compose up -d
printf 'Authorization: Bearer %s\n' "$(sed -n 's/^TAILSTATE_METRICS_TOKEN=//p' .env)" > metrics.header
curl -fsS -H @metrics.header http://127.0.0.1:8080/metrics
```

Reading the header from a file keeps the token out of your shell history and
the process list. Do not set the token with `export` in the shell that runs
`docker compose`: Compose prefers shell variables over `.env`. With the HTTPS
override in `compose.remote.yaml` there is no host port, so scrape through the
proxy instead, for example `https://tailstate.example.com/metrics`.

A standalone binary listening on loopback can be scraped without a token
(`curl -fsS http://127.0.0.1:8080/metrics`) as long as `127.0.0.1` is not listed
in `TAILSTATE_TRUSTED_PROXIES`.

When `TAILSTATE_METRICS_TOKEN` is empty, TailState answers only a loopback peer that is not listed in `TAILSTATE_TRUSTED_PROXIES` and sends no `X-Forwarded-For` or `X-Forwarded-Proto` header; everything else receives `401`. TailState cannot tell a loopback forwarder (for example an nginx `proxy_pass` that adds no forwarded headers, or an SSH tunnel) from a local client, so such a forwarder is treated as local: never expose `/metrics` through one without a token. Set that variable for Prometheus or any reverse proxy to require `Authorization: Bearer <token>` from any network location. Do not publish the endpoint without a token through a public reverse proxy.

## Metric reference

`/metrics` exposes the following families. Labels are low-cardinality: a
collector name, a fixed outcome or state vocabulary, or a table name; no
destination, resource, or user appears in a label.

| Area | Metrics | Meaning |
| --- | --- | --- |
| Readiness | `tailstate_ready`, `tailstate_baseline_degraded` | Setup and baseline complete; baseline ready but at least one collector degraded (see [Health and readiness](operations.md#health-and-readiness)) |
| Notification state | `tailstate_notification_state{state="unconfigured\|no_destinations\|paused\|active"}` | Exactly one state is `1` |
| | `tailstate_notifications_paused` | `1` when a configured installation has no destination or every destination is disabled |
| | `tailstate_notification_destinations`, `tailstate_notification_destinations_enabled` | Notification destination totals and enabled counts |
| Delivery queue | `tailstate_outbox_pending`, `tailstate_outbox_processing`, `tailstate_outbox_dead` | Pending, in-flight (leased), and dead-lettered notifications |
| Delivery telemetry | `tailstate_outbox_delivery_attempts_total`, `tailstate_outbox_delivery_success_total`, `tailstate_outbox_delivery_failure_total` | Delivery attempts, successes, and failures |
| | `tailstate_outbox_lease_renewals_total`, `tailstate_outbox_lease_renewal_failures_total`, `tailstate_outbox_lease_losses_total` | Delivery lease renewals, renewal failures, and leases lost before completion |
| | `tailstate_outbox_delivery_duration_seconds` | Histogram of delivery attempt duration |
| Collector health | `tailstate_collector_supported`, `tailstate_collector_baseline`, `tailstate_collector_partial`, `tailstate_collector_partial_errors`, `tailstate_collector_failures`, `tailstate_collector_poll_duration_seconds`, `tailstate_collector_last_success_timestamp_seconds`, `tailstate_collector_next_poll_timestamp_seconds` (all `{collector=...}`) | Per-collector support, baseline, partial-result state, partial error count, consecutive failures, last poll duration, last success, and next poll time |
| | `tailstate_collector_due_errors_total` | The scheduler's total database-error counter while selecting due collectors |
| | `tailstate_resources{collector=...}` | Resources in the current baseline |
| Webhooks | `tailstate_webhook_triggers_pending`, `tailstate_webhook_triggers_processing`, `tailstate_webhook_triggers_dead` | Verified webhook triggers waiting, being reconciled, or past their retry window |
| | `tailstate_webhook_requests_total{outcome=...}` | Webhook requests by outcome (see [webhooks](monitoring.md#faster-reconciliation-with-tailscale-webhooks)) |
| Change attribution | `tailstate_attribution_lookups_total{outcome=...}`, `tailstate_attribution_changes_total{result=...}` | Audit log lookups and attributed changes (see [Change attribution](monitoring.md#change-attribution)) |
| Storage size | `tailstate_storage_bytes`, `tailstate_storage_used_bytes`, `tailstate_storage_freelist_pages`, `tailstate_storage_free_bytes`, `tailstate_storage_pressure_ratio` | Allocated and used database size, free pages and their bytes, and the used-bytes pressure ratio (see [Storage limits](operations.md#storage-limits)) |
| Storage limits | `tailstate_storage_limit_bytes`, `tailstate_storage_enforced_limit_bytes`, `tailstate_storage_limit_enforced` | Configured database budget; the page ceiling SQLite is actually enforcing; `tailstate_storage_limit_enforced` drops to `0` if the active ceiling ever exceeds the configured budget |
| | `tailstate_snapshot_limit_bytes`, `tailstate_event_value_limit_bytes`, `tailstate_history_page_limit_bytes`, `tailstate_reject_limit_bytes` | Configured snapshot, event, history, and rejection limits |
| Physical files | `tailstate_storage_database_file_bytes`, `tailstate_storage_wal_bytes`, `tailstate_storage_shm_bytes`, `tailstate_storage_physical_bytes` | Observed physical sizes (see [WAL and read concurrency](operations.md#wal-and-read-concurrency)) |
| Truncation | `tailstate_snapshot_truncations_total`, `tailstate_event_value_truncations_total`, `tailstate_history_page_truncations_total`, `tailstate_oversized_writes_rejected_total` | Snapshot truncation, event-value truncation, history-page truncation, and oversized raw writes represented by a metadata marker |
| Retention cleanup | `tailstate_cleanup_runs_total`, `tailstate_cleanup_failures_total`, `tailstate_cleanup_remaining`, `tailstate_cleanup_remaining_passes_total`, `tailstate_cleanup_transactions_total`, `tailstate_cleanup_duration_seconds`, `tailstate_cleanup_rows_total{table=...}` | Retention cleanup progress (see [Retention cleanup](operations.md#retention-cleanup)) |
| Sign-in forms | `tailstate_credential_challenge_total{action=...,outcome=...}`, `tailstate_credential_rejections_total{action=...}` | Credential form challenge outcomes and rejected submissions (see [Credential forms and throttling](security.md#credential-forms-and-throttling)) |

These signals make storage pressure visible without exposing destination URLs, provider bodies, or message contents. Every metric family carries `# HELP` and `# TYPE` lines (the exposition passes `promtool check metrics`), and the response is rendered in full before it is sent: if a store query fails, the scrape receives a clean `500` rather than a partial `200` body.

## Alerting

TailState's own notifications cannot tell you that notification delivery is
broken, so alert on `/metrics` from an independent Prometheus.
[`prometheus/alerts.yml`](prometheus/alerts.yml) contains example rules,
validated in CI with `promtool check rules`:

| Alert | Fires when |
| --- | --- |
| `TailStateNotificationsDeadLettered` | `tailstate_outbox_dead > 0`: a destination missed a notification |
| `TailStateNotificationsStuck` | Notifications are pending but none was delivered for an hour |
| `TailStateNotificationsPaused`, `TailStateNoNotificationDestinations` | Every destination is disabled, or none exists |
| `TailStateNotReady`, `TailStateBaselineDegraded` | Setup or the first baseline is incomplete, or readiness is degraded |
| `TailStateCollectorFailing` | A supported collector has failed three or more consecutive polls |
| `TailStateCollectorPollOverdue`, `TailStateSchedulerDatabaseErrors` | The scheduler is behind or cannot read due collectors |
| `TailStateWebhookTriggersDead` | Webhook triggers exhausted their retry window |
| `TailStateAttributionLookupsFailing` | Audit log lookups keep failing, so changes show "actor unknown" |
| `TailStateStoragePressureHigh`, `TailStateStoragePressureCritical` | Used database bytes exceed 80% or 95% of the budget |
| `TailStateStorageLimitNotEnforced` | `tailstate_storage_limit_enforced == 0`: the database needs compaction |
| `TailStateRetentionCleanupFailing` | Retention cleanup keeps failing |

Load the file with `rule_files` in `prometheus.yml`, scrape TailState with its
bearer token, and tune thresholds and `for` durations to your polling
intervals. A minimal scrape job:

```yaml
scrape_configs:
  - job_name: tailstate
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/tailstate_metrics_token
    static_configs:
      - targets: ["tailstate.example.com"]
```

Also alert on the scrape itself (for example `up{job="tailstate"} == 0`),
because none of these rules fire when Prometheus cannot reach TailState.
