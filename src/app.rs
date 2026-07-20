use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::Rng;
use serde_json::json;
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::{
    config::{Config, duration},
    destinations::Sender,
    event::{Event, Severity},
    storage::Store,
    tailscale::TailscaleClient,
    webhook,
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    store: Store,
    ready: Arc<AtomicBool>,
    source_health: Arc<Mutex<HashMap<String, bool>>>,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct Metrics {
    webhooks_received: AtomicU64,
    events_created: AtomicU64,
    deliveries_succeeded: AtomicU64,
    deliveries_failed: AtomicU64,
    collector_failures: AtomicU64,
}

pub async fn run(config: Config) -> Result<()> {
    let store = Store::open(&config.storage.path)?;
    let ready = Arc::new(AtomicBool::new(!config.tailscale.polling_enabled));
    let source_health = Arc::new(Mutex::new(HashMap::new()));
    let state = AppState {
        config: Arc::new(config),
        store,
        ready,
        source_health,
        metrics: Arc::new(Metrics::default()),
    };

    if state.config.tailscale.polling_enabled {
        let client = TailscaleClient::new(&state.config.tailscale)?;
        initial_sync(&state, &client).await?;
        spawn_pollers(state.clone(), client);
    } else if !state.store.is_baseline_complete()? {
        enqueue_started(&state, BTreeMap::new())?;
        state.store.set_baseline_complete()?;
    }
    spawn_delivery_worker(state.clone())?;
    spawn_cleanup_worker(state.clone());

    let router = Router::new()
        .route("/webhooks/tailscale", post(webhook_handler))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind(state.config.server.listen)
        .await
        .with_context(|| format!("bind {}", state.config.server.listen))?;
    info!(address=%state.config.server.listen, "TailState is listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn initial_sync(state: &AppState, client: &TailscaleClient) -> Result<()> {
    let first_baseline = !state.store.is_baseline_complete()?;
    if first_baseline {
        state.store.reset_incomplete_baseline()?;
    }
    let mut counts = BTreeMap::new();
    for collector in &state.config.tailscale.collectors {
        let items = client
            .collect(collector)
            .await
            .with_context(|| format!("initial collector {collector} failed"))?;
        let (count, events) = state.store.apply_snapshot(
            collector,
            items,
            &state.config.tailscale.tailnet,
            &state.config.destinations,
        )?;
        state
            .metrics
            .events_created
            .fetch_add(events.len() as u64, Ordering::Relaxed);
        counts.insert(collector.clone(), count);
        state
            .source_health
            .lock()
            .await
            .insert(collector.clone(), true);
    }
    if first_baseline {
        enqueue_started(state, counts)?;
        state.store.set_baseline_complete()?;
    }
    state.ready.store(true, Ordering::Release);
    Ok(())
}

fn enqueue_started(state: &AppState, counts: BTreeMap<String, usize>) -> Result<()> {
    let total: usize = counts.values().sum();
    let mut event = Event::new(
        &state.config.tailscale.tailnet,
        "system",
        "tailstate.baseline_ready",
        "system",
        "TailState",
        format!(
            "TailState baseline is ready: {total} resources across {} collectors",
            counts.len()
        ),
    );
    event
        .metadata
        .insert("collectors".into(), serde_json::to_value(counts)?);
    state.store.enqueue_event(
        &event,
        Some("system:baseline_ready"),
        &state.config.destinations,
    )?;
    state.metrics.events_created.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn spawn_pollers(state: AppState, client: TailscaleClient) {
    let mut schedules = BTreeMap::<u64, Vec<String>>::new();
    for collector in &state.config.tailscale.collectors {
        let default = if matches!(collector.as_str(), "devices" | "users") {
            state.config.tailscale.core_interval_seconds
        } else {
            state.config.tailscale.secondary_interval_seconds
        };
        let interval = state
            .config
            .tailscale
            .collector_intervals_seconds
            .get(collector)
            .copied()
            .unwrap_or(default);
        schedules
            .entry(interval)
            .or_default()
            .push(collector.clone());
    }
    for (interval, collectors) in schedules {
        tokio::spawn(poll_loop(
            state.clone(),
            client.clone(),
            collectors,
            interval,
        ));
    }
}

async fn poll_loop(
    state: AppState,
    client: TailscaleClient,
    collectors: Vec<String>,
    interval: u64,
) {
    let jitter = if state.config.tailscale.startup_jitter_seconds == 0 {
        0
    } else {
        rand::rng().random_range(0..=state.config.tailscale.startup_jitter_seconds)
    };
    tokio::time::sleep(Duration::from_secs(jitter)).await;
    let mut timer = tokio::time::interval(duration(interval));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        for collector in &collectors {
            match client.collect(collector).await.and_then(|items| {
                state.store.apply_snapshot(
                    collector,
                    items,
                    &state.config.tailscale.tailnet,
                    &state.config.destinations,
                )
            }) {
                Ok((_, events)) => {
                    state
                        .metrics
                        .events_created
                        .fetch_add(events.len() as u64, Ordering::Relaxed);
                    set_source_health(&state, collector, true).await;
                }
                Err(error) => {
                    warn!(collector, error=%error, "collector failed");
                    state
                        .metrics
                        .collector_failures
                        .fetch_add(1, Ordering::Relaxed);
                    set_source_health(&state, collector, false).await;
                }
            }
        }
    }
}

async fn set_source_health(state: &AppState, collector: &str, healthy: bool) {
    let mut health = state.source_health.lock().await;
    let previous = health.insert(collector.into(), healthy);
    state
        .ready
        .store(health.values().all(|v| *v), Ordering::Release);
    if previous == Some(healthy) {
        return;
    }
    let event_type = if healthy {
        "tailstate.source_recovered"
    } else {
        "tailstate.source_unhealthy"
    };
    let mut event = Event::new(
        &state.config.tailscale.tailnet,
        "system",
        event_type,
        "system",
        collector,
        format!(
            "Tailscale collector {collector} is {}",
            if healthy {
                "healthy again"
            } else {
                "unhealthy"
            }
        ),
    );
    event.severity = if healthy {
        Severity::Info
    } else {
        Severity::Warning
    };
    if let Err(error) = state
        .store
        .enqueue_event(&event, None, &state.config.destinations)
    {
        error!(%error, "failed to enqueue health event");
    }
}

fn spawn_delivery_worker(state: AppState) -> Result<()> {
    let sender = Sender::new(state.config.tailscale.request_timeout_seconds)?;
    tokio::spawn(async move {
        let mut timer =
            tokio::time::interval(duration(state.config.delivery.poll_interval_seconds));
        loop {
            timer.tick().await;
            let items = match state.store.due_outbox(50) {
                Ok(items) => items,
                Err(error) => {
                    error!(%error, "load outbox failed");
                    continue;
                }
            };
            for item in items {
                let Some(destination) = state
                    .config
                    .destinations
                    .iter()
                    .find(|d| d.name == item.destination && d.enabled)
                else {
                    if let Err(error) =
                        state
                            .store
                            .delivery_failed(&item, "destination missing or disabled", 0, 1)
                    {
                        error!(%error, "mark delivery dead failed");
                    }
                    continue;
                };
                match sender.send(destination, &item.event).await {
                    Ok(()) => {
                        if let Err(error) = state.store.delivery_succeeded(item.id) {
                            error!(%error, "mark delivery complete failed");
                        }
                        state
                            .metrics
                            .deliveries_succeeded
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        warn!(destination=%item.destination, error=%error, "notification delivery failed");
                        state
                            .metrics
                            .deliveries_failed
                            .fetch_add(1, Ordering::Relaxed);
                        match state.store.delivery_failed(
                            &item,
                            &error.to_string(),
                            state.config.delivery.retry_horizon_seconds,
                            state.config.delivery.max_attempts,
                        ) {
                            Ok(true) => {
                                error!(destination=%item.destination, event_id=%item.event.id, "notification moved to dead letter")
                            }
                            Ok(false) => {}
                            Err(store_error) => {
                                error!(%store_error, "record delivery failure failed")
                            }
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

fn spawn_cleanup_worker(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            if let Err(error) = state.store.cleanup(state.config.storage.retention_days) {
                error!(%error, "retention cleanup failed");
            }
        }
    });
}

async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.config.tailscale.webhook_enabled {
        return (StatusCode::NOT_FOUND, "webhook ingestion disabled").into_response();
    }
    let secret = state
        .config
        .tailscale
        .webhook_secret
        .as_deref()
        .expect("validated webhook secret");
    match webhook::verify_and_parse(
        &headers,
        &body,
        secret,
        state.config.server.replay_window_seconds,
    ) {
        Ok(events) => {
            state
                .metrics
                .webhooks_received
                .fetch_add(events.len() as u64, Ordering::Relaxed);
            let mut accepted = 0;
            for (event, key) in events {
                match state
                    .store
                    .enqueue_event(&event, Some(&key), &state.config.destinations)
                {
                    Ok(true) => {
                        accepted += 1;
                        state.metrics.events_created.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
                            .into_response();
                    }
                }
            }
            (StatusCode::OK, axum::Json(json!({"accepted":accepted}))).into_response()
        }
        Err(error) => (StatusCode::UNAUTHORIZED, error.to_string()).into_response(),
    }
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(json!({"status":"ok"})))
}
async fn readiness(State(state): State<AppState>) -> Response {
    let stats = match state.store.stats() {
        Ok(v) => v,
        Err(error) => return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    };
    let ready = state.ready.load(Ordering::Acquire);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(
            json!({"ready":ready,"storage":stats,"sources":*state.source_health.lock().await}),
        ),
    )
        .into_response()
}
async fn metrics(State(state): State<AppState>) -> Response {
    let stats = match state.store.stats() {
        Ok(v) => v,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let m = &state.metrics;
    let body = format!(
        concat!(
            "# TYPE tailstate_webhooks_received_total counter\ntailstate_webhooks_received_total {}\n",
            "# TYPE tailstate_events_created_total counter\ntailstate_events_created_total {}\n",
            "# TYPE tailstate_deliveries_succeeded_total counter\ntailstate_deliveries_succeeded_total {}\n",
            "# TYPE tailstate_deliveries_failed_total counter\ntailstate_deliveries_failed_total {}\n",
            "# TYPE tailstate_collector_failures_total counter\ntailstate_collector_failures_total {}\n",
            "# TYPE tailstate_outbox_pending gauge\ntailstate_outbox_pending {}\n",
            "# TYPE tailstate_outbox_dead gauge\ntailstate_outbox_dead {}\n"
        ),
        m.webhooks_received.load(Ordering::Relaxed),
        m.events_created.load(Ordering::Relaxed),
        m.deliveries_succeeded.load(Ordering::Relaxed),
        m.deliveries_failed.load(Ordering::Relaxed),
        m.collector_failures.load(Ordering::Relaxed),
        stats.pending,
        stats.dead
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler")
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
    info!("shutdown requested");
}
