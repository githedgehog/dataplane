// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use axum::{Router, response::Response, routing::get};
use lifecycle::Subsystem;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::StatsCollector;
use std::time::Duration;
use tracing::{error, info};

use tracectl::trace_target;
trace_target!("stats-server", LevelFilter::INFO, &[]);

/// Simple Prometheus metrics handler
pub struct PrometheusHandler {
    handle: PrometheusHandle,
}

impl PrometheusHandler {
    pub fn new() -> Self {
        let prometheus_handle = PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full("http_request_duration_seconds".to_string()),
                &[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
            )
            .unwrap()
            .install_recorder()
            .unwrap();

        Self {
            handle: prometheus_handle,
        }
    }
}

/// HTTP handler for /metrics endpoint
async fn metrics_handler(
    axum::extract::State(handler): axum::extract::State<PrometheusHandle>,
) -> Response<String> {
    Response::builder()
        .header("Content-Type", "text/plain; version=1.0.0; charset=utf-8")
        .body(handler.render())
        .unwrap()
}

/// Spawn the `/metrics` endpoint on `addr`, a 30s upkeep ticker, and the
/// stats collector onto `handle`, tracked under `metrics`. Uses
/// [`Subsystem::spawn_on`] — a dead metrics endpoint should not take down
/// the dataplane.
pub fn spawn_metrics(
    metrics: &Subsystem,
    handle: &tokio::runtime::Handle,
    addr: std::net::SocketAddr,
    stats: StatsCollector,
) {
    let PrometheusHandler {
        handle: prom_handle,
    } = PrometheusHandler::new();

    let upkeep_handle = prom_handle.clone();
    let upkeep_cancel = metrics.cancel_token();
    metrics.spawn_on(
        async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    () = upkeep_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        upkeep_handle.run_upkeep();
                    }
                }
            }
        },
        handle,
    );

    let stats_cancel = metrics.cancel_token();
    metrics.spawn_on(
        async move {
            tokio::select! {
                () = stats_cancel.cancelled() => {}
                () = stats.run() => {}
            }
        },
        handle,
    );

    let server_cancel = metrics.cancel_token();
    metrics.spawn_on(
        async move {
            let app = Router::new()
                .route("/metrics", get(metrics_handler))
                .with_state(prom_handle);

            info!("metrics server listening on {}", addr);

            tokio::select! {
                () = server_cancel.cancelled() => {
                    info!("metrics server shutdown requested");
                }
                res = axum_server::bind(addr).serve(app.into_make_service()) => {
                    if let Err(e) = res {
                        error!("metrics server error: {}", e);
                    }
                }
            }
        },
        handle,
    );
}
