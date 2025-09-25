// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use axum::{Router, response::Response, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::StatsCollector;
use std::thread::JoinHandle;
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

#[derive(Debug)]
pub struct MetricsServer {
    #[allow(unused)] // temporary
    handle: JoinHandle<()>,
}

impl MetricsServer {
    // TODO: convert to scoped thread
    #[tracing::instrument(level = "info", skip(stats))]
    pub fn new(addr: std::net::SocketAddr, stats: StatsCollector) -> Self {
        MetricsServer {
            handle: std::thread::Builder::new()
                .name("metrics-server".to_string())
                .spawn(move || {
                    info!("Starting metrics server thread");

                    // create tokio runtime
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                        .expect("runtime creation failed for metrics server");

                    // block thread to run metrics HTTP server
                    rt.block_on(Self::run(addr, stats));
                })
                .unwrap(),
        }
    }

    #[tracing::instrument(level = "info", skip(stats))]
    async fn run(addr: std::net::SocketAddr, stats: StatsCollector) {
        let PrometheusHandler { handle } = PrometheusHandler::new();
        tokio::spawn(stats.run());
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(handle);

        info!("metrics server listening on {}", addr);

        if let Err(e) = axum_server::bind(addr).serve(app.into_make_service()).await {
            error!("metrics server error: {}", e);
        }
    }
}
