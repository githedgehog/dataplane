// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use axum::{Router, http::StatusCode, response::Response, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::PacketStatsReader;
use tracing::{error, info};

pub mod global_counters;
use global_counters::sync_to_prometheus;

/// Simple Prometheus metrics handler
#[derive(Clone)]
pub struct PrometheusHandler {
    prometheus_handle: PrometheusHandle,
    statsr: PacketStatsReader,
}

impl PrometheusHandler {
    pub fn new(statsr: PacketStatsReader) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize metrics descriptions
        global_counters::init_metrics();

        // Create Prometheus exporter
        let prometheus_handle = PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full("http_request_duration_seconds".to_string()),
                &[
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ],
            )?
            .install_recorder()?;

        Ok(Self {
            prometheus_handle,
            statsr,
        })
    }

    /// Get the Prometheus metrics as a string
    pub fn render_metrics(&self) -> String {
        // Get current dataplane per-VPC counters and sync them to Prometheus
        if let Some(statsr) = self.statsr.enter() {
            sync_to_prometheus(&statsr);
        }
        // Render the metrics
        self.prometheus_handle.render()
    }
}

/// HTTP handler for /metrics endpoint
async fn metrics_handler(
    axum::extract::State(handler): axum::extract::State<PrometheusHandler>,
) -> Response<String> {
    let metrics = handler.render_metrics();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=1.0.0; charset=utf-8")
        .body(metrics)
        .unwrap()
}

/// Start the metrics server
pub fn start_metrics_server(
    addr: std::net::SocketAddr,
    statsr: PacketStatsReader,
) -> Result<std::thread::JoinHandle<()>, Box<dyn std::error::Error>> {
    let prometheus_handler = PrometheusHandler::new(statsr)?;

    let handle = std::thread::Builder::new()
        .name("metrics-server".to_string())
        .spawn(move || {
            info!("Starting metrics server thread");

            /* create tokio runtime */
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed for metrics server");

            /* block thread to run metrics HTTP server */
            rt.block_on(async {
                let app = Router::new()
                    .route("/metrics", get(metrics_handler))
                    .with_state(prometheus_handler);

                info!("Metrics server listening on {}", addr);

                if let Err(e) = axum_server::bind(addr).serve(app.into_make_service()).await {
                    error!("Metrics server error: {}", e);
                }
            });
        })?;

    Ok(handle)
}
