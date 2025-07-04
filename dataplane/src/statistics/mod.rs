// src/statistics/mod.rs

use axum::{Router, http::StatusCode, response::Response, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::PacketStatsReader;
use std::sync::Arc;
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
    pub async fn render_metrics(&self) -> String {
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
    let metrics = handler.render_metrics().await;
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(metrics)
        .unwrap()
}

/// Start the metrics server
pub fn start_metrics_server(
    port: u16,
    statsr: PacketStatsReader,
) -> Result<(std::thread::JoinHandle<()>, Arc<PrometheusHandler>), Box<dyn std::error::Error>> {
    let prometheus_handler = Arc::new(PrometheusHandler::new(statsr)?);
    let handler_for_thread = prometheus_handler.clone();

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
                    .with_state(handler_for_thread.as_ref().clone());

                let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

                info!("Metrics server listening on {}", addr);

                if let Err(e) = axum_server::bind(addr).serve(app.into_make_service()).await {
                    error!("Metrics server error: {}", e);
                }
            });
        })?;

    Ok((handle, prometheus_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_handler() {
        let handler = PrometheusHandler::new().unwrap();

        // Update with test data
        let test_counters = vec![VpcCounters {
            name: "vpc-test".to_string(),
            rx: 100,
            tx: 50,
            rx_bytes: 15000,
            tx_bytes: 7500,
            drops: 5,
        }];

        handler.update_vpc_counters(test_counters).await;
        let metrics = handler.render_metrics().await;

        // Check that metrics contain our VPC data
        assert!(metrics.contains("vpc_packets_total"));
        assert!(metrics.contains("vpc_bytes_total"));
        assert!(metrics.contains("vpc_drops_total"));
        assert!(metrics.contains("vpc-test"));
    }
}
