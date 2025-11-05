// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use axum::{Router, response::Response, routing::get};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::StatsCollector;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio_util::{future::FutureExt, sync::CancellationToken};
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
    handle: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

impl MetricsServer {
    // TODO: convert to scoped thread
    #[tracing::instrument(level = "info", skip(stats))]
    pub fn new(addr: std::net::SocketAddr, stats: StatsCollector) -> Self {
        MetricsServer {
            cancel: stats.cancel_token(),
            handle: Some(
                std::thread::Builder::new()
                    .name("metrics-server".to_string())
                    .spawn(move || {
                        info!("Starting metrics server thread");

                        // create tokio runtime
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_io()
                            .enable_time()
                            .max_blocking_threads(32)
                            .on_thread_stop(|| unsafe {
                                dpdk::lcore::ServiceThread::unregister_current_thread();
                            })
                            .build()
                            .expect("runtime creation failed for metrics server");

                        // block thread to run metrics HTTP server
                        rt.block_on(Self::run(addr, stats));
                        rt.shutdown_timeout(Duration::from_secs(3));
                    })
                    .unwrap(),
            ),
        }
    }

    #[tracing::instrument(level = "info", skip(stats))]
    async fn run(addr: std::net::SocketAddr, stats: StatsCollector) {
        let PrometheusHandler { handle } = PrometheusHandler::new();

        let upkeep_handle = handle.clone();
        let tick = tokio::spawn({
            let cancel_token = stats.cancel_token();
            async move {
                // average prometheus scraper is between 15 and 60 secs,
                // so run upkeep every 30 secs is a reasonable default
                let mut ticker = tokio::time::interval(Duration::from_secs(30));
                // run_upkeep is synchronous; call it periodically.
                loop {
                    upkeep_handle.run_upkeep();
                    tokio::select! {
                        _ = ticker.tick() => {}
                        () = cancel_token.cancelled() => break,
                    }
                }
                upkeep_handle.run_upkeep();
            }
        });
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(handle);
        let server_cancel_token = stats.cancel_token();
        let server = axum_server::bind(addr)
            .serve(app.into_make_service())
            .with_cancellation_token(&server_cancel_token);
        info!("metrics server listening on {}", addr);

        match tokio::join!(server, tick, stats.run()) {
            (Some(Err(e)), _, ()) => {
                error!("error in stats server shutdown: {e}");
                panic!("error in stats server shutdown: {e}");
            }
            (_, Err(e), ()) => {
                error!("error in stats tick server shutdown: {e}");
                panic!("error in stats tick server shutdown: {e}");
            }
            (_, _, ()) => {
                info!("stats task shutdown");
            }
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        info!("shutting down metrics server");
        self.cancel.cancel();
        self.handle
            .take()
            .map(std::thread::JoinHandle::join)
            .unwrap()
            .unwrap();
        info!("metrics server shut down");
    }
}
