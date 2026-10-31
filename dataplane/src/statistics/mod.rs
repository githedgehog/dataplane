// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod telemetry;

pub(crate) use telemetry::TelemetrySources;

use axum::{Router, response::Response, routing::get};
use concurrency::sync::{Arc, Mutex};
use lifecycle::Subsystem;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use stats::StatsCollector;
use std::time::Duration;
use tracing::{error, info};

use tracectl::trace_target;
trace_target!("stats-server", LevelFilter::INFO, &[]);

/// What the `/metrics` endpoint renders: the exporter, and the counts it publishes first.
#[derive(Clone)]
pub struct PrometheusHandler {
    handle: PrometheusHandle,
    rate_limits: rate_limit::RateLimitReader<rate_limit::PeeringRules>,
    telemetry: Arc<Mutex<telemetry::Telemetry>>,
}

impl PrometheusHandler {
    pub(crate) fn new(
        rate_limits: rate_limit::RateLimitReader<rate_limit::PeeringRules>,
        telemetry: TelemetrySources,
    ) -> Self {
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
            rate_limits,
            // Registered after the recorder is installed, or the series would go nowhere.
            telemetry: Arc::new(Mutex::new(telemetry::Telemetry::new(telemetry))),
        }
    }
}

/// HTTP handler for /metrics endpoint
///
/// Publishes the rate limits', the pipeline's and the workers' counts as they stand before
/// rendering, so a scrape sees them as of the scrape -- the workers' as of the supervisor's last
/// poll -- and nothing polls them between scrapes.
async fn metrics_handler(
    axum::extract::State(handler): axum::extract::State<PrometheusHandler>,
) -> Response<String> {
    handler.rate_limits.load().publish_metrics();
    handler.telemetry.lock().publish();
    Response::builder()
        .header("Content-Type", "text/plain; version=1.0.0; charset=utf-8")
        .body(handler.handle.render())
        .unwrap()
}

/// Spawn the `/metrics` endpoint on `addr`, publishing `telemetry` as each scrape comes, a 30s
/// upkeep ticker, and the stats collector onto `handle`, tracked under `metrics`. Uses
/// [`Subsystem::spawn_on`] — a dead metrics endpoint should not take down
/// the dataplane.
pub(crate) fn spawn_metrics(
    metrics: &Subsystem,
    handle: &tokio::runtime::Handle,
    addr: std::net::SocketAddr,
    stats: StatsCollector,
    rate_limits: rate_limit::RateLimitReader<rate_limit::PeeringRules>,
    telemetry: TelemetrySources,
) {
    let handler = PrometheusHandler::new(rate_limits, telemetry);

    let upkeep_handle = handler.handle.clone();
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
                .with_state(handler);

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
