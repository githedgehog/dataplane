// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use opentelemetry::KeyValue;
use opentelemetry::logs::LoggerProvider;
use opentelemetry::trace::TracerProvider;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{BatchLogProcessor, SdkLoggerProvider};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    RandomIdGenerator, Sampler, SdkTracerProvider, TracerProviderBuilder,
};
use std::time::Duration;
use tracing::{error, info, span, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

fn test_name<F: Fn() -> T, T>(f: F) -> &'static str {
    std::any::type_name::<F>()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint("http://127.0.0.1:4317")
        .with_timeout(Duration::from_secs(3))
        .build()?;
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_max_events_per_span(1024)
        .with_max_attributes_per_span(1024)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([KeyValue::new("service.name", test_name(main))])
                .build(),
        )
        .build();
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let tracer = provider.tracer("main_example");
    let log_exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint("http://127.0.0.1:4317")
        .with_timeout(Duration::from_secs(3))
        .build()?;
    let log_provider = SdkLoggerProvider::builder()
        .with_log_processor(BatchLogProcessor::builder(log_exporter).build())
        .with_resource(
            Resource::builder_empty()
                .with_attributes([KeyValue::new("service.name", test_name(main))])
                .build(),
        )
        .build();
    log_provider.logger("main_example");
    // let filter_otel = EnvFilter::new("info")
    //     .add_directive("hyper=off".parse().unwrap())
    //     .add_directive("opentelemetry=off".parse().unwrap())
    //     .add_directive("tonic=off".parse().unwrap())
    //     .add_directive("h2=off".parse().unwrap())
    //     .add_directive("reqwest=off".parse().unwrap());
    let layer2 = OpenTelemetryTracingBridge::new(&log_provider);

    let telemetry = tracing_opentelemetry::layer()
        .with_level(true)
        .with_threads(true)
        .with_location(true)
        .with_tracer(tracer);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::CLOSE)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(true)
        .with_ansi(true)
        .with_thread_names(true)
        .with_test_writer();

    // Use the tracing subscriber `Registry`, or any other subscriber
    // that impls `LookupSpan`
    let subscriber = Registry::default()
        .with(fmt_layer)
        .with(telemetry)
        .with(layer2);
    // Trace executed code
    tracing::subscriber::with_default(subscriber, || {
        // Spans will be sent to the configured OpenTelemetry exporter
        for _ in 0..100 {
            let root = span!(tracing::Level::INFO, "app_start", work_units = 2);
            let _enter = root.enter();

            info!("science is a verb now!");
            do_stuff(22);
            error!(biscuit = 19, "This event will be logged in the root span.");
            do_stuff(1);
            do_stuff(7);
            warn!(biscuit = 27, "This event will be logged in the root span.");
            do_stuff(17);
        }
    });

    Ok(())
}

#[tracing::instrument(level = "info")]
fn do_stuff(arg: i32) {
    info!(arg = arg, "doing some stuff");
}
