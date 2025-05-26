use opentelemetry::logs::LoggerProvider;
use opentelemetry::trace::TracerProvider;
use opentelemetry::{KeyValue, global, trace::Tracer};
use opentelemetry_otlp::{LogExporter, SpanExporter};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{BatchLogProcessor, SdkLoggerProvider};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use std::time::Duration;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::service::LayerExt;
use tracing::{Level, info};
use tracing::{error, span};
use tracing_loki::url::Url;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[tokio::test(flavor = "multi_thread")]
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
        .with_max_events_per_span(64)
        .with_max_attributes_per_span(16)
        .with_resource(
            Resource::builder_empty()
                .with_attributes([KeyValue::new("service.name", "science")])
                .build(),
        )
        .build();
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
                .with_attributes([KeyValue::new("service.name", "science")])
                .build(),
        )
        .build();
    log_provider.logger("main_example");
    let filter_otel = EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("opentelemetry=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());
    let layer2 =
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&log_provider);

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let fmt_layer = tracing_subscriber::fmt::layer().with_thread_names(true);

    // Use the tracing subscriber `Registry`, or any other subscriber
    // that impls `LookupSpan`
    let subscriber = Registry::default().with(telemetry).with(fmt_layer);
    // Trace executed code
    tracing::subscriber::with_default(subscriber, || {
        // Spans will be sent to the configured OpenTelemetry exporter
        let root = span!(tracing::Level::INFO, "app_start", work_units = 2);
        let _enter = root.enter();

        println!("stuff");

        info!("science is a verb now!");

        error!("This event will be logged in the root span.");

        println!("more_stuff");
    });

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn bix() {
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
        .build();
    let tracer = provider.tracer("readme_example");

    // Create a tracing layer with the configured tracer
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Use the tracing subscriber `Registry`, or any other subscriber
    // that impls `LookupSpan`
    let subscriber = Registry::default().with(telemetry);

    // Trace executed code
    tracing::subscriber::with_default(subscriber, || {
        // Spans will be sent to the configured OpenTelemetry exporter
        let root = span!(tracing::Level::TRACE, "app_start", work_units = 2);
        let _enter = root.enter();

        error!("This event will be logged in the root span.");
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn log_to_loki() {
    let (layer, task) = tracing_loki::builder()
        .label("host", "mine")
        .unwrap()
        .extra_field("pid", format!("{}", std::process::id()))
        .unwrap()
        .build_url(Url::parse("http://localhost:3100/loki").unwrap())
        .unwrap();

    // We need to register our layer with `tracing`.
    tracing_subscriber::registry()
        .with(layer)
        // One could add more layers here, for example logging to stdout:
        // .with(tracing_subscriber::fmt::Layer::new())
        .init();

    // The background task needs to be spawned so the logs actually get
    // delivered.
    tokio::spawn(task);

    error!(
        task = "tracing_setup",
        result = "success",
        "tracing successfully set up",
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[test]
fn main2() {
    tracing_subscriber::fmt()
        .json()
        .with_line_number(true)
        .with_file(true)
        .with_test_writer()
        .with_level(false)
        .with_thread_ids(false)
        .with_target(false)
        .without_time()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_max_level(Level::TRACE)
        .compact()
        .init();

    let number_of_yaks = 3;
    // this creates a new event, outside of any spans.
    info!(number_of_yaks, "preparing to shave yaks");

    info!(all_yaks_shaved = 17, "yak shaving completed");
}
