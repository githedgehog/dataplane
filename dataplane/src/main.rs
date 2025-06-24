// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod packet_processor;

use crate::args::{CmdArgs, Parser};
use drivers::dpdk::DriverDpdk;
use drivers::kernel::DriverKernel;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
#[allow(unused)]
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::packet_processor::start_router;
use mgmt::processor::launch::start_mgmt;
use routing::RouterParamsBuilder;

// Add metrics imports
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .with_env_filter(EnvFilter::new("debug,tonic=off,h2=off"))
        .init();
}

fn init_metrics(metrics_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    info!("Initializing Prometheus metrics on port {}", metrics_port);

    let builder = PrometheusBuilder::new();
    builder
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install()
        .map_err(|e| {
            error!("Failed to install Prometheus exporter: {}", e);
            e
        })?;

    // Describe core gateway metrics
    describe_counter!(
        "gateway_packets_processed_total",
        "Total packets processed by the gateway"
    );
    describe_counter!(
        "gateway_packets_dropped_total",
        "Total packets dropped by the gateway"
    );
    describe_counter!(
        "gateway_bytes_processed_total",
        "Total bytes processed by the gateway"
    );
    describe_counter!(
        "gateway_errors_total",
        "Total errors encountered by the gateway"
    );

    describe_gauge!("gateway_active_connections", "Number of active connections");
    describe_gauge!("gateway_memory_usage_bytes", "Memory usage in bytes");
    describe_gauge!("gateway_cpu_usage_percent", "CPU usage percentage");

    describe_histogram!(
        "gateway_packet_processing_duration_seconds",
        "Time to process packets"
    );
    describe_histogram!(
        "gateway_request_duration_seconds",
        "Time to handle requests"
    );

    // Desctribe interface metrics
    describe_counter!(
        "interface_packets_received_total",
        "Total packets received on interfaces"
    );
    describe_counter!(
        "interface_packets_transmitted_total",
        "Total packets transmitted on interfaces"
    );
    describe_counter!("interface_errors_total", "Total interface errors");

    // Driver-specific metrics
    describe_counter!(
        "driver_packets_received_total",
        "Total packets received by driver"
    );
    describe_counter!(
        "driver_packets_transmitted_total",
        "Total packets transmitted by driver"
    );
    describe_counter!("driver_errors_total", "Total driver errors");

    // Router-specific metrics
    describe_counter!("router_routes_learned_total", "Total routes learned");
    describe_counter!("router_routes_expired_total", "Total routes expired");
    describe_gauge!("router_active_routes", "Number of active routes");
    describe_gauge!("router_neighbor_count", "Number of active neighbors");

    // Management API metrics
    describe_counter!("mgmt_api_requests_total", "Total management API requests");
    describe_counter!("mgmt_api_errors_total", "Total management API errors");
    describe_histogram!(
        "mgmt_api_request_duration_seconds",
        "Management API request duration"
    );

    info!(
        "Prometheus metrics initialized successfully on http://0.0.0.0:{}/metrics",
        metrics_port
    );
    Ok(())
}

fn setup_pipeline<Buf: PacketBufferMut>() -> DynPipeline<Buf> {
    let pipeline = DynPipeline::new();
    if false {
        /* replace false by true to try filters and write your own */
        let custom_filter = |_packet: &Packet<Buf>| -> bool {
            /* your own filter here */
            true
        };
        pipeline.add_stage(PacketDumper::new(
            "default",
            true,
            Some(Box::new(custom_filter)),
        ))
    } else {
        pipeline.add_stage(PacketDumper::new("default", true, None))
    }
}

fn main() {
    init_logging();
    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    /* parse cmd line args */
    let args = CmdArgs::parse();

    let metrics_port = args.metrics_port().unwrap_or(9090);
    if let Err(e) = init_metrics(metrics_port) {
        error!("Failed to initialize metrics: {}", e);
        warn!("Continuing without metrics...");
    }

    let grpc_addr = match args.get_grpc_address() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid gRPC address configuration: {e}");
            panic!("Management service configuration error. Aborting...");
        }
    };

    /* router configuration */
    let Ok(config) = RouterParamsBuilder::default()
        .cli_sock_path(args.cli_sock_path())
        .cpi_sock_path(args.cpi_sock_path())
        .frr_agent_path(args.frr_agent_path())
        .build()
    else {
        error!("Bad router configuration");
        panic!("Bad router configuration");
    };

    /* start router and create routing pipeline */
    let (builder, router) = match start_router(config) {
        Ok((router, pipeline)) => {
            info!("Router started successfully");
            // Record router startup metric

            counter!("gateway_component_starts_total", "component" => "router").increment(1);
            (move || pipeline, router)
        }
        Err(e) => {
            error!("Failed to start router: {e}");
            counter!("gateway_errors_total", "component" => "router", "error" => "startup_failed")
                .increment(1);
            panic!("Failed to start router: {e}");
        }
    };
    let router_ctl = router.get_ctl_tx();
    let frr_agent_path = router.get_frr_agent_path().to_str().unwrap();

    /* start management */
    if let Err(e) = start_mgmt(grpc_addr, router_ctl, frr_agent_path) {
        error!("Failed to start gRPC server: {e}");
        counter!("gateway_errors_total", "component" => "mgmt", "error" => "startup_failed")
            .increment(1);
        panic!("Failed to start gRPC server: {e}");
    } else {
        info!("Management gRPC server started successfully");
        counter!("gateway_component_starts_total", "component" => "mgmt").increment(1);
    }

    /* start driver with the provided pipeline */
    match args.get_driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            counter!("gateway_component_starts_total", "component" => "driver", "type" => "dpdk")
                .increment(1);
            DriverDpdk::start(args.eal_params(), &setup_pipeline);
        }
        "kernel" => {
            info!("Using driver kernel...");
            counter!("gateway_component_starts_total", "component" => "driver", "type" => "kernel")
                .increment(1);
            DriverKernel::start(args.kernel_params(), builder);
        }
        other => {
            error!("Unknown driver '{other}'. Aborting...");
            counter!("gateway_errors_total", "component" => "driver", "error" => "unknown_driver")
                .increment(1);
            panic!("Packet processing pipeline failed to start. Aborting...");
        }
    }

    info!("All components started successfully. Gateway is running.");
    info!(
        "Metrics available at http://0.0.0.0:{}/metrics",
        metrics_port
    );

    // Record that gateway is fully operational
    gauge!("gateway_status", "state" => "running").set(1.0);

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");

    // Record shutdown metrics
    gauge!("gateway_status", "state" => "running").set(0.0);
    gauge!("gateway_status", "state" => "shutdown").set(1.0);

    std::process::exit(0);
}
