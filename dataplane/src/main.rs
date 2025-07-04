// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod packet_processor;
mod statistics;  // Add statistics module

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
use tokio::{io, spawn};

use crate::packet_processor::start_router;
use mgmt::processor::launch::start_mgmt;
use routing::RouterParamsBuilder;

// Import statistics functions
use crate::statistics::start_metrics_server;

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
    let (builder, router, vpcmapw) = match start_router(config) {
        Ok((router, pipeline, vpcmapw)) => (move || pipeline, router, vpcmapw),
        Err(e) => {
            error!("Failed to start router: {e}");
            panic!("Failed to start router: {e}");
        }
    };
    let router_ctl = router.get_ctl_tx();
    let frr_agent_path = router.get_frr_agent_path().to_str().unwrap();

    /* start management */
    if let Err(e) = start_mgmt(grpc_addr, router_ctl, frr_agent_path, vpcmapw) {
        error!("Failed to start gRPC server: {e}");
        panic!("Failed to start gRPC server: {e}");
    } else {
        info!("Management gRPC server started successfully");
    }

  // Start metrics server early in the process
  let metrics_port = args.metrics_port().unwrap_or(9090);
  let _metrics_handle = match start_metrics_server(metrics_port) {
      Ok(handle) => {
          info!("Metrics server started on http://0.0.0.0:{}/metrics", metrics_port);
          Some(handle)
      }
      Err(e) => {
          error!("Failed to start metrics server: {}", e);
          warn!("Continuing without metrics...");
          None
      }
  };


    /* start driver with the provided pipeline */
    match args.get_driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            DriverDpdk::start(args.eal_params(), &setup_pipeline);
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(args.kernel_params(), builder);
        }
        other => {
            error!("Unknown driver '{other}'. Aborting...");
            panic!("Packet processing pipeline failed to start. Aborting...");
        }
    }

    info!("All components started successfully. Gateway is running.");
    if let Some(_) = _metrics_handle {
        info!("Metrics available at http://0.0.0.0:{}/metrics", metrics_port);

    }

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
