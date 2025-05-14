// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod nat;

use crate::args::{CmdArgs, GrpcAddress, Parser};
use drivers::dpdk::DriverDpdk;
use drivers::kernel::DriverKernel;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
use tracing::{debug, error, info};

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

use mgmt::processor::proc::{start_mgmt_tcp, start_mgmt_unix};
use tracing_subscriber::EnvFilter;

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
            error!("Invalid gRPC address configuration: {}", e);
            panic!("Management service configuration error. Aborting...");
        }
    };
    match grpc_addr {
        GrpcAddress::Tcp(addr) => {
            info!("Starting gRPC server on TCP address: {}", addr);
            if let Err(e) = start_mgmt_tcp(addr) {
                error!("Failed to start management service on TCP listener: {e}");
                panic!("Management service failed to start. Aborting...");
            }
        }
        GrpcAddress::UnixSocket(path) => {
            info!("Starting gRPC server on UNIX socket: {:?}", path);
            if let Err(e) = start_mgmt_unix(&path) {
                error!("Failed to start management service on UNIX socket: {e}");
                panic!("Management service failed to start. Aborting...");
            }
        }
    }

    debug!("Starting pipeline....");

    /* start driver */
    match args.get_driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            DriverDpdk::start(args.eal_params(), &setup_pipeline);
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(args.kernel_params(), &setup_pipeline);
        }
        other => {
            error!("Unknown driver '{other}'. Aborting...");
            panic!("Packet processing pipeline failed to start. Aborting...");
        }
    }

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
