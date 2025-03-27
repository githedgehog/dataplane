// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod nat;

use crate::args::{CmdArgs, Parser};
use drivers::dpdk::DriverDpdk;
use drivers::kernel::DriverKernel;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
use tracing::{error, info};

fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
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
            std::process::exit(0);
        }
    }

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
