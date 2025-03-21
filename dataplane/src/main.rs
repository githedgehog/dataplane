// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

use crate::args::CmdArgs;
use clap::Parser;
use tracing::{error, info};

mod args;
mod drivers;
mod nat;

use drivers::Driver;
use drivers::dpdk::DriverDpdk;
use net::buffer::PacketBufferMut;

use dpdk::mem::Mbuf;
use pipeline::DynPipeline;

use pipeline::sample_nfs::Passthrough;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();
}

// Returns a driver object depending on the cmd line arg --driver
fn get_driver<Buf: PacketBufferMut>(args: &CmdArgs) -> Option<impl Driver<Buf>>
where
    DriverDpdk: Driver<Buf>,
{
    match args.get_driver_name() {
        "dpdk" => Some(DriverDpdk),
        "kernel" => None,
        other => {
            error!("Unknown driver '{other}'");
            None
        }
    }
}

fn setup_pipeline() -> DynPipeline<Mbuf> {
    let pipeline = DynPipeline::new();

    pipeline.add_stage(Passthrough)
}

fn main() {
    init_logging();
    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    /* build the pipeline to use, common to any driver */
    let pipeline = setup_pipeline();

    /* parse cmd line args */
    let args = CmdArgs::parse();

    /* start driver */
    if let Some(driver) = get_driver(&args) {
        info!("Using driver '{}'", driver.name());
        let env = driver.init_driver(driver.get_args(&args));
        let devices = driver.init_devs(&env);
        driver.start(&devices, pipeline);
    } else {
        error!("Shutting down ...");
        std::process::exit(0);
    }

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}
