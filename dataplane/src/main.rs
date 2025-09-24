// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod args;
mod drivers;
mod packet_processor;
mod statistics;

use crate::args::{CmdArgs, Parser};
use crate::packet_processor::start_router;
use crate::statistics::MetricsServer;

use drivers::dpdk::DriverDpdk;
use drivers::kernel::DriverKernel;

use mgmt::processor::launch::start_mgmt;

use net::buffer::PacketBufferMut;
use net::packet::Packet;

use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;

use routing::RouterParamsBuilder;
use tracectl::{custom_target, get_trace_ctl, trace_target};

use tracing::{error, info, level_filters::LevelFilter};

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
fn init_logging() {
    let tctl = get_trace_ctl();
    tctl.set_default_level(LevelFilter::DEBUG);
    custom_target!("tonic", LevelFilter::ERROR, &[]);
    custom_target!("h2", LevelFilter::ERROR, &[]);
}

fn setup_pipeline<Buf: PacketBufferMut>() -> DynPipeline<Buf> {
    let pipeline = DynPipeline::new();
    if false {
        let custom_filter = |_packet: &Packet<Buf>| -> bool { true };
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
    /* parse cmd line args */
    let args = CmdArgs::parse();
    if let Some(tracing) = args.tracing()
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    if args.show_tracing_tags() {
        get_trace_ctl().dump_targets_by_tag();
        std::process::exit(0);
    }
    if args.show_tracing_targets() {
        get_trace_ctl().dump();
        std::process::exit(0);
    }

    /* initialize logging */
    init_logging();
    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    let grpc_addr = match args.get_grpc_address() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid gRPC address configuration: {e}");
            panic!("Management service configuration error. Aborting...");
        }
    };

    /* router parameters */
    let Ok(config) = RouterParamsBuilder::default()
        .metrics_addr(args.metrics_address())
        .cli_sock_path(args.cli_sock_path())
        .cpi_sock_path(args.cpi_sock_path())
        .frr_agent_path(args.frr_agent_path())
        .build()
    else {
        error!("Bad router configuration");
        panic!("Bad router configuration");
    };

    // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
    let setup = start_router(config).expect("failed to start router");

    MetricsServer::new(args.metrics_address(), setup.stats);

    /* pipeline builder */
    let pipeline_factory = setup.pipeline;

    /* start management */
    start_mgmt(
        grpc_addr,
        setup.router.get_ctl_tx(),
        setup.nattablew,
        setup.natallocatorw,
        setup.vpcdtablesw,
        setup.vpcmapw,
    )
    .expect("Failed to start gRPC server");

    /* start driver with the provided pipeline builder */
    match args.get_driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            DriverDpdk::start(args.eal_params(), &setup_pipeline);
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(
                args.kernel_interfaces(),
                args.kernel_num_workers(),
                &pipeline_factory,
            );
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

#[cfg(test)]
mod test {
    use n_vm::in_vm;

    #[allow(unreachable_code, clippy::should_panic_without_expect)] // demo test to check vm functionality
    #[should_panic]
    #[test]
    #[in_vm]
    fn panic_in_vm_shows_as_test_failure() {
        panic!("this panic should be caught by the test framework and show as a test failure");
    }

    #[test]
    #[in_vm]
    fn root_filesystem_in_vm_is_read_only() {
        let error = std::fs::File::create_new("/some.file").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
    }

    #[test]
    #[in_vm]
    fn run_filesystem_in_vm_is_read_write() {
        std::fs::File::create_new("/run/some.file").unwrap();
    }

    #[test]
    #[in_vm]
    fn tmp_filesystem_in_vm_is_read_write() {
        std::fs::File::create_new("/tmp/some.file").unwrap();
    }
}
