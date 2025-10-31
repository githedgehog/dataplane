// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod drivers;
mod packet_processor;
mod statistics;

use crate::packet_processor::start_router;
use crate::statistics::MetricsServer;
use args::{LaunchConfiguration, TracingConfigSection};

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
custom_target!("tonic", LevelFilter::ERROR, &[]);
custom_target!("h2", LevelFilter::ERROR, &[]);

fn init_logging() {
    let tctl = get_trace_ctl();
    tctl.set_default_level(LevelFilter::DEBUG)
        .expect("Setting default loglevel failed");
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

fn process_tracing_cmds(cfg: &TracingConfigSection) {
    if let Some(tracing) = &cfg.config
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    match cfg.show.tags {
        args::TracingDisplayOption::Hide => {}
        args::TracingDisplayOption::Show => {
            let out = get_trace_ctl()
                .as_string_by_tag()
                .unwrap_or_else(|e| e.to_string());
            println!("{out}");
            std::process::exit(0);
        }
    }
    if cfg.show.targets == args::TracingDisplayOption::Show {
        let out = get_trace_ctl()
            .as_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    // if args.tracing_config_generate() {
    //     let out = get_trace_ctl()
    //         .as_config_string()
    //         .unwrap_or_else(|e| e.to_string());
    //     println!("{out}");
    //     std::process::exit(0);
    // }
}

fn main() {
    let launch_config = LaunchConfiguration::inherit();
    init_logging();
    info!("launch config: {launch_config:?}");
    process_tracing_cmds(&launch_config.tracing);

    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    let grpc_addr = launch_config.config_server.address;

    /* router parameters */
    let config = match RouterParamsBuilder::default()
        .metrics_addr(launch_config.metrics.address)
        .cli_sock_path(launch_config.cli.cli_sock_path)
        .cpi_sock_path(launch_config.routing.control_plane_socket)
        .frr_agent_path(launch_config.routing.frr_agent_socket)
        .build()
    {
        Ok(config) => config,
        Err(e) => {
            error!("error building router parameters: {e}");
            panic!("error building router parameters: {e}");
        }
    };

    // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
    let setup = start_router(config).expect("failed to start router");

    let _metrics_server = MetricsServer::new(launch_config.metrics.address, setup.stats);

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
        setup.vpc_stats_store,
    )
    .expect("Failed to start gRPC server");

    /* start driver with the provided pipeline builder */
    let _keep = match &launch_config.driver {
        args::DriverConfigSection::Dpdk(dpdk_driver_config) => {
            let (eal, devices) =
                DriverDpdk::start(dpdk_driver_config.eal_args.clone(), &setup_pipeline);
            info!("Now using driver DPDK...");
            Some((eal, devices))
        }
        args::DriverConfigSection::Kernel(kernel_driver_config) => {
            DriverKernel::start(&kernel_driver_config.interfaces, 2, &pipeline_factory);
            info!("Now using driver kernel...");
            None
        }
    };
    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    std::process::exit(0);
}

#[cfg(test)]
mod test {
    use n_vm::in_vm;

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
