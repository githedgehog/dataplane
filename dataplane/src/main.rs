// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]
#![feature(allocator_api)]

mod drivers;
mod packet_processor;
mod statistics;

use crate::statistics::MetricsServer;
use crate::{drivers::dpdk::Dpdk, packet_processor::start_router};
use args::{LaunchConfiguration, TracingConfigSection};

use driver::{Configure, Start, Stop};
use drivers::kernel::DriverKernel;
use mgmt::{ConfigProcessorParams, MgmtParams, start_mgmt};

use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{PprofConfig, pprof_backend};

use net::buffer::{TestBuffer, TestBufferPool};
use pkt_io::{start_io, tap_init};

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
    // memory allocation banned until EAL is started
    let launch_config_memmap = LaunchConfiguration::inherit();
    let launch_config = rkyv::access::<rkyv::Archived<LaunchConfiguration>, rkyv::rancor::Failure>(
        launch_config_memmap.as_ref(),
    )
    .expect("failed to validate ArchivedLaunchConfiguration");
    let configured = Dpdk::configure(launch_config).unwrap();
    let started = configured.start().unwrap();
    // memory allocation ok after this line
    init_logging();
    // started.stop();
    // let agent_running = launch_config
    //     .profiling
    //     .pyroscope_url
    //     .as_ref()
    //     .and_then(|url| {
    //         match PyroscopeAgent::builder(url.as_str(), "hedgehog-dataplane")
    //             .backend(pprof_backend(
    //                 PprofConfig::new()
    //                     .sample_rate(launch_config.profiling.frequency) // Hz
    //                     .report_thread_name(),
    //             ))
    //             .build()
    //         {
    //             Ok(agent) => match agent.start() {
    //                 Ok(running) => Some(running),
    //                 Err(e) => {
    //                     error!("Pyroscope start failed: {e}");
    //                     None
    //                 }
    //             },
    //             Err(e) => {
    //                 error!("Pyroscope build failed: {e}");
    //                 None
    //             }
    //         }
    //     });
    // info!("launch config: {launch_config:?}");
    // process_tracing_cmds(&launch_config.tracing);

    // info!("Starting gateway process...");

    // let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    // ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
    //     .expect("failed to set SIGINT handler");

    // let grpc_addr = launch_config.config_server.address;

    // /* router parameters */
    // let config = match RouterParamsBuilder::default()
    //     .metrics_addr(launch_config.metrics.address)
    //     .cli_sock_path(launch_config.cli.cli_sock_path)
    //     .cpi_sock_path(launch_config.routing.control_plane_socket)
    //     .frr_agent_path(launch_config.routing.frr_agent_socket)
    //     .build()
    // {
    //     Ok(config) => config,
    //     Err(e) => {
    //         error!("error building router parameters: {e}");
    //         panic!("error building router parameters: {e}");
    //     }
    // };

    // // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
    // let setup = start_router(config).expect("failed to start router");

    // let _metrics_server = MetricsServer::new(launch_config.metrics.address, setup.stats);

    // // pipeline builder
    // let pipeline_factory = setup.pipeline;

    // Start driver with the provided pipeline builder. Taps must have been created before this
    // happens so that their ifindex is available when drivers initialize.

    // let (_handle, iom_ctl) = {
    //     match &launch_config.driver {
    //         args::DriverConfigSection::Dpdk(section) => {
    //             tap_init(&section.interfaces).expect("Tap initialization failed");

    //             info!("Using driver DPDK...");
    //             todo!();
    //         }
    //         args::DriverConfigSection::Kernel(section) => {
    //             tap_init(&section.interfaces).expect("Tap initialization failed");
    //             info!("Using driver kernel...");
    //             DriverKernel::start(
    //                 section.interfaces.clone().into_iter(),
    //                 launch_config.dataplane_workers,
    //                 &pipeline_factory,
    //             )
    //         }
    //     };
    //     start_io::<TestBuffer, TestBufferPool>(setup.puntq, setup.injectq, TestBufferPool)
    //         .expect("Failed to start IO manager")
    // };

    // // prepare parameters for mgmt
    // let mgmt_params = MgmtParams {
    //     grpc_addr,
    //     processor_params: ConfigProcessorParams {
    //         router_ctl: setup.router.get_ctl_tx(),
    //         nattablesw: setup.nattablesw,
    //         natallocatorw: setup.natallocatorw,
    //         vpcdtablesw: setup.vpcdtablesw,
    //         vpcmapw: setup.vpcmapw,
    //         vpc_stats_store: setup.vpc_stats_store,
    //         iom_ctl,
    //     },
    // };
    // // start mgmt
    // start_mgmt(mgmt_params).expect("Failed to start gRPC server");

    // stop_rx.recv().expect("failed to receive stop signal");
    // info!("Shutting down dataplane");
    // if let Some(running) = agent_running {
    //     match running.stop() {
    //         Ok(ready) => ready.shutdown(),
    //         Err(e) => error!("Pyroscope stop failed: {e}"),
    //     }
    // }
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
