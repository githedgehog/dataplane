// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod drivers;
mod packet_processor;
mod statistics;

use std::path::PathBuf;

use crate::packet_processor::start_router;
use crate::statistics::MetricsServer;
use args::{LaunchConfiguration, TracingConfigSection};

use drivers::kernel::DriverKernel;
use mgmt::{ConfigProcessorParams, MgmtParams, start_mgmt};

use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{PprofConfig, pprof_backend};

use routing::RouterParamsBuilder;
use tracectl::{custom_target, get_trace_ctl, trace_target};

use tracing::{error, info, level_filters::LevelFilter};

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
custom_target!("tonic", LevelFilter::ERROR, &[]);
custom_target!("h2", LevelFilter::ERROR, &[]);
custom_target!("Pyroscope", LevelFilter::INFO, &[]);

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
    let launch_config = LaunchConfiguration::inherit();
    init_logging();
    let agent_running = launch_config
        .profiling
        .pyroscope_url
        .as_ref()
        .and_then(|url| {
            match PyroscopeAgent::builder(url.as_str(), "hedgehog-dataplane")
                .backend(pprof_backend(
                    PprofConfig::new()
                        .sample_rate(launch_config.profiling.frequency) // Hz
                        .report_thread_name(),
                ))
                .build()
            {
                Ok(agent) => match agent.start() {
                    Ok(running) => Some(running),
                    Err(e) => {
                        error!("Pyroscope start failed: {e}");
                        None
                    }
                },
                Err(e) => {
                    error!("Pyroscope build failed: {e}");
                    None
                }
            }
        });
    info!("launch config: {launch_config:?}");
    process_tracing_cmds(&launch_config.tracing);

    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let ctrlc_stop_tx = stop_tx.clone();
    ctrlc::set_handler(move || {
        ctrlc_stop_tx
            .send(0)
            .expect("Error sending shutdown signal");
    })
    .expect("failed to set SIGINT handler");

    let grpc_addr = launch_config.config_server.address;

    /* router parameters */
    let Ok(config) = RouterParamsBuilder::default()
        .cli_sock_path(PathBuf::from(launch_config.cli.cli_sock_path))
        .cpi_sock_path(PathBuf::from(launch_config.routing.control_plane_socket))
        .frr_agent_path(PathBuf::from(launch_config.routing.frr_agent_socket))
        .build()
    else {
        error!("Bad router configuration");
        panic!("Bad router configuration");
    };

    // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
    let setup = start_router(config).expect("failed to start router");

    let _metrics_server = MetricsServer::new(launch_config.metrics.address, setup.stats);

    // pipeline builder
    let pipeline_factory = setup.pipeline;

    /* start management */
    start_mgmt(MgmtParams {
        grpc_addr,
        processor_params: ConfigProcessorParams {
            router_ctl: setup.router.get_ctl_tx(),
            vpcmapw: setup.vpcmapw,
            nattablesw: setup.nattablesw,
            natallocatorw: setup.natallocatorw,
            vpcdtablesw: setup.vpcdtablesw,
            vpc_stats_store: setup.vpc_stats_store,
        },
    })
    .expect("Failed to start gRPC server");

    /* start driver with the provided pipeline builder */
    match launch_config.driver {
        args::DriverConfigSection::Dpdk(_driver_config) => {
            info!("Using driver DPDK...");
            todo!();
        }
        args::DriverConfigSection::Kernel(driver_config) => {
            info!("Using driver kernel...");
            let interfaces = driver_config.interfaces.iter().map(|iface| match &iface.port {
                args::NetworkDeviceDescription::Pci(pci_address) => {
                    error!("unable to launch kernel driver with pci device specified: {pci_address}");
                    panic!("unable to launch kernel driver with pci device specified: {pci_address}");
                },
                args::NetworkDeviceDescription::Kernel(interface_name) => {
                    interface_name
                },
            });
            DriverKernel::start(
                stop_tx.clone(),
                interfaces,
                launch_config.dataplane_workers,
                &pipeline_factory,
            )
        }
    }

    let exit_code = stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    if let Some(running) = agent_running {
        match running.stop() {
            Ok(ready) => ready.shutdown(),
            Err(e) => error!("Pyroscope stop failed: {e}"),
        }
    }
    std::process::exit(exit_code);
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
