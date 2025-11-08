// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]
#![feature(allocator_api, thread_spawn_hook)]

mod drivers;
mod packet_processor;
mod statistics;

use std::{io::Write, process::ExitCode, time::Duration};

use crate::{drivers::dpdk::Dpdk, packet_processor::start_router, statistics::MetricsServer};
use args::{LaunchConfiguration, TracingConfigSection};

use dpdk::{
    eal::{Eal, EalArgs},
    mem::{RteAllocator, SwitchingAllocator},
};
use driver::{Configure, Start, Stop};
use miette::{Context, IntoDiagnostic};
use nix::libc;
use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{PprofConfig, pprof_backend};

use routing::RouterParamsBuilder;
use tokio_util::sync::CancellationToken;
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

async fn dataplane(
    launch_config: &LaunchConfiguration,
    _eal: &Eal<dpdk::eal::Started<'_>>,
    cancel: CancellationToken,
) {
    info!("starting gateway process...");
    let grpc_addr = &launch_config.config_server.address;

    /* router parameters */
    let config = match RouterParamsBuilder::default()
        .metrics_addr(launch_config.metrics.address)
        .cli_sock_path(launch_config.cli.cli_sock_path.clone())
        .cpi_sock_path(launch_config.routing.control_plane_socket.clone())
        .frr_agent_path(launch_config.routing.frr_agent_socket.clone())
        .cancelation_token(cancel.child_token())
        .build()
    {
        Ok(config) => config,
        Err(e) => {
            error!("error building router parameters: {e}");
            panic!("error building router parameters: {e}");
        }
    };

    // start the router; returns control-plane handles and a pipeline factory (Arc<... Fn() -> DynPipeline<_> >)
    let setup = start_router::<dpdk::mem::Mbuf>(config).expect("failed to start router");

    let _metrics_server = MetricsServer::new(launch_config.metrics.address, setup.stats);

    // pipeline builder
    let pipeline_factory = setup.pipeline;

    tokio::time::sleep(Duration::from_secs(1)).await;

    cancel.cancel();
    tokio::time::sleep(Duration::from_secs(1)).await;

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

    // std::process::exit(0);
}

/// This method
///
/// 1. configures the dataplane's runtime environment
/// 2. invokes the dataplane function in that environment.
/// 3. cleans up that environment after it completes or panics
#[allow(clippy::too_many_lines)]
fn launch_dataplane<'a>(
    dataplane_fn: impl AsyncFnOnce(
        &LaunchConfiguration,
        &Eal<dpdk::eal::Started<'a>>,
        CancellationToken,
    ),
) {
    // Look Mom, I fixed POSIX!
    extern "C" fn skip_all_exit_handlers_and_fail() {
        const EXITED_APPLICATION_UNCLEANLY: i32 = 2;
        const FAILED_TO_SYNC_STDOUT: i32 = 3;
        const FAILED_TO_SYNC_STDERR: i32 = 4;
        eprintln!("fatal error: improper shutdown sequence");
        std::io::stdout().flush().unwrap_or_else(|_| unsafe {
            libc::_exit(FAILED_TO_SYNC_STDOUT);
        });
        std::io::stderr().flush().unwrap_or_else(|_| unsafe {
            libc::_exit(FAILED_TO_SYNC_STDERR);
        });
        unsafe {
            libc::_exit(EXITED_APPLICATION_UNCLEANLY);
        }
    }
    unsafe {
        libc::atexit(skip_all_exit_handlers_and_fail);
    }

    let eal = {
        // memory allocation banned until EAL is started
        let launch_config_memmap = LaunchConfiguration::inherit();
        let launch_config = rkyv::access::<
            rkyv::Archived<LaunchConfiguration>,
            rkyv::rancor::Failure,
        >(launch_config_memmap.as_ref())
        .expect("failed to validate ArchivedLaunchConfiguration");
        // memory/thread allocation ok so long as you have an eal
        let eal = match &launch_config.driver {
            args::ArchivedDriverConfigSection::Dpdk(driver_config) => {
                let eal_args = EalArgs::new(&driver_config.eal_args);
                let configured = dpdk::eal::Eal::configure(eal_args).unwrap();
                configured.start().unwrap()
            }
            args::ArchivedDriverConfigSection::Kernel(_driver_config) => {
                todo!();
            }
        };
        init_logging();
        let launch_config = rkyv::from_bytes::<LaunchConfiguration, rkyv::rancor::Error>(
            launch_config_memmap.as_ref(),
        )
        .into_diagnostic()
        .wrap_err("failed to deserialize launch configuration")
        .unwrap();
        info!("launch config: {launch_config:?}");
        process_tracing_cmds(&launch_config.tracing);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .max_blocking_threads(2) // deliberately very low for now
            .on_thread_stop(|| {
                // safe because of eal registration hook
                unsafe {
                    dpdk::lcore::ServiceThread::unregister_current_thread();
                }
            })
            .build()
            .unwrap();
        let _runtime_guard = runtime.enter();
        let pyroscope_agent = launch_config
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
        runtime.block_on(async {
            // TODO: add stop signal / cancel token to the args of dataplane_fn
            // let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
            let cancel = CancellationToken::new();
            let _drop_guard = cancel.clone().drop_guard();
            // ctrlc::set_handler({
            //     let cancel = cancel.clone();
            //     move || {
            //         cancel.cancel();
            //         // stop_tx.try_send(()).expect("Error sending shutdown signal");
            //     }
            // })
            // .expect("failed to set SIGINT handler");
            let dataplane = dataplane_fn(&launch_config, &eal, cancel.child_token());
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("shutdown requested: closing down dataplane");
                }
                () = dataplane => {
                    info!("dataplane shutting down");
                }
            }
        });
        info!("cleaning up pyroscope");
        if let Some(running) = pyroscope_agent {
            match running.stop() {
                Ok(ready) => ready.shutdown(),
                Err(e) => error!("Pyroscope stop failed: {e}"),
            }
        }
        info!("shutting down async runtime");
        runtime.shutdown_timeout(Duration::from_secs(90)); // crazy timeout to force bug hunt
        info!("acync runtime stopped");
        eal
    };
    // panic!("injecting failure to test abnormal shutdown");
    let _stopped = eal.stop().unwrap_or_else(|_| std::process::abort()); // abort case here should be unreachable
}

// NOTE: do not add _any_ other logic to this function.  The `launch_dataplane` call is the one and only line
// which ever needs to be invoked in main.
// If you wish to edit application logic put it in the dataplane fn.
// If you wish to add application runtime configuration (e.g. logic revolving around tracing, observability,
// performance, or low level memory allocation configuration), then edit the `launch_dataplane` function.
//
// Any deviation from this pattern is likely to result in a program which does not shut down correctly.
fn main() {
    launch_dataplane(dataplane);
}
