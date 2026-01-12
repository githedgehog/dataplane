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
use args::{CmdArgs, Parser};

use drivers::kernel::DriverKernel;
use mgmt::{ConfigProcessorParams, MgmtParams, start_mgmt};

use nix::unistd::gethostname;
use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{PprofConfig, pprof_backend};

use routing::RouterParamsBuilder;
use tracectl::{custom_target, get_trace_ctl, trace_target};

use tracing::{error, info, level_filters::LevelFilter};

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
custom_target!("Pyroscope", LevelFilter::INFO, &[]);

fn init_name(args: &CmdArgs) -> Result<String, String> {
    if let Some(name) = args.get_name() {
        Ok(name.clone())
    } else {
        let hostname =
            gethostname().map_err(|errno| format!("Failed to get hostname: {}", errno.desc()))?;
        let name = hostname
            .to_str()
            .ok_or_else(|| format!("Failed to convert hostname {}", hostname.display()))?;
        Ok(name.to_string())
    }
}
fn init_logging(gwname: &str) {
    let tctl = get_trace_ctl();
    info!(" ━━━━━━ Dataplane for '{gwname}' started ━━━━━━",);

    tctl.set_default_level(LevelFilter::DEBUG)
        .expect("Setting default loglevel failed");
}

fn process_tracing_cmds(args: &CmdArgs) {
    if let Some(tracing) = args.tracing()
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    if args.show_tracing_tags() {
        let out = get_trace_ctl()
            .as_string_by_tag()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    if args.show_tracing_targets() {
        let out = get_trace_ctl()
            .as_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    if args.tracing_config_generate() {
        let out = get_trace_ctl()
            .as_config_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    let args = CmdArgs::parse();
    let gwname = match init_name(&args) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Failed to set gateway name: {e}");
            std::process::exit(1);
        }
    };
    init_logging(&gwname);

    let agent_running = args.pyroscope_url().and_then(|url| {
        match PyroscopeAgent::builder(url.as_str(), "hedgehog-dataplane")
            .backend(pprof_backend(
                PprofConfig::new()
                    .sample_rate(100) // Hz
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
    process_tracing_cmds(&args);
    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    let ctrlc_stop_tx = stop_tx.clone();
    ctrlc::set_handler(move || {
        ctrlc_stop_tx
            .send(0)
            .expect("Error sending shutdown signal");
    })
    .expect("failed to set SIGINT handler");

    /* router parameters */
    let Ok(config) = RouterParamsBuilder::default()
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

    // pipeline builder
    let pipeline_factory = setup.pipeline;

    /* start management */
    start_mgmt(MgmtParams {
        config_dir: args.config_dir().cloned(),
        hostname: gwname.clone(),
        processor_params: ConfigProcessorParams {
            router_ctl: setup.router.get_ctl_tx(),
            vpcmapw: setup.vpcmapw,
            nattablesw: setup.nattablesw,
            natallocatorw: setup.natallocatorw,
            vpcdtablesw: setup.vpcdtablesw,
            vpc_stats_store: setup.vpc_stats_store,
        },
    })
    .expect("Failed to start management");

    /* start driver with the provided pipeline builder */
    let e = match args.driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            todo!();
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(
                stop_tx.clone(),
                args.kernel_interfaces(),
                args.kernel_num_workers(),
                &pipeline_factory,
            )
        }
        other => {
            error!("Unknown driver '{other}'. Aborting...");
            panic!("Packet processing pipeline failed to start. Aborting...");
        }
    };

    if let Err(e) = e {
        error!("Failed to start driver: {e}");
        std::process::exit(-1);
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

#[cfg(false)] // disabled until dpdk-sys refactor is complete
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
