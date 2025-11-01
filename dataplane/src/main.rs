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
use mgmt::processor::launch::start_mgmt;


use pyroscope::PyroscopeAgent;
use pyroscope_pprofrs::{PprofConfig, pprof_backend};

use net::buffer::PacketBufferMut;
use net::buffer::{PacketBufferMut, TestBuffer, TestBufferPool};
use net::packet::Packet;

use pipeline::DynPipeline;
use pipeline::sample_nfs::PacketDumper;
use pkt_io::{PortMapWriter, start_io};


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

fn main() {
    init_logging();
    let args = CmdArgs::parse();
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
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");

    let grpc_addr = match args.grpc_address() {
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

    // pipeline builder
    let pipeline_factory = setup.pipeline;

    // Start driver with the provided pipeline builder. Driver should create a portmap table,
    // populate it with [`PortSpec`]s and return the writer
    let _pmap_w = match args.driver_name() {
        "dpdk" => {
            info!("Using driver DPDK...");
            todo!();
        }
        "kernel" => {
            info!("Using driver kernel...");
            DriverKernel::start(
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

    // always log port mappings
    pmap_w.log_pmap_table();

    // start IO service
    let (_handle, _io_ctl) = match args.driver_name() {
/*
        "dpdk" => {
            let pool_cfg =
                PoolConfig::new("fixme", PoolParams::default()).expect("Bad pool config");
            let pool = Pool::new_pkt_pool(pool_cfg).expect("Failed to create DPDK buffer pool");
            start_io::<Mbuf, Pool>(setup.puntq, setup.injectq, pool)
        }
 */
        "kernel" => {
            start_io::<TestBuffer, TestBufferPool>(setup.puntq, setup.injectq, TestBufferPool)
        }
        &_ => todo!(),
    }
    .expect("Failed to start IO manager");

    // start management interface
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

    stop_rx.recv().expect("failed to receive stop signal");
    info!("Shutting down dataplane");
    if let Some(running) = agent_running {
        match running.stop() {
            Ok(ready) => ready.shutdown(),
            Err(e) => error!("Pyroscope stop failed: {e}"),
        }
    }
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
