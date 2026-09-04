// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::packet_processor::start_router;
use crate::statistics::spawn_metrics;
use args::{CmdArgs, Parser, PortArg};

use crate::drivers::DriverError;
use crate::drivers::dpdk::{DriverDpdk, Port};
use crate::drivers::kernel::DriverKernel;
use crate::drivers::status::driver_status_access;
use lifecycle::{
    CancellationToken, DpSignal, Shutdown, default_deadlines, spawn_shutdown_watchdog,
};
use mgmt::{ConfigProcessorParams, LaunchError, MgmtParams, run_mgmt};

use dpdk::dev::DevInfo;
use dpdk::eal::Eal;
use nix::unistd::gethostname;
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
use pyroscope::pyroscope::{PyroscopeAgentBuilder, PyroscopeConfig};
use routing::{BmpServerParams, RouterCtlSender, RouterParamsBuilder, spawn_bmp_server};
use tracectl::{
    TracingControl, TracingRateLimitConfig, custom_target, get_trace_ctl, trace_target,
};

use tracing::{error, info, level_filters::LevelFilter, warn};

use concurrency::sync::Arc;
use config::internal::routing::bmp::BmpOptions;
use config::internal::status::DataplaneStatus;
use net::tcp::TcpPort;
use std::time::Duration;
use tokio::sync::RwLock;

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
custom_target!("Pyroscope", LevelFilter::WARN, &["third-party"]);
custom_target!("kube", LevelFilter::WARN, &["third-party"]);
custom_target!("hyper", LevelFilter::WARN, &["third-party"]);
custom_target!("tower", LevelFilter::WARN, &["third-party"]);

const PYROSCOPE_APP_NAME: &str = "hedgehog-dataplane";

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
fn init_logging(args: &CmdArgs, gwname: &str) {
    // Log throttling is on by default; a missing --tracing-rate-limit uses the
    // default. It can be disabled at runtime via the dataplane CLI.
    let rate_limit =
        args.tracing_rate_limit()
            .map_or_else(TracingRateLimitConfig::default, |rate_limit| {
                TracingRateLimitConfig {
                    burst: rate_limit.burst,
                    replenish_per_second: rate_limit.replenish_per_second,
                }
            });
    TracingControl::init_with_rate_limit(Some(rate_limit));

    let tctl = get_trace_ctl();
    info!(
        " ━━━━━━ Starting dataplane for gateway '{gwname}' (Version = {}) ━━━━━━",
        option_env!("VERSION").unwrap_or("dev").to_string()
    );

    if args.tracing().is_none() {
        tctl.set_default_level(LevelFilter::DEBUG)
            .expect("Setting default loglevel failed");
    }
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

fn parse_bmp_params(args: &CmdArgs) -> (Option<BmpServerParams>, Option<BmpOptions>) {
    if args.bmp_enabled() {
        let bind_addr = args.bmp_address();
        let interval: Duration = args.bmp_interval();

        info!("BMP: required. Bind-address: {bind_addr}, interval={interval:?}");

        // BMP server (for routing crate)
        let server = BmpServerParams { bind_addr };

        // BMP options for FRR (for internal config)
        let host = bind_addr.ip().to_string();
        let port = TcpPort::try_from(bind_addr.port()).expect("Invalid BMP port");
        let client = BmpOptions::new("bmp1", host, port)
            .set_retry(interval, interval.saturating_mul(4u32))
            .set_stats_interval(interval)
            .monitor_ipv4(true, true)
            .mirror(true);

        (Some(server), Some(client))
    } else {
        info!("BMP: disabled");
        (None, None)
    }
}

fn start_bmp(
    mgmt: &lifecycle::Subsystem,
    mgmt_handle: &tokio::runtime::Handle,
    bmp_params: &BmpServerParams,
    dp_status: Arc<RwLock<DataplaneStatus>>,
    rtr_ctl: RouterCtlSender,
) -> tokio::task::JoinHandle<()> {
    spawn_bmp_server(mgmt, mgmt_handle, bmp_params.bind_addr, dp_status, rtr_ctl)
}

// Main signal handling of dataplane occurs here
fn spawn_signal_handler(
    rt_handle: &tokio::runtime::Handle,
    mut sigrx: tokio::sync::mpsc::Receiver<DpSignal>,
    root: CancellationToken,
) {
    rt_handle.spawn(async move {
        loop {
            tokio::select! {
                Some(sig) = sigrx.recv() => {
                    info!("Processing signal {sig:?} from signal catcher");
                    match sig {
                        DpSignal::SIGTERM | DpSignal::SIGINT | DpSignal::SIGQUIT => root.cancel(),
                        DpSignal::SIGUSR1 | DpSignal::SIGUSR2 | DpSignal::SIGHUP | DpSignal::SIGALRM | DpSignal::SIGPIPE => {},
                    }
                }
                () = root.cancelled() => {
                    break;
                }
            }
        }
        info!("Signal handler ended");
    });
}

/// Bring up the EAL with arguments appropriate to the configured driver.
///
/// Only ever called once: `rte_eal_init` is process-global and a second call fails.
fn init_eal(args: &CmdArgs) -> dpdk::eal::Eal {
    let main_lcore_arg = dpdk::eal::main_lcore_arg();

    let mut eal_args: Vec<String> = vec![
        "dataplane".to_string(),
        "--in-memory".to_string(),
        "--no-telemetry".to_string(),
        "--no-shconf".to_string(),
        "--iova-mode=va".to_string(),
        "--lcores".to_string(),
        main_lcore_arg.clone(),
    ];

    if args.driver_name() == "dpdk" {
        // Allow exactly the devices named on the command line. Without an allowlist the EAL probes
        // every PCI device it recognises, which on a host with more than one NIC means attaching to
        // one the operator did not offer us -- including, potentially, the management uplink.
        for interface in args.interfaces() {
            if let Some(PortArg::PCI(addr)) = &interface.port {
                eal_args.push("-a".to_string());
                eal_args.push(addr.to_string());
            }
        }
    } else {
        // Classifier-only: rte_acl needs the memory subsystem and nothing else.
        eal_args.push("--no-huge".to_string());
        eal_args.push("--no-pci".to_string());
    }

    info!("Initializing DPDK EAL with: {}", eal_args.join(" "));
    dpdk::eal::init(eal_args)
}

/// Configure and start every DPDK port named on the command line.
///
/// Ports must already be *bound* to a driver DPDK can attach to. That is `dataplane-init`'s job,
/// not this one: for most NICs it means unbinding from the kernel driver and binding to `vfio-pci`,
/// and for mlx5 it means deliberately leaving the kernel driver in place, because that driver is
/// bifurcated and DPDK attaches alongside it. By the time this runs the EAL has already probed
/// whatever was bound, so a port that is missing here was missing then.
fn bring_up_ports<'eal>(eal: &'eal Eal, args: &CmdArgs) -> Result<Vec<Port<'eal>>, DriverError> {
    let num_workers = u16::try_from(args.num_workers()).map_err(|_| {
        DriverError::PortSetup(format!("{} workers is too many", args.num_workers()))
    })?;

    // What the EAL actually probed, keyed by PCI address so the command line can be matched against
    // it. A device the operator named but the EAL did not probe is a hard error rather than a
    // warning: silently forwarding on a subset of the configured ports is a worse outcome than
    // refusing to start.
    let mut probed: Vec<DevInfo<'eal>> = eal.dev.iter().collect();
    info!("EAL probed {} DPDK port(s)", probed.len());

    let mut ports = Vec::new();
    for interface in args.interfaces() {
        let Some(PortArg::PCI(addr)) = &interface.port else {
            return Err(DriverError::PortSetup(format!(
                "interface '{}' has no PCI address; the DPDK driver needs one \
                 (--interface {}=pci@0000:xx:yy.z)",
                interface.interface, interface.interface
            )));
        };

        // `DevInfo` does not carry the PCI address, so ports are matched positionally in the order
        // the EAL probed them, which is the order of the `-a` allowlist built from these same
        // arguments. That is fragile and deliberately temporary -- matching on the device name is
        // the right fix, and needs an accessor the dpdk crate does not have yet.
        if probed.is_empty() {
            return Err(DriverError::PortSetup(format!(
                "no DPDK port left to match interface '{}' ({addr}); the EAL probed fewer devices \
                 than were configured. If this is zero overall, the usual cause is that the NIC was \
                 never bound for DPDK -- see dataplane-init.",
                interface.interface
            )));
        }
        let info = probed.remove(0);
        ports.push(Port::bring_up(
            eal,
            info,
            interface.interface.to_string(),
            num_workers,
        )?);
    }

    if !probed.is_empty() {
        warn!(
            "{} DPDK port(s) were probed but not configured; they will carry no traffic",
            probed.len()
        );
    }

    Ok(ports)
}

#[allow(clippy::too_many_lines)]
pub fn main() {
    let args = CmdArgs::parse();
    let gwname = match init_name(&args) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Failed to set gateway name: {e}");
            std::process::exit(1);
        }
    };
    init_logging(&args, &gwname);

    // Initialize the EAL as early as possible, and exactly once.
    //
    // Two things need it and they want different arguments. Stages such as the ACL filter and the
    // flow-filter build rte_acl classifiers when configuration is applied -- which happens before
    // any packet driver starts -- and rte_acl needs only the EAL memory subsystem. The DPDK
    // datapath driver needs hugepages and its devices probed. There can be only one
    // `rte_eal_init` per process, so the driver decides: with `--driver dpdk` the EAL comes up
    // device-capable and rte_acl uses it happily, and otherwise it comes up in the lightweight
    // classifier-only form. The guard is held for the life of the process.
    //
    // `--lcores` pins DPDK's main lcore to every CPU currently allowed for this process rather
    // than letting `rte_eal_init` default it to a single CPU; see `main_lcore_arg` for why that
    // default matters here (it otherwise pins every thread spawned after EAL init, not just DPDK's).
    let eal = init_eal(&args);

    let (bmp_server_params, bmp_client_opts) = parse_bmp_params(&args);

    let dp_status: Arc<RwLock<DataplaneStatus>> = Arc::new(RwLock::new(DataplaneStatus::new()));

    let agent_running = args.pyroscope_url().and_then(|url| {
        let pyroscope_config = PyroscopeConfig::default();
        let sample_rate = pyroscope_config.sample_rate;

        match PyroscopeAgentBuilder::new(
            url.as_str(),
            PYROSCOPE_APP_NAME,
            sample_rate,
            pyroscope_config.spy_name,
            pyroscope_config.spy_version,
            pprof_backend(
                PprofConfig { sample_rate },
                BackendConfig {
                    report_thread_name: true,
                    ..BackendConfig::default()
                },
            ),
        )
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

    let (driver_status_writer, driver_status_reader) = driver_status_access();

    let shutdown = Shutdown::new();

    let mgmt_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("mgmt-rt")
        .build()
        .expect("Failed to build mgmt runtime");
    let mgmt_handle = mgmt_runtime.handle().clone();

    let sigrx = lifecycle::spawn_signal_catcher(&mgmt_handle, shutdown.root.clone())
        .expect("failed to install signal handler");

    spawn_signal_handler(&mgmt_handle, sigrx, shutdown.root.clone());

    spawn_shutdown_watchdog(shutdown.root.clone(), default_deadlines::TOTAL, 124)
        .expect("failed to spawn shutdown watchdog");

    // assemble router parameters
    let mut binding = RouterParamsBuilder::default();
    let rp_builder = binding
        .cli_sock_path(args.cli_sock_path())
        .cpi_sock_path(args.cpi_sock_path())
        .frr_agent_path(args.frr_agent_path());

    let Ok(router_params) = rp_builder.build() else {
        error!("Bad router configuration");
        panic!("Bad router configuration");
    };

    // start router
    let mut setup = start_router(&shutdown.router, router_params, driver_status_reader)
        .expect("failed to start router");

    // start bmp server if indicated via cmd line. It is fine to start it after the router since no bgp session may be up
    // until a configuration is applied, and the mgmt is not yet up.
    let _bmp_handle = if let Some(bmp_params) = &bmp_server_params {
        Some(start_bmp(
            &shutdown.mgmt,
            &mgmt_handle,
            bmp_params,
            dp_status.clone(),
            setup.router.get_ctl_tx(),
        ))
    } else {
        None
    };

    spawn_metrics(
        &shutdown.metrics,
        &mgmt_handle,
        args.metrics_address(),
        setup.stats,
    );

    let ingredients = setup.pipeline;
    let pipeline_data = ingredients.data();

    // Ports are brought up before the worker scope opens, because the queue handles workers own are
    // branded with the borrow of the port they came from: the ports have to outlive every thread
    // that touches one. An empty vector for any other driver.
    let ports = if args.driver_name() == "dpdk" {
        match bring_up_ports(&eal, &args) {
            Ok(ports) => ports,
            Err(e) => {
                error!("Failed to bring up DPDK ports: {e}");
                shutdown.fail();
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    concurrency::thread::scope(|scope| {
        let mgmt_result = run_mgmt(
            &mgmt_handle,
            &shutdown.mgmt,
            MgmtParams {
                config_dir: args.config_dir().cloned(),
                hostname: gwname.clone(),
                interfaces: args.interfaces().map(|i| i.interface).collect(),
                processor_params: ConfigProcessorParams {
                    router_ctl: setup.router.get_ctl_tx(),
                    pipeline_data,
                    flow_table: setup.flow_table,
                    vpcmapw: setup.vpcmapw,
                    nattablesw: setup.nattablesw,
                    natallocatorw: setup.natallocatorw,
                    flow_filter_writer: setup.flow_filter_writer,
                    aclfilterw: setup.aclfiltertablesw,
                    portfw_w: setup.portfw_w,
                    vpc_stats_store: setup.vpc_stats_store,
                    dp_status_r: dp_status.clone(),
                    bmp_options: bmp_client_opts,
                },
            },
        );

        match mgmt_result {
            Ok(()) => {
                info!("Management is running now");

                let driver_result = match args.driver_name() {
                    "dpdk" => {
                        info!("Using driver DPDK...");
                        Some(DriverDpdk::start(
                            scope,
                            &shutdown.workers,
                            &ports,
                            args.num_workers(),
                            &ingredients.factory(),
                            driver_status_writer,
                        ))
                    }
                    "kernel" => {
                        info!("Using driver kernel...");
                        Some(DriverKernel::start(
                            scope,
                            &shutdown.workers,
                            args.kernel_interfaces(),
                            args.num_workers(),
                            &ingredients.factory(),
                            driver_status_writer,
                        ))
                    }
                    other => {
                        error!("Unknown driver '{other}'. Stopping dataplane...");
                        shutdown.fail();
                        None
                    }
                };

                if let Some(Err(e)) = driver_result {
                    error!("Failed to start driver: {e}");
                    shutdown.fail();
                }
            }
            Err(LaunchError::Cancelled) => {
                // Don't call shutdown.fail() — that flips the fatal flag
                // and turns a graceful SIGINT into a non-zero exit, which
                // systemd would restart-loop.
                info!("Mgmt init cancelled; proceeding to shutdown");
            }
            Err(e) => {
                error!("Failed to start mgmt: {e}. Stopping dataplane...");
                shutdown.fail();
            }
        }

        mgmt_handle.block_on(shutdown.root.cancelled());
        info!("Shutting down dataplane");
        mgmt_handle.block_on(shutdown.drain_in_order());
    });

    let exit_code = i32::from(shutdown.is_fatal());

    // Every worker has been joined by the scope above, so the queue handles that borrowed these
    // ports are gone and the ports can be stopped. Explicitly, rather than leaving it to
    // `PortLifecycle`'s `Drop` backstop, so a device that refuses to stop is reported.
    for port in ports {
        port.shutdown();
    }

    setup.router.stop();
    mgmt_runtime.shutdown_timeout(Duration::from_secs(2));

    if let Some(running) = agent_running {
        match running.stop() {
            Ok(ready) => ready.shutdown(),
            Err(e) => error!("Pyroscope stop failed: {e}"),
        }
    }
    info!("Dataplane shutdown completed");
    std::process::exit(exit_code);
}
