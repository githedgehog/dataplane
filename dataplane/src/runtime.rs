// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::packet_processor::start_router;
use crate::statistics::spawn_metrics;
use args::{CmdArgs, Parser};

use crate::drivers::kernel::DriverKernel;
use lifecycle::{
    CancellationToken, DpSignal, Shutdown, default_deadlines, spawn_shutdown_watchdog,
};
use mgmt::{ConfigProcessorParams, LaunchError, MgmtParams, run_mgmt};

use nix::unistd::gethostname;
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
use pyroscope::pyroscope::{PyroscopeAgentBuilder, PyroscopeConfig};
use routing::{BmpServerParams, RouterCtlSender, RouterParamsBuilder, spawn_bmp_server};
use tracectl::{
    TracingControl, TracingRateLimitConfig, custom_target, get_trace_ctl, trace_target,
};

use tracing::{error, info, level_filters::LevelFilter};

use concurrency::sync::Arc;
use config::internal::routing::bmp::BmpOptions;
use config::internal::status::DataplaneStatus;
use net::tcp::TcpPort;
use std::time::Duration;
use tokio::sync::RwLock;

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
custom_target!("Pyroscope", LevelFilter::INFO, &["third-party"]);
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

    // Initialize a minimal EAL as early as possible. The ACL filter builds rte_acl
    // classifiers when configuration is applied (which happens before any packet driver starts),
    // and rte_acl needs the EAL memory subsystem up. These are the lightweight, classifier-only
    // args (no hugepages / no PCI). NOTE: there can be only one `rte_eal_init` per process, so the
    // real DPDK datapath driver (currently `todo!()`) must eventually take over EAL ownership with
    // device-appropriate args rather than adding a second init. The guard is held for the life of
    // the process.
    let _eal = dpdk::eal::init([
        "--no-huge",
        "--no-pci",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
    ]);

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
    let mut setup = start_router(&shutdown.router, router_params).expect("failed to start router");

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

    let pipeline_factory = setup.pipeline;

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
                    pipeline_data: pipeline_factory().get_data(),
                    flow_table: setup.flow_table,
                    vpcmapw: setup.vpcmapw,
                    nattablesw: setup.nattablesw,
                    natallocatorw: setup.natallocatorw,
                    flowfilterw: setup.flowfiltertablesw,
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
                        todo!();
                    }
                    "kernel" => {
                        info!("Using driver kernel...");
                        Some(DriverKernel::start(
                            scope,
                            &shutdown.workers,
                            args.kernel_interfaces(),
                            args.kernel_num_workers(),
                            &pipeline_factory,
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
