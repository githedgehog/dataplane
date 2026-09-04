// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::packet_processor::start_router;
use crate::statistics::spawn_metrics;
use args::{
    CmdArgs, DriverConfigSection, LaunchConfiguration, Parser, PortArg, TracingDisplayOption,
};

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
use hardware::pci::address::PciAddress;
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

fn init_name(config: &LaunchConfiguration) -> Result<String, String> {
    if let Some(name) = &config.general.name {
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
fn init_logging(config: &LaunchConfiguration, gwname: &str) {
    // Log throttling is on by default; a missing --tracing-rate-limit uses the
    // default. It can be disabled at runtime via the dataplane CLI.
    let rate_limit = config.tracing.rate_limit.as_ref().map_or_else(
        TracingRateLimitConfig::default,
        |rate_limit| TracingRateLimitConfig {
            burst: rate_limit.burst,
            replenish_per_second: rate_limit.replenish_per_second,
        },
    );
    TracingControl::init_with_rate_limit(Some(rate_limit));

    let tctl = get_trace_ctl();
    info!(
        " ━━━━━━ Starting dataplane for gateway '{gwname}' (Version = {}) ━━━━━━",
        option_env!("VERSION").unwrap_or("dev").to_string()
    );

    if config.tracing.config.is_none() {
        tctl.set_default_level(LevelFilter::DEBUG)
            .expect("Setting default loglevel failed");
    }
}

fn process_tracing_cmds(config: &LaunchConfiguration) {
    if let Some(tracing) = &config.tracing.config
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    if config.tracing.show.tags == TracingDisplayOption::Show {
        let out = get_trace_ctl()
            .as_string_by_tag()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    if config.tracing.show.targets == TracingDisplayOption::Show {
        let out = get_trace_ctl()
            .as_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
}

/// Emit the generated tracing configuration and exit, if asked for.
///
/// Only reachable from a command line: it is a developer convenience, not something a launch
/// configuration can express, so it is handled before the arguments become one.
fn process_tracing_cmdline_only(args: &CmdArgs) {
    if args.tracing_config_generate() {
        TracingControl::init_with_rate_limit(None);
        let out = get_trace_ctl()
            .as_config_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
}

fn parse_bmp_params(config: &LaunchConfiguration) -> (Option<BmpServerParams>, Option<BmpOptions>) {
    if let Some(bmp) = &config.bmp {
        let bind_addr = bmp.address;
        let interval: Duration = bmp.interval;

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
fn init_eal(config: &LaunchConfiguration) -> dpdk::eal::Eal {
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

    if let DriverConfigSection::Dpdk(dpdk) = &config.driver {
        // Allow exactly the devices named in the configuration. Without an allowlist the EAL probes
        // every PCI device it recognises, which on a host with more than one NIC means attaching to
        // one the operator did not offer us -- including, potentially, the management uplink.
        for interface in &dpdk.interfaces {
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
/// whatever was bound, so a port missing here was missing then.
///
/// Ports are matched to configuration by **PCI address**, using the same
/// [`PciAddress`] type `dataplane-init` binds them with, so the two agree on what
/// `0000:02:00.1` means rather than each parsing the string their own way.
fn bring_up_ports<'eal>(
    eal: &'eal Eal,
    config: &LaunchConfiguration,
) -> Result<Vec<Port<'eal>>, DriverError> {
    let workers = config.driver.num_workers();
    let num_workers = u16::try_from(workers)
        .map_err(|_| DriverError::PortSetup(format!("{workers} workers is too many")))?;

    // What the EAL actually probed, keyed by PCI address. `DevInfo::name` is the device's bus-level
    // name, which for a PCI device is its extended BDF whatever driver it is bound to -- unlike
    // `if_index`, which is 0 for a `vfio-pci` device because it has no netdev, and unlike the port
    // index, which is only the order the EAL happened to probe in.
    let mut probed: Vec<(PciAddress, DevInfo<'eal>)> = Vec::new();
    for info in eal.dev.iter() {
        let index = info.index();
        let name = info.name().map_err(|e| {
            DriverError::PortSetup(format!("could not read the name of DPDK port {index}: {e}"))
        })?;
        match PciAddress::try_from(name.as_str()) {
            Ok(addr) => probed.push((addr, info)),
            // Not every DPDK device is a PCI device: SoC and virtual devices are named differently.
            // None of those can be named by the configuration, so skipping them is right.
            Err(e) => warn!("DPDK port {index} is named '{name}', which is not a PCI address: {e}"),
        }
    }
    info!(
        "EAL probed {} DPDK port(s): {}",
        probed.len(),
        probed
            .iter()
            .map(|(addr, _)| addr.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut ports = Vec::new();
    for interface in config.driver.interfaces() {
        let Some(PortArg::PCI(ebdf)) = &interface.port else {
            return Err(DriverError::PortSetup(format!(
                "interface '{}' has no PCI address; the DPDK driver needs one \
                 (--interface {}=pci@0000:xx:yy.z)",
                interface.interface, interface.interface
            )));
        };

        let wanted = PciAddress::try_from(ebdf.to_string().as_str()).map_err(|e| {
            DriverError::PortSetup(format!(
                "interface '{}' names '{ebdf}', which is not a valid PCI address: {e}",
                interface.interface
            ))
        })?;

        let at = probed.iter().position(|(addr, _)| *addr == wanted).ok_or_else(|| {
            DriverError::PortSetup(format!(
                "interface '{}' names PCI device {wanted}, which the EAL did not probe. Either it \
                 was not passed to the EAL, or it is not bound to a driver DPDK can attach to -- \
                 binding is dataplane-init's job.",
                interface.interface
            ))
        })?;
        // Removed rather than borrowed, so a device named twice is caught by the lookup above
        // failing the second time rather than quietly producing two ports on one device.
        let (_, info) = probed.remove(at);

        ports.push(Port::bring_up(
            eal,
            info,
            interface.interface.to_string(),
            num_workers,
        )?);
    }

    if !probed.is_empty() {
        warn!(
            "{} probed DPDK port(s) were not named by any interface and will carry no traffic: {}",
            probed.len(),
            probed
                .iter()
                .map(|(addr, _)| addr.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(ports)
}

#[allow(clippy::too_many_lines)]
pub fn main() {
    // Either `dataplane-init` handed us a sealed configuration over the standard descriptors, or we
    // were run directly and have to build one from the command line ourselves. Everything below
    // sees only the configuration, so the two paths differ in exactly one place.
    let config = if LaunchConfiguration::was_inherited() {
        LaunchConfiguration::inherit()
    } else {
        let args = CmdArgs::parse();
        process_tracing_cmdline_only(&args);
        match LaunchConfiguration::try_from(args) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Invalid command line arguments: {e}");
                std::process::exit(1);
            }
        }
    };

    let gwname = match init_name(&config) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Failed to set gateway name: {e}");
            std::process::exit(1);
        }
    };
    init_logging(&config, &gwname);

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
    let eal = init_eal(&config);

    let (bmp_server_params, bmp_client_opts) = parse_bmp_params(&config);

    let dp_status: Arc<RwLock<DataplaneStatus>> = Arc::new(RwLock::new(DataplaneStatus::new()));

    let agent_running = config.profiling.pyroscope_url.as_ref().and_then(|url| {
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

    process_tracing_cmds(&config);

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
        .cli_sock_path(config.cli.cli_sock_path.clone())
        .cpi_sock_path(config.routing.control_plane_socket.clone())
        .frr_agent_path(config.routing.frr_agent_socket.clone());

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
        config.metrics.address,
        setup.stats,
    );

    let ingredients = setup.pipeline;
    let pipeline_data = ingredients.data();

    // Ports are brought up before the worker scope opens, because the queue handles workers own are
    // branded with the borrow of the port they came from: the ports have to outlive every thread
    // that touches one. An empty vector for any other driver.
    let ports = if matches!(config.driver, DriverConfigSection::Dpdk(_)) {
        match bring_up_ports(&eal, &config) {
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
                config_dir: config
                    .config_server
                    .as_ref()
                    .and_then(|c| c.config_dir.clone()),
                hostname: gwname.clone(),
                interfaces: config
                    .driver
                    .interfaces()
                    .map(|i| i.interface.clone())
                    .collect(),
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

                let driver_result = match config.driver.name() {
                    "dpdk" => {
                        info!("Using driver DPDK...");
                        Some(DriverDpdk::start(
                            scope,
                            &shutdown.workers,
                            &ports,
                            config.driver.num_workers(),
                            &ingredients.factory(),
                            driver_status_writer,
                        ))
                    }
                    "kernel" => {
                        info!("Using driver kernel...");
                        Some(DriverKernel::start(
                            scope,
                            &shutdown.workers,
                            config
                                .driver
                                .interfaces()
                                .map(|i| i.interface.to_string())
                                .collect::<Vec<_>>(),
                            config.driver.num_workers(),
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
