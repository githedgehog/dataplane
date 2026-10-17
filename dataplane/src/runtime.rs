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
use crate::drivers::status::{DriverStatusWriter, driver_status_access};
use crate::packet_processor::PipelineIngredients;
use concurrency::thread;
#[allow(unused_imports)] // used under the loom/shuttle backends
use concurrency::thread::BuilderExt;
use hardware::netns::NetworkNamespace;
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

fn process_tracing_cmds(config: Option<&str>, show_tags: bool, show_targets: bool) {
    if let Some(tracing) = config
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    if show_tags {
        let out = get_trace_ctl()
            .as_string_by_tag()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    if show_targets {
        let out = get_trace_ctl()
            .as_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
}

/// Display tracing information before validating launch configuration or initializing EAL.
fn process_tracing_cmdline_only(args: &CmdArgs) {
    if !args.is_informational() {
        return;
    }
    TracingControl::init_with_rate_limit(None);
    if args.tracing_config_generate() {
        let out = get_trace_ctl()
            .as_config_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    process_tracing_cmds(
        args.tracing().map(String::as_str),
        args.show_tracing_tags(),
        args.show_tracing_targets(),
    );
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

/// Keep EAL initialization separate from explicit device attachment.
fn eal_arguments(config: &LaunchConfiguration) -> Vec<String> {
    let main_lcore_arg = dpdk::eal::main_lcore_arg();

    let mut eal_args: Vec<String> = vec![
        "--no-auto-probing".to_string(),
        "--in-memory".to_string(),
        "--no-telemetry".to_string(),
        "--no-shconf".to_string(),
        "--iova-mode=va".to_string(),
        "--lcores".to_string(),
        main_lcore_arg,
    ];

    if !matches!(config.driver, DriverConfigSection::Dpdk(_)) {
        // Classifier-only: rte_acl needs the memory subsystem and nothing else.
        eal_args.push("--no-huge".to_string());
        eal_args.push("--no-pci".to_string());
    }

    eal_args
}

fn init_eal(config: &LaunchConfiguration) -> dpdk::eal::Eal {
    let eal_args = eal_arguments(config);
    info!("Initializing DPDK EAL with: {}", eal_args.join(" "));
    dpdk::eal::init(eal_args)
}

/// Validate every interface before probing any device.
fn configured_pci_ports(
    config: &LaunchConfiguration,
) -> Result<Vec<(String, PciAddress)>, DriverError> {
    let mut selected = Vec::new();
    let mut addresses = std::collections::BTreeSet::new();
    for interface in config.driver.interfaces() {
        let name = interface.interface.to_string();
        let Some(PortArg::PCI(ebdf)) = &interface.port else {
            return Err(DriverError::PortSetup(format!(
                "interface '{name}' needs a PCI address (--interface {name}=pci@0000:xx:yy.z)"
            )));
        };
        let address = PciAddress::try_from(ebdf.to_string().as_str()).map_err(|e| {
            DriverError::PortSetup(format!(
                "interface '{name}' has an invalid PCI address: {e}"
            ))
        })?;
        if !addresses.insert(address) {
            return Err(DriverError::PortSetup(format!(
                "PCI device {address} is configured more than once"
            )));
        }
        selected.push((name, address));
    }
    if selected.is_empty() {
        return Err(DriverError::PortSetup(
            "no PCI devices were configured".to_string(),
        ));
    }
    Ok(selected)
}

/// Probe, configure and start the selected devices. Init must prepare their kernel bindings first.
fn bring_up_ports<'eal>(
    eal: &'eal mut Eal,
    config: &LaunchConfiguration,
) -> Result<Vec<Port<'eal>>, DriverError> {
    let num_workers = u16::try_from(config.driver.num_workers()).map_err(|_| {
        DriverError::PortSetup(format!(
            "{} workers is too many",
            config.driver.num_workers()
        ))
    })?;
    let selected = configured_pci_ports(config)?;
    for (name, address) in &selected {
        eal.probe_pci(*address)
            .map_err(|e| DriverError::PortSetup(format!("interface '{name}': {e}")))?;
    }

    // Index probed ports whose ethdev names parse as PCI addresses.
    let mut probed: Vec<(PciAddress, DevInfo<'eal>)> = Vec::new();
    for info in eal.dev.iter() {
        let index = info.index();
        let name = info.name().map_err(|e| {
            DriverError::PortSetup(format!("could not read the name of DPDK port {index}: {e}"))
        })?;
        match PciAddress::try_from(name.as_str()) {
            Ok(addr) => probed.push((addr, info)),
            // Configuration currently accepts only PCI addresses.
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
    for (name, wanted) in selected {
        // TODO: Resolve suffixed PMD port names when init supports eswitch configuration.
        let at = probed.iter().position(|(addr, _)| *addr == wanted).ok_or_else(|| {
            DriverError::PortSetup(format!(
                "interface '{name}': probing PCI device {wanted} produced no Ethernet port with that name"
            ))
        })?;
        let (_, info) = probed.remove(at);
        let index = info.index();
        // Claim before any setup, so a port something else owns is refused up front.
        let port = eal
            .claim(index)
            .map_err(|e| DriverError::PortSetup(format!("cannot use port {index}: {e}")))?;

        ports.push(Port::bring_up(eal, port, name, num_workers)?);
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

/// Move the calling thread into the datapath namespace, unless it is already there.
fn enter_datapath_netns(netns: &NetworkNamespace) -> Result<(), String> {
    let current = netns
        .is_current()
        .map_err(|e| format!("failed to identify the datapath network namespace: {e}"))?;
    if current {
        info!("The datapath shares the management network namespace");
        return Ok(());
    }
    // libibverbs needs sysfs mounted in the destination network namespace.
    netns
        .enter_with_sysfs()
        .map_err(|e| format!("failed to enter the datapath network namespace: {e}"))?;
    info!(
        "Datapath thread is in network namespace {}",
        hardware::netns::current()
    );
    Ok(())
}

/// Run the packet path on a thread in the datapath namespace.
///
/// Report readiness once the namespace is entered (and, for DPDK, the EAL exists, since management
/// builds ACL classifiers in it), then wait for management startup before touching any device.
/// Driver threads inherit this thread's namespaces.
#[allow(clippy::too_many_arguments)]
fn run_datapath(
    config: &LaunchConfiguration,
    netns: &NetworkNamespace,
    workers: &lifecycle::Subsystem,
    timer_handle: &tokio::runtime::Handle,
    ingredients: PipelineIngredients,
    status_writer: DriverStatusWriter,
    ready: &std::sync::mpsc::Sender<Result<(), String>>,
    go: &std::sync::mpsc::Receiver<()>,
) {
    if let Err(detail) = enter_datapath_netns(netns) {
        error!("{detail}");
        drop(ready.send(Err(detail)));
        return;
    }

    let eal = match config.driver {
        DriverConfigSection::Dpdk(_) => Some(init_eal(config)),
        DriverConfigSection::Kernel(_) => None,
    };

    if ready.send(Ok(())).is_err() {
        info!("The datapath is ready but nothing is waiting for it; stopping");
        return;
    }

    // A disconnected channel means management startup failed or was cancelled.
    if go.recv().is_err() {
        info!("Datapath was told to stand down before starting");
        return;
    }

    match eal {
        Some(mut eal) => run_dpdk_driver(
            &mut eal,
            config,
            workers,
            timer_handle,
            ingredients,
            status_writer,
        ),
        None => run_kernel_driver(config, workers, ingredients, status_writer),
    }
}

/// Run the kernel driver until its workers stop.
fn run_kernel_driver(
    config: &LaunchConfiguration,
    workers: &lifecycle::Subsystem,
    ingredients: PipelineIngredients,
    status_writer: DriverStatusWriter,
) {
    concurrency::thread::scope(|scope| {
        info!("Using driver kernel...");
        if let Err(e) = DriverKernel::start(
            scope,
            workers,
            config
                .driver
                .interfaces()
                .map(|i| i.interface.to_string())
                .collect::<Vec<_>>(),
            config.driver.num_workers(),
            &ingredients.factory(),
            status_writer,
        ) {
            error!("Failed to start driver: {e}");
            workers.report_fatal("the kernel driver could not be started");
        }
    });
}

/// Bring up the DPDK ports and run their workers until they stop.
fn run_dpdk_driver(
    eal: &mut Eal,
    config: &LaunchConfiguration,
    workers: &lifecycle::Subsystem,
    timer_handle: &tokio::runtime::Handle,
    ingredients: PipelineIngredients,
    status_writer: DriverStatusWriter,
) {
    let ports = match bring_up_ports(eal, config) {
        Ok(ports) => ports,
        Err(e) => {
            error!("Failed to bring up DPDK ports: {e}");
            workers.report_fatal("DPDK ports could not be brought up");
            return;
        }
    };

    // Queue handles borrow the ports, so workers must join before port shutdown.
    concurrency::thread::scope(|scope| {
        info!("Using driver DPDK...");
        if let Err(e) = DriverDpdk::start(
            scope,
            workers,
            timer_handle,
            &ports,
            config.driver.num_workers(),
            &ingredients.factory(),
            status_writer,
        ) {
            error!("Failed to start driver: {e}");
            workers.report_fatal("the DPDK driver could not be started");
        }
    });

    // Explicit shutdown reports errors that the Drop backstop would suppress.
    for port in ports {
        port.shutdown();
    }
}

#[allow(clippy::too_many_lines)]
pub fn main() {
    // Consume the handoff before runtimes or other components can acquire these FD numbers.
    let inherited = LaunchConfiguration::was_inherited().unwrap_or_else(|e| {
        eprintln!("Invalid init handoff: {e}");
        std::process::exit(1);
    });
    if !inherited {
        // Init forwards informational commands here, since only this binary knows every
        // tracing target. Anything else must be prepared by init.
        let args = CmdArgs::parse();
        process_tracing_cmdline_only(&args);
        eprintln!("The dataplane must be launched by dataplane-init, with the same arguments");
        std::process::exit(1);
    }
    // SAFETY: this is the only handoff reader, at process startup before other FD owners.
    let config = unsafe { LaunchConfiguration::inherit() };
    // SAFETY: init owns the reserved namespace FD; no other startup component has run yet.
    let datapath_netns = unsafe { LaunchConfiguration::inherit_netns() }
        .map_err(|e| e.to_string())
        .and_then(|fd| NetworkNamespace::from_fd(fd).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            eprintln!("Invalid datapath namespace handoff: {e}");
            std::process::exit(1);
        });

    let gwname = match init_name(&config) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("Failed to set gateway name: {e}");
            std::process::exit(1);
        }
    };
    init_logging(&config, &gwname);
    process_tracing_cmds(
        config.tracing.config.as_deref(),
        config.tracing.show.tags == TracingDisplayOption::Show,
        config.tracing.show.targets == TracingDisplayOption::Show,
    );

    // The DPDK EAL belongs to the datapath thread, which enters its namespace first.
    // The kernel driver only needs EAL memory for ACL classifiers.
    let _eal = match config.driver {
        DriverConfigSection::Dpdk(_) => None,
        DriverConfigSection::Kernel(_) => Some(init_eal(&config)),
    };

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

    concurrency::thread::scope(|scope| {
        // Management waits for the datapath to be ready, then releases it after its own startup.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();

        let spawned = thread::Builder::new()
            .name("datapath".to_string())
            .spawn_scoped(scope, {
                let config = &config;
                let netns = &datapath_netns;
                let workers = &shutdown.workers;
                let timer_handle = &mgmt_handle;
                move || {
                    run_datapath(
                        config,
                        netns,
                        workers,
                        timer_handle,
                        ingredients,
                        driver_status_writer,
                        &ready_tx,
                        &go_rx,
                    );
                }
            });
        // Cancel on failure, then follow the normal shutdown path.
        if let Err(e) = spawned {
            error!("Failed to spawn the datapath thread: {e}");
            shutdown.fail();
        } else {
            // Nothing below may serve a configuration until a DPDK EAL exists.
            match ready_rx.recv() {
                Ok(Ok(())) => info!("The datapath is ready; starting management"),
                Ok(Err(e)) => {
                    error!("The datapath failed to start: {e}");
                    shutdown.fail();
                }
                Err(_) => {
                    error!("The datapath thread stopped without reporting why");
                    shutdown.fail();
                }
            }
        }

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

                // Release the datapath to bring up its devices and start workers.
                if go_tx.send(()).is_err() {
                    error!("The datapath thread is gone; cannot start the packet path");
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

#[cfg(test)]
mod probe_tests {
    use super::*;

    // Inherited configurations may contain interface lists rejected by CLI conversion.
    fn launch_config(args: &CmdArgs) -> LaunchConfiguration {
        let driver = args.driver_name().unwrap();
        let interface = if driver == "kernel" {
            "eth0=kernel@eth0"
        } else {
            "eth0=pci@0000:01:00.0"
        };
        let mut config = LaunchConfiguration::try_from(
            CmdArgs::try_parse_from(["dataplane", "--driver", driver, "--interface", interface])
                .unwrap(),
        )
        .unwrap();
        match &mut config.driver {
            DriverConfigSection::Dpdk(driver) => driver.interfaces = args.interfaces().collect(),
            DriverConfigSection::Kernel(driver) => driver.interfaces = args.interfaces().collect(),
        }
        config
    }

    #[test]
    fn eal_never_probes_configured_interfaces_implicitly() {
        for command_line in [
            vec!["dataplane", "--driver", "dpdk"],
            vec![
                "dataplane",
                "--driver",
                "dpdk",
                "--interface",
                "eth0=pci@0000:01:00.0",
            ],
            vec![
                "dataplane",
                "--driver",
                "kernel",
                "--interface",
                "eth0=kernel@eth0",
            ],
        ] {
            let args = CmdArgs::try_parse_from(command_line).unwrap();
            let config = launch_config(&args);
            let flags = eal_arguments(&config);
            assert!(flags.iter().any(|flag| flag == "--no-auto-probing"));
            assert!(!flags.iter().any(|flag| matches!(
                flag.as_str(),
                "-a" | "--allow" | "--auto-probing" | "--vdev"
            )));
            assert!(!flags.iter().any(|flag| flag.contains("0000:01:00.0")));
            assert_eq!(
                flags.iter().any(|flag| flag == "--no-pci"),
                args.driver_name() == Some("kernel")
            );
        }
    }

    #[test]
    fn validate_all_interfaces_before_selecting_devices() {
        for (interfaces, message) in [
            (None, "no PCI devices"),
            (
                Some("eth0=pci@0000:01:00.0,eth1=kernel@eth1"),
                "needs a PCI address",
            ),
            (
                Some("eth0=pci@0000:ab:00.0,eth1=pci@0000:AB:00.0"),
                "configured more than once",
            ),
        ] {
            let mut command_line = vec!["dataplane", "--driver", "dpdk"];
            if let Some(interfaces) = interfaces {
                command_line.extend(["--interface", interfaces]);
            }
            let args = CmdArgs::try_parse_from(command_line).unwrap();
            assert!(
                configured_pci_ports(&launch_config(&args))
                    .unwrap_err()
                    .to_string()
                    .contains(message)
            );
        }
        let args = CmdArgs::try_parse_from([
            "dataplane",
            "--driver",
            "dpdk",
            "--interface",
            "eth1=pci@0000:02:00.0,eth0=pci@0000:01:00.0",
        ])
        .unwrap();
        assert_eq!(
            configured_pci_ports(&launch_config(&args)).unwrap(),
            vec![
                (
                    "eth1".to_string(),
                    PciAddress::try_from("0000:02:00.0").unwrap()
                ),
                (
                    "eth0".to_string(),
                    PciAddress::try_from("0000:01:00.0").unwrap()
                ),
            ]
        );
    }
}
