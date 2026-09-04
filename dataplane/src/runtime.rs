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

/// Everything that has to happen on the datapath's own thread, in the order it has to happen in.
///
/// # Why this is a thread and not just more of `main`
///
/// The dataplane spans two network namespaces: the control plane stays in the host's, talking to
/// Kubernetes and FRR, while the packet path runs in one that owns the NICs. A thread moves between
/// them with `setns`, which affects the calling thread alone -- so the jump has to happen somewhere
/// that is not `main`, or the control plane would go with it.
///
/// The DPDK objects then pin themselves to this side. `rte_eal_init` only finds devices belonging
/// to the namespace it runs in, so it must run *after* the jump; [`Eal`] is `!Send`; ports borrow
/// the EAL and queues borrow the ports. Once the EAL is created here, everything descended from it
/// has to stay here, which is why this function owns the whole sequence rather than handing pieces
/// back.
///
/// Threads created after the jump inherit the namespace, so the workers spawned below land in it
/// without doing anything themselves.
///
/// # Why it stops twice
///
/// Startup is interleaved with `main`, because the EAL and the packet path are wanted at different
/// moments:
///
/// 1. Enter the namespace and create the EAL, then report through `eal_ready`. `main` waits for
///    that before letting the management plane serve, because applying a configuration builds
///    `rte_acl` classifiers and those need the EAL -- a configuration arriving first would meet a
///    process that cannot compile it.
/// 2. Wait on `go` before touching the hardware, so ports come up and workers start only once
///    management is running. This is where the driver has always started; moving the EAL earlier
///    should not drag the packet path along with it.
fn run_dpdk_datapath(
    config: &LaunchConfiguration,
    netns: Option<&NetworkNamespace>,
    workers: &lifecycle::Subsystem,
    ingredients: PipelineIngredients,
    status_writer: DriverStatusWriter,
    eal_ready: &std::sync::mpsc::Sender<Result<(), String>>,
    go: &std::sync::mpsc::Receiver<()>,
) {
    if let Some(netns) = netns {
        // Both halves matter, and the second is the one that is easy to miss: `setns` gets access
        // to the devices, and the fresh sysfs is what lets them be *enumerated*. Without it the EAL
        // below probes nothing and reports only that no device matched.
        if let Err(e) = netns.enter_with_sysfs() {
            let detail = format!("failed to enter the datapath network namespace: {e}");
            error!("{detail}");
            // Only fails if `main` has already given up, in which case there is nobody to tell.
            drop(eal_ready.send(Err(detail)));
            return;
        }
        info!(
            "Datapath thread is in network namespace {}",
            hardware::netns::current()
        );
    }

    let eal = init_eal(config);

    if eal_ready.send(Ok(())).is_err() {
        info!("The EAL is up but nothing is waiting for it; stopping");
        return;
    }

    // `main` sends nothing and drops this when management fails to start, so a disconnect is the
    // ordinary way to be told to stand down rather than an error.
    if go.recv().is_err() {
        info!("Datapath was told to stand down before starting");
        return;
    }

    let ports = match bring_up_ports(&eal, config) {
        Ok(ports) => ports,
        Err(e) => {
            error!("Failed to bring up DPDK ports: {e}");
            workers.report_fatal("DPDK ports could not be brought up");
            return;
        }
    };

    // An inner scope, because the queue handles the workers own borrow these ports: the ports have
    // to outlive every thread that touches one, and the scope is what proves they do. It returns
    // when the supervisor has joined every worker, which happens once `workers` is cancelled.
    concurrency::thread::scope(|scope| {
        info!("Using driver DPDK...");
        if let Err(e) = DriverDpdk::start(
            scope,
            workers,
            &ports,
            config.driver.num_workers(),
            &ingredients.factory(),
            status_writer,
        ) {
            error!("Failed to start driver: {e}");
            workers.report_fatal("the DPDK driver could not be started");
        }
    });

    // Every worker has been joined, so the queue handles that borrowed these ports are gone and the
    // ports can be stopped. Explicitly, rather than leaving it to `PortLifecycle`'s `Drop`
    // backstop, so a device that refuses to stop is reported.
    for port in ports {
        port.shutdown();
    }
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
    //
    // Which *thread* initializes it is not a free choice. With the DPDK driver the EAL is created
    // on the datapath thread instead of here, because that thread may first have moved into
    // another network namespace and `rte_eal_init` only finds devices belonging to the namespace
    // it runs in. Everything the EAL hands out is branded with its lifetime and `Eal` is `!Send`,
    // so the EAL, the ports and the workers all have to live on that side together. See
    // `run_dpdk_datapath`.
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

    // The namespace `dataplane-init` made for the datapath, if it made one. It arrives as a
    // descriptor rather than a name, which is what keeps it alive: there is no bind mount to
    // outlive this process and nothing to clean up, and when the last descriptor closes the kernel
    // destroys the namespace and returns the devices to the host.
    let datapath_netns = LaunchConfiguration::inherit_netns().map(NetworkNamespace::from_fd);
    if datapath_netns.is_some() {
        info!("Inherited a network namespace for the datapath");
    }

    concurrency::thread::scope(|scope| {
        // Two handshakes with the datapath thread. `eal_ready` is how it reports that the EAL
        // exists, which management must not serve without; `go` is how it is told management is
        // running and the hardware can come up. See `run_dpdk_datapath`.
        let (eal_ready_tx, eal_ready_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel();

        // Only one driver ever runs, but the compiler cannot see that this arm and the kernel arm
        // further down are exclusive, so ownership of the pipeline factory and the status writer
        // goes to whichever one claims it here.
        let kernel_driver = match config.driver {
            DriverConfigSection::Dpdk(_) => {
                let spawned = thread::Builder::new()
                    .name("dpdk-datapath".to_string())
                    .spawn_scoped(scope, {
                        let config = &config;
                        let netns = datapath_netns.as_ref();
                        let workers = &shutdown.workers;
                        move || {
                            run_dpdk_datapath(
                                config,
                                netns,
                                workers,
                                ingredients,
                                driver_status_writer,
                                &eal_ready_tx,
                                &go_rx,
                            );
                        }
                    });
                // A failure here is fatal but not a reason to leave by a different door: tripping
                // the root token makes `run_mgmt` below report `Cancelled`, and the shutdown then
                // drains in the usual order. Returning early instead would skip that drain.
                if let Err(e) = spawned {
                    error!("Failed to spawn the datapath thread: {e}");
                    shutdown.fail();
                } else {
                    // Nothing below may serve a configuration until the EAL exists.
                    match eal_ready_rx.recv() {
                        Ok(Ok(())) => info!("The EAL is up; starting management"),
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
                None
            }
            // The kernel driver has no namespace to enter and its EAL is already up, so it starts
            // below in this scope exactly as it always has.
            DriverConfigSection::Kernel(_) => Some((ingredients, driver_status_writer)),
        };

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

                match kernel_driver {
                    Some((ingredients, driver_status_writer)) => {
                        info!("Using driver kernel...");
                        if let Err(e) = DriverKernel::start(
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
                        ) {
                            error!("Failed to start driver: {e}");
                            shutdown.fail();
                        }
                    }
                    // The DPDK datapath is already waiting on its own thread with the EAL up. This
                    // releases it to bring the ports up and start polling.
                    None => {
                        if go_tx.send(()).is_err() {
                            error!("The datapath thread is gone; cannot start the packet path");
                            shutdown.fail();
                        }
                    }
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
