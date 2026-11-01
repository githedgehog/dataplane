// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rate limit VXLAN traffic per VNI, and optionally per inner destination prefix, in the meters of
//! mlx5 NICs, in front of the dataplane's kernel driver.
//!
//! The kernel driver reads its ports with `AF_PACKET` sockets, which see every frame before tc or
//! netfilter ingress can drop it; a limit there would come too late.
//! This program instead isolates each port's DPDK side (mlx5 is bifurcated: the kernel keeps every
//! packet no DPDK rule takes) and installs hardware rules that meter the configured traffic, return
//! what conforms to the kernel, and drop the rest in the NIC.
//! See [`pipeline`] for the rules.
//!
//! The rules live as long as this process: if it exits or dies, traffic is no longer limited.

mod config;
mod pipeline;
mod report;

use clock::Duration;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
// A signal handler's flag is one per process, outside any model checker's execution.
use concurrency::process_global::atomic::{AtomicBool, Ordering};
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::flow::template::{TemplateConfig, TemplateError, TemplateFlows};
use dpdk::mem::{PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use tracing::{error, info};

use config::{Config, ConfigError};
use pipeline::{InstallError, Plan, PortCounts, Rules, Tables, Templates};

/// Packet buffers for the receive queue, which isolation leaves idle.
const POOL_MBUFS: u32 = 1023;

/// Receive and transmit descriptors; the queues carry no traffic.
const DESCRIPTORS: u16 = 256;

/// How often the main loop checks for a stop signal.
const TICK: Duration = Duration::from_millis(200);

#[derive(Debug, Parser)]
#[command(about = "Rate limit VXLAN traffic per VNI in mlx5 NICs, in front of the kernel driver")]
struct Cli {
    /// The YAML file of limits.
    #[arg(long)]
    config: PathBuf,
    /// The PCI address of the port to limit, e.g. 0000:02:00.0. Run one process per port: with
    /// two in one process, mlx5 fails to create the first port's tables once the second is
    /// configured. Each port enforces every limit on its own.
    #[arg(long = "pci")]
    pci: Vec<String>,
    /// Seconds between counter reports on standard output; 0 reports only at exit.
    #[arg(long, default_value_t = 10)]
    stats_interval: u64,
    /// Also write each report to this file, replacing the previous one.
    #[arg(long)]
    stats_file: Option<PathBuf>,
    /// Use hugepages for DPDK memory. The queues are idle, so ordinary memory serves by default.
    #[arg(long)]
    hugepages: bool,
    /// An extra EAL argument, e.g. `--eal-arg=--log-level=pmd.net.mlx5:debug` (repeat for more).
    #[arg(long = "eal-arg", allow_hyphen_values = true)]
    eal_args: Vec<String>,
    /// Validate the configuration, print the limits, and exit.
    #[arg(long)]
    check: bool,
}

/// Failures, reported at exit.
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("no port to limit: name one with --pci")]
    NoPorts,
    #[error("cannot install signal handlers: {0}")]
    Signal(nix::Error),
    #[error("DPDK has no port {pci}; it found {found:?}")]
    NoSuchPort { pci: String, found: Vec<String> },
    /// Port bring-up failures carry their cause as text: the `dpdk` errors here borrow the EAL or
    /// do not implement `Error`, and nothing handles them but the report at exit.
    #[error("port {pci}: {step} failed: {detail}")]
    Port {
        pci: String,
        step: &'static str,
        detail: String,
    },
    #[error("port {pci}: {source}")]
    Template { pci: String, source: TemplateError },
    #[error("port {pci}: {source}")]
    Install { pci: String, source: InstallError },
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: nix::libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() -> Result<(), Error> {
    let action = SigAction::new(
        SigHandler::Handler(request_stop),
        SaFlags::empty(),
        SigSet::empty(),
    );
    for signal in [Signal::SIGINT, Signal::SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe { sigaction(signal, &action) }.map_err(Error::Signal)?;
    }
    Ok(())
}

/// The EAL arguments: no shared files, the allowed CPUs, and hardware steering on every port.
fn eal_args(cli: &Cli) -> Vec<String> {
    let mut args = vec![
        "--in-memory".to_string(),
        "--lcores".to_string(),
        dpdk::eal::main_lcore_arg(),
    ];
    if !cli.hugepages {
        args.push("--no-huge".to_string());
    }
    for pci in &cli.pci {
        args.push("-a".to_string());
        args.push(format!("{pci},dv_flow_en=2"));
    }
    args.extend(cli.eal_args.iter().cloned());
    args
}

/// The MTU of the kernel interface `if_index`, which a bifurcated port shares with DPDK.
fn kernel_mtu(if_index: u32) -> Result<u16, String> {
    if if_index == 0 {
        return Err("the port has no kernel interface, so it is not bifurcated".to_string());
    }
    let name = nix::net::if_::if_indextoname(if_index)
        .map_err(|e| format!("interface {if_index}: {e}"))?;
    let name = name.to_string_lossy();
    let path = format!("/sys/class/net/{name}/mtu");
    std::fs::read_to_string(&path)
        .map_err(|e| format!("{path}: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("{path}: {e}"))
}

/// Configure, isolate and start a port, with idle queues and room for the limits' rules.
fn start_port<'eal>(
    eal: &'eal Eal,
    pci: &str,
    resources: &TemplateConfig,
) -> Result<Dev<'eal, Started>, Error> {
    let fail = |step, detail: String| Error::Port {
        pci: pci.to_string(),
        step,
        detail,
    };
    let names: Vec<_> = eal.dev.iter().filter_map(|d| d.name().ok()).collect();
    let index = eal
        .dev
        .iter()
        .find(|d| d.name().is_ok_and(|name| name == pci))
        .map(|d| d.index())
        .ok_or_else(|| Error::NoSuchPort {
            pci: pci.to_string(),
            found: names,
        })?;
    let claim = eal
        .claim(index)
        .map_err(|e| fail("claiming the port", e.to_string()))?;
    let mtu = kernel_mtu(claim.info().if_index())
        .map_err(|e| fail("reading the kernel interface's MTU", e))?;
    let config = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        // mlx5 sets the kernel interface's MTU to this when the port is configured
        // (`mlx5_dev_configure`), so it must be the one the interface already has.
        mtu: Some(mtu),
        rss: None,
    };
    let mut dev = config
        .apply(claim)
        .map_err(|e| fail("configuring the port", e.error.to_string()))?;
    dev.isolate()
        .map_err(|e| fail("isolating the port", e.to_string()))?;
    dev.configure_templates(resources)
        .map_err(|e| fail("configuring template rules", e.to_string()))?;
    let pool = eal
        .mem
        .new_pkt_pool(
            PoolConfig::new(
                format!("vni_limit_{index}"),
                PoolParams {
                    size: POOL_MBUFS,
                    cache_size: 0,
                    ..Default::default()
                },
            )
            .map_err(|e| fail("configuring a packet pool", format!("{e:?}")))?,
        )
        .map_err(|e| fail("creating a packet pool", format!("{e:?}")))?;
    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(0),
        num_descriptors: DESCRIPTORS,
        socket_preference: socket::Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool,
    })
    .map_err(|e| fail("setting up the receive queue", e.to_string()))?;
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: DESCRIPTORS,
        socket_preference: socket::Preference::Dev(index),
        config: (),
    })
    .map_err(|e| fail("setting up the transmit queue", e.to_string()))?;
    dev.start()
        .map_err(|e| fail("starting the port", e.error.to_string()))
}

/// Write `text` to `path` through a temporary file, so readers never see half a report.
fn replace_file(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)
}

/// Print every port's counter table, and replace the stats file with it.
fn report(cli: &Cli, config: &Config, rules: &[Rules<'_>], last: &mut [PortCounts], seconds: f64) {
    let at = chrono::DateTime::<chrono::Utc>::from(clock::system_now())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut text = format!("vni-limit counters at {at}\n\n");
    for ((pci, rules), last) in cli.pci.iter().zip(rules).zip(last.iter_mut()) {
        match rules.counts() {
            Ok(now) => {
                text.push_str(&report::render(pci, config, last, &now, seconds));
                text.push('\n');
                *last = now;
            }
            Err(e) => error!("port {pci}: cannot read the counters: {e}"),
        }
    }
    print!("{text}");
    if let Some(path) = &cli.stats_file
        && let Err(e) = replace_file(path, &text)
    {
        error!("cannot write {}: {e}", path.display());
    }
}

fn run(cli: &Cli) -> Result<(), Error> {
    let yaml = std::fs::read_to_string(&cli.config).map_err(|source| Error::Read {
        path: cli.config.clone(),
        source,
    })?;
    let config = Config::parse(&yaml)?;
    for limit in &config.limits {
        info!(
            "{limit}: {} bit/s, burst {} bytes",
            limit.cir_bytes * 8,
            limit.cbs_bytes
        );
    }
    if cli.check {
        return Ok(());
    }
    if cli.pci.is_empty() {
        return Err(Error::NoPorts);
    }
    let plan = Plan::new(&config);
    let resources = Plan::resources(&config);

    // Each layer borrows the one before, and they drop in reverse: rules, tables, templates,
    // contexts, ports, then the EAL.
    let eal = dpdk::eal::init(eal_args(cli));
    install_signal_handlers()?;
    let ports = cli
        .pci
        .iter()
        .map(|pci| start_port(&eal, pci, &resources))
        .collect::<Result<Vec<_>, _>>()?;
    let flows = ports
        .iter()
        .zip(&cli.pci)
        .map(|(dev, pci)| {
            TemplateFlows::new(dev).map_err(|source| Error::Template {
                pci: pci.clone(),
                source,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let install = |pci: &String| {
        let pci = pci.clone();
        move |source| Error::Install { pci, source }
    };
    let templates = flows
        .iter()
        .zip(&cli.pci)
        .map(|(flows, pci)| Templates::new(flows, &plan, &config).map_err(install(pci)))
        .collect::<Result<Vec<_>, _>>()?;
    let tables = flows
        .iter()
        .zip(&templates)
        .zip(&cli.pci)
        .map(|((flows, templates), pci)| Tables::new(flows, templates, &plan).map_err(install(pci)))
        .collect::<Result<Vec<_>, _>>()?;
    let rules = tables
        .iter()
        .zip(&cli.pci)
        .map(|(tables, pci)| Rules::new(tables, &plan, &config).map_err(install(pci)))
        .collect::<Result<Vec<_>, _>>()?;
    for (pci, rules) in cli.pci.iter().zip(&rules) {
        info!(
            "port {pci}: {} limit(s) installed behind {} root rule(s)",
            config.limits.len(),
            rules.root_rules()
        );
    }

    let interval = Duration::from_secs(cli.stats_interval);
    let mut last: Vec<PortCounts> = rules
        .iter()
        .map(|r| r.counts().unwrap_or_default())
        .collect();
    let mut since = clock::now();
    while !STOP.load(Ordering::Relaxed) {
        std::thread::sleep(TICK);
        let elapsed = clock::elapsed(since);
        if !interval.is_zero() && elapsed >= interval {
            report(cli, &config, &rules, &mut last, elapsed.as_secs_f64());
            since = clock::now();
        }
    }
    // The last report, before the rules and their counters go.
    report(
        cli,
        &config,
        &rules,
        &mut last,
        clock::elapsed(since).as_secs_f64(),
    );
    info!("stopping: removing the rules; traffic is no longer limited");
    Ok(())
}

fn main() -> ExitCode {
    // Reports go to standard output; logs stay out of their way.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}
