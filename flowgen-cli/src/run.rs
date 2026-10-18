// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Running a scenario on a real port, and reporting it.

use std::io::Write;
use std::path::Path;

use dpdk::dev::{DevIndex, Started};
use dpdk::eal::{self, Eal};
use flowgen::bfd::{Peer, Session};
use flowgen::drive::{Agent, Ending, Load, Patience, Wire, run as generate};
use flowgen::ledger::Ledgers;
use flowgen::port::{self, PortSetup, Queues};
use flowgen::sender::{Clock, Sender};
use flowgen::tcp::Host;
use flowgen_report::{
    Bound, Build, Case, Environment, Evidence, Header, Port as ReportPort, Report, Sample, Status,
};
use hardware::pci::address::PciAddress;

use crate::scenario::{AgentSpec, CaseSpec, Device, Scenario};
use crate::scrape;

/// Why a run could not start.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The scenario is not runnable.
    #[error(transparent)]
    Scenario(#[from] crate::scenario::ScenarioError),
    /// The port could not be found or brought up.
    #[error("port: {0}")]
    Port(String),
    /// The report could not be written.
    #[error("report: {0}")]
    Report(#[from] std::io::Error),
}

/// The EAL arguments a run uses: the ones every run needs, then the device's, then `extra`.
fn eal_args(device: &Device<'_>, extra: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "--in-memory",
        "--no-telemetry",
        "--iova-mode=va",
        "--lcores",
    ]
    .map(str::to_string)
    .to_vec();
    args.push(eal::main_lcore_arg());
    match device {
        // Probed explicitly below, and nothing else: a generator must never take a device it
        // was not given, least of all on a host whose other NICs carry real traffic.
        Device::Pci(_) => args.push("--no-auto-probing".to_string()),
        Device::Vdev(spec) => {
            args.push("--no-pci".to_string());
            args.push(format!("--vdev={spec}"));
        }
    }
    args.extend(extra.iter().cloned());
    args
}

/// The port `device` is, attaching it first if it is a PCI device.
fn find(eal: &mut Eal, device: &Device<'_>) -> Result<DevIndex, RunError> {
    let wanted = match device {
        Device::Pci(address) => {
            let parsed = PciAddress::try_from(*address)
                .map_err(|e| RunError::Port(format!("{address} is not a PCI address: {e}")))?;
            eal.probe_pci(parsed)
                .map_err(|e| RunError::Port(e.to_string()))?;
            parsed.to_string()
        }
        Device::Vdev(spec) => spec.split(',').next().unwrap_or(spec).to_string(),
    };
    eal.dev
        .iter()
        .find(|info| info.name().is_ok_and(|name| name == wanted))
        .map(|info| info.index())
        .ok_or_else(|| RunError::Port(format!("no Ethernet port is called {wanted}")))
}

/// The report's header for `scenario`, run on `dev` with `eal_args`.
fn header(scenario: &Scenario, dev: &dpdk::dev::Dev<'_, Started>, eal_args: &[String]) -> Header {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|name| name.trim().to_string());
    let mut header = Header::new(
        Build {
            name: "flowgen".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("FLOWGEN_COMMIT").map(str::to_string),
        },
        Environment {
            host,
            cpus: std::thread::available_parallelism()
                .ok()
                .map(std::num::NonZero::get),
            workers: None,
            ports: vec![ReportPort {
                name: scenario.port.name.clone(),
                driver: Some(dev.info().driver_name().to_string()),
                device: dev.info().name().ok(),
            }],
            eal_args: eal_args.to_vec(),
        },
        serde_json::to_value(scenario).unwrap_or_default(),
    );
    header.seed = None;
    header
}

/// The agents `scenario` names, starting at `now_ns`.
fn agents(scenario: &Scenario, now_ns: u64) -> Vec<Box<dyn Agent>> {
    scenario
        .agents
        .iter()
        .map(|spec| -> Box<dyn Agent> {
            match spec {
                AgentSpec::Bfd {
                    name,
                    endpoints,
                    session,
                } => Box::new(Peer::new(
                    name,
                    0,
                    *endpoints,
                    Session::new(*session, now_ns),
                )),
                AgentSpec::Host {
                    name,
                    mac,
                    addresses,
                    announce_every,
                } => Box::new(flowgen::host::Host::new(
                    name,
                    0,
                    flowgen::host::Config {
                        mac: *mac,
                        addresses: addresses.clone(),
                        announce_every: (!announce_every.is_zero()).then_some(*announce_every),
                    },
                )),
                AgentSpec::Tcp {
                    name,
                    addressing,
                    encap,
                    role,
                } => Box::new(Host::new(
                    name,
                    0,
                    *addressing,
                    *encap,
                    role.clone(),
                    now_ns,
                )),
            }
        })
        .collect()
}

/// What a run reads besides its own ledgers: its port's counters, and the gateway's telemetry.
struct Probe<'a, 'eal> {
    dev: &'a dpdk::dev::Dev<'eal, Started>,
    name: &'a str,
    telemetry: Option<&'a str>,
    scrape_errors: u64,
}

impl Probe<'_, '_> {
    fn sample(&mut self) -> Sample {
        let sample = port::counters(self.dev, self.name, Sample::new());
        let sample = if let Some(url) = self.telemetry {
            if let Ok(text) = scrape::fetch(url) {
                flowgen::prometheus::sample(&text, "dataplane", sample)
            } else {
                self.scrape_errors += 1;
                sample
            }
        } else {
            sample
        };
        sample.counter("telemetry.scrape_errors", self.scrape_errors)
    }
}

/// Run `scenario`, reporting to `report_path`, with `extra` EAL arguments; say how it came out.
///
/// # Errors
///
/// If the run cannot start: the scenario is not runnable, the port cannot be had, or the report
/// cannot be written. Once it has started, everything else is in the report.
pub fn run(scenario: &Scenario, report_path: &Path, extra: &[String]) -> Result<Status, RunError> {
    let device = scenario.port.device()?;
    let mut extra_args = scenario.eal.clone();
    extra_args.extend(extra.iter().cloned());
    let eal_args = eal_args(&device, &extra_args);
    let mut eal = eal::init(eal_args.iter());
    let index = find(&mut eal, &device)?;
    let eal: &Eal = &eal;
    let setup = PortSetup {
        queues: scenario.port.queues,
        descriptors: scenario.port.descriptors,
        pool_size: scenario.port.pool_size,
        mtu: scenario.port.mtu,
    };
    let (dev, pool) = port::start(eal, index, setup).map_err(|e| RunError::Port(e.to_string()))?;
    let mut queues = port::take(&dev, setup.queues).map_err(|e| RunError::Port(e.to_string()))?;

    let out: Box<dyn Write> =
        Box::new(std::io::BufWriter::new(std::fs::File::create(report_path)?));
    let mut report = Report::new(out, header(scenario, &dev, &eal_args))?;
    let clock = Clock::start();
    let mut agents = agents(scenario, clock.now_ns());
    let mut probe = Probe {
        dev: &dev,
        name: &scenario.port.name,
        telemetry: scenario.telemetry.as_ref().map(|t| t.url.as_str()),
        scrape_errors: 0,
    };
    let mut wire = Queues {
        tx: &mut queues.tx,
        rx: &mut queues.rx,
        pool: &pool,
    };
    let mut first_run = 1;
    for spec in &scenario.cases {
        let mut case = report.case(&spec.name, case_params(spec))?;
        let mut refs: Vec<&mut dyn Agent> = agents
            .iter_mut()
            .map(|a| &mut **a as &mut dyn Agent)
            .collect();
        let (last, ending) = run_case(
            spec,
            first_run,
            &mut wire,
            &mut refs,
            &clock,
            scenario.sample_every,
            &mut probe,
            &mut case,
        );
        first_run += u32::try_from(spec.streams.len()).unwrap_or(u32::MAX);
        check_case(spec, &mut case, &last, ending)?;
        case.finish()?;
    }
    Ok(report.finish()?)
}

/// What distinguishes a case in the report.
fn case_params(spec: &CaseSpec) -> serde_json::Value {
    serde_json::json!({
        "streams": spec.streams.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        "hold": format!("{:?}", spec.hold),
    })
}

/// Run one case; its last sample and how it ended.
#[allow(clippy::too_many_arguments)] // a case is run with exactly these
fn run_case(
    spec: &CaseSpec,
    first_run: u32,
    wire: &mut Queues<'_, '_>,
    agents: &mut [&mut dyn Agent],
    clock: &Clock,
    every: std::time::Duration,
    probe: &mut Probe<'_, '_>,
    case: &mut Case<'_, Box<dyn Write>>,
) -> (Sample, Ending) {
    let queues = wire.tx.len();
    let mut ledgers = Ledgers::new();
    let mut senders: Vec<(usize, Sender)> = (first_run..)
        .zip(&spec.streams)
        .map(|(run, stream)| {
            ledgers.add_stream(stream, run);
            (0, Sender::new(stream.clone(), run, queues))
        })
        .collect();
    // Counters in a case's samples are since the case began: the agents' and the probe's alike.
    let baseline = probe.sample();
    let agents_before = agents.iter().fold(Sample::new(), |sample, agent| {
        agent.sample(clock.now_ns(), sample)
    });
    let mut last = Sample::new();
    let ending = {
        let mut wires: [&mut dyn Wire; 1] = [wire];
        let mut load = Load {
            senders: &mut senders,
            agents,
        };
        generate(
            &mut load,
            &mut wires,
            &mut ledgers,
            clock,
            Patience {
                quiet: spec.quiet,
                limit: spec.limit,
                hold: spec.hold,
            },
            every,
            |sample| {
                let sample = sample
                    .since(&agents_before)
                    .merge(probe.sample().since(&baseline));
                last = sample.clone();
                // A sample the report will not take is not worth stopping the run for; the run's end
                // will say whether the report survived.
                let _ = case.sample(sample);
            },
        )
    };
    let stray = ledgers.stray_evidence().to_vec();
    if !stray.is_empty() {
        let _ = case.expect(
            "no-strays",
            "every frame received was a stream's or an agent's",
            false,
            stray,
        );
    }
    (last, ending)
}

/// Check how a case ended, and what its scenario expects of its counters.
fn check_case(
    spec: &CaseSpec,
    case: &mut Case<'_, Box<dyn Write>>,
    last: &Sample,
    ending: Ending,
) -> std::io::Result<()> {
    case.expect(
        "in-time",
        "the case finishes before its limit",
        ending != Ending::OutOfTime,
        vec![Evidence::text(format!("{ending:?}"))],
    )?;
    for expect in &spec.expect {
        let bound = match expect.exactly {
            Some(n) => Bound::exactly(n),
            None => Bound {
                min: expect.min,
                max: expect.max,
            },
        };
        let observed = last
            .counters
            .get(&expect.path)
            .or_else(|| last.gauges.get(&expect.path))
            .copied();
        case.expect_counter(&expect.id, &expect.path, bound, observed, vec![])?;
    }
    Ok(())
}
