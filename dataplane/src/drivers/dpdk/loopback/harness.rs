// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What every loopback test shares: the EAL, the cable, the port, the detached bridge, the driver
//! and the report.

use std::io::Write;
use std::num::{NonZero, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use concurrency::sync::Arc;
use concurrency::thread;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes_and_acl,
};
use dpdk::dev::ring::RingCable;
use dpdk::dev::{Dev, DevConfig, PortStats, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::{self, Eal};
use dpdk::mem::{Mbuf, MbufArray, Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket::Preference;
use flow_entry::flow_table::FlowTable;
use flowgen_report::{
    Bound, Build, Case, Environment, Evidence, Header, Port as ReportPort, Report, Sample, Status,
};
use lifecycle::{CancellationToken, Subsystem};
use lldp::Link;
use net::buffer::Append;
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, InterfaceName};
use pipeline::DynPipeline;
use tokio::sync::watch;
use traffic_control::ControlPlane;

use super::super::source::{PortSettings, RingPort, attach_ports, bring_up_ports};
use super::super::{DatapathEnds, DriverDpdk};
use crate::drivers::cpbridge::DetachedPort;
use crate::drivers::status::driver_status_access;
use crate::packet_processor::PipelineIngredients;
use crate::packet_processor::fixture::{Fleet, GATEWAY_MAC, exposes, topology, uplink, vni};

/// Data workers.
pub(super) const WORKERS: u16 = 2;

/// Data queues and the control queue.
pub(super) const QUEUES: u16 = WORKERS + 1;

/// How often the driver's supervisor collects its workers' counters: often, so that a check of
/// them need wait only moments for the counts to settle.
pub(super) const SUPERVISOR_POLL: Duration = Duration::from_millis(10);

/// The configured name of the dataplane's end of the cable.
pub(super) fn loop0() -> InterfaceName {
    InterfaceName::try_from("loop0").unwrap()
}

/// How long anything in these tests may take to happen before it is taken not to.
pub(super) const PATIENCE: Duration = Duration::from_secs(10);

/// The far end of the cable: every queue the dataplane's end has, unsteered.
pub(super) struct FarEnd<'eal> {
    pub(super) pool: Pool<'eal>,
    pub(super) rx: Vec<RxQueue<'eal>>,
    pub(super) tx: Vec<TxQueue<'eal>>,
}

impl<'eal> FarEnd<'eal> {
    fn start(eal: &'eal Eal, cable: RingCable) -> (Dev<'eal, Started>, Pool<'eal>) {
        let pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(
                    "far_end",
                    PoolParams {
                        // Ring ports pass mbufs across rather than copying, so the far end's pool
                        // backs every frame in flight in both directions.
                        size: 8191,
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
            .unwrap();
        let mut dev = DevConfig {
            num_rx_queues: cable.queues,
            num_tx_queues: cable.queues,
            num_hairpin_queues: 0,
            tx_offloads: TxOffloadConfig::none(),
            rx_offloads: RxOffload::NONE,
            mtu: None,
            rss: None,
        }
        .apply(eal.claim(cable.b).unwrap())
        .unwrap();
        for queue in 0..cable.queues {
            dev.new_rx_queue(RxQueueConfig {
                queue_index: RxQueueIndex(queue),
                num_descriptors: 512,
                socket_preference: Preference::Dev(cable.b),
                offloads: RxOffload::NONE,
                pool: pool.clone(),
            })
            .unwrap();
            dev.new_tx_queue(TxQueueConfig {
                queue_index: TxQueueIndex(queue),
                num_descriptors: 512,
                socket_preference: Preference::Dev(cable.b),
                config: (),
            })
            .unwrap();
        }
        (dev.start().unwrap(), pool)
    }

    fn queues(dev: &'eal Dev<'_, Started>, pool: Pool<'eal>, queues: u16) -> Self {
        let mut taken = dev.take_queues().unwrap();
        FarEnd {
            pool,
            rx: (0..queues)
                .map(|q| taken.take_rx(RxQueueIndex(q)).unwrap())
                .collect(),
            tx: (0..queues)
                .map(|q| taken.take_tx(TxQueueIndex(q)).unwrap())
                .collect(),
        }
    }

    /// Send `frame` into the dataplane's receive queue `queue`.
    pub(super) fn send(&mut self, queue: usize, frame: &[u8]) {
        let mut burst = self.pool.alloc_bulk(1).unwrap();
        for mbuf in &mut burst {
            mbuf.append(u16::try_from(frame.len()).unwrap())
                .unwrap()
                .copy_from_slice(frame);
        }
        assert!(self.tx[queue].transmit(burst).is_empty());
    }

    /// The next frame the dataplane transmitted on its queue `queue`, if one comes in time.
    pub(super) fn receive(&mut self, queue: usize) -> Option<Vec<u8>> {
        let deadline = clock::now() + PATIENCE;
        while clock::now() < deadline {
            let burst: MbufArray<'_> = self.rx[queue].receive();
            if let Some(mbuf) = burst.iter().next() {
                return Some(Mbuf::raw_data(mbuf).to_vec());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }
}

/// A pipeline that does nothing, so whatever it is given leaves with no output interface.
fn empty_pipeline<'p>() -> Arc<dyn Send + Sync + Fn() -> DynPipeline<'p, Mbuf<'p>> + 'p> {
    Arc::new(DynPipeline::new)
}

/// Where a loopback test's checks go.
pub(super) type TestCase<'r> = Case<'r, Box<dyn Write>>;

/// Check that what `description` says `holds`, with `evidence` if it does not.
pub(super) fn expect(
    case: &mut TestCase<'_>,
    id: &str,
    description: &str,
    holds: bool,
    evidence: impl FnOnce() -> Vec<Evidence>,
) -> bool {
    let evidence = if holds { vec![] } else { evidence() };
    case.expect(id, description, holds, evidence)
        .expect("the report should take the check");
    holds
}

/// `frame` as evidence, if there is one.
pub(super) fn frame_evidence(what: &str, frame: Option<&[u8]>) -> Vec<Evidence> {
    match frame {
        Some(frame) => vec![Evidence::frame(what, frame)],
        None => vec![Evidence::text(format!("{what}: none"))],
    }
}

/// What stands on the dataplane's side of the cable.
pub(super) struct Gateway {
    /// The port's address.
    pub(super) mac: Mac,
    /// What the pipeline calls the port.
    pub(super) index: InterfaceIndex,
    /// The pipeline the workers run; one that does nothing if `None`.
    pub(super) pipeline: Option<PipelineIngredients>,
}

/// A counter expectation: check id, counter path, bound.
pub(super) type CounterExpectation = (&'static str, &'static str, Bound);

/// Where a loopback test's report goes.
pub(super) type TestReport = Report<Box<dyn Write>>;

/// What a test drives once the driver is up.
pub(super) struct Loopback<'a, 'eal, 'far> {
    /// The far end of the cable.
    pub(super) far: &'a mut FarEnd<'far>,
    /// The kernel's side of the port's bridge.
    pub(super) kernel: &'a mut DetachedPort,
    /// The report, in which the test begins its cases.
    pub(super) report: &'a mut TestReport,
    /// Both ends of the cable, by the names their counters are reported under.
    pub(super) ports: [(&'static str, &'a Dev<'eal, Started>); 2],
}

/// Bring the DPDK driver up on one end of a ring cable and run `exchange` against the other end,
/// the kernel's side of the port's bridge, and a report it records its cases in.
///
/// The report is `$DATAPLANE_REPORT_DIR/<name>.jsonl` if that is set, under the system's temporary
/// directory otherwise. The test fails if the report's run did not pass, naming what failed and
/// where the report is.
///
/// `setup` runs once the EAL exists and inside the timer runtime, as the gateway's state needs;
/// whatever else it returns is kept alive until the driver has stopped.
pub(super) fn over_cable<K>(
    name: &str,
    setup: impl FnOnce() -> (Gateway, K),
    exchange: impl FnOnce(&mut Loopback<'_, '_, '_>),
) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let eal_args = eal_args();
    let mut eal = eal::init(eal_args.iter());
    let timers = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (gateway, _upkeep) = {
        let _runtime = timers.enter();
        setup()
    };

    let cable = eal.attach_ring_cable("loop", QUEUES, 1024).unwrap();
    let sources = attach_ports(
        &mut eal,
        vec![RingPort {
            settings: PortSettings {
                name: loop0(),
                mtu: None,
                rx_descriptors: None,
                fallback_mac: Some(gateway.mac),
            },
            dev: cable.a,
        }],
    )
    .unwrap();
    let eal: &Eal = &eal;
    let ports = bring_up_ports(eal, &sources, WORKERS).unwrap();
    assert_eq!(ports[0].if_index, None, "a ring port has no kernel netdev");
    assert_eq!(
        ports[0].mac.inner(),
        gateway.mac,
        "a ring port has no address of its own"
    );

    let (far_dev, far_pool) = FarEnd::start(eal, cable);
    let mut far = FarEnd::queues(&far_dev, far_pool, QUEUES);

    let (mut bridge, mut kernel, _identities) = DatapathEnds::detached([(loop0(), gateway.index)]);
    let mut kernel = kernel.pop().unwrap();
    assert_eq!(kernel.name, loop0());

    let path = report_path(name);
    let header = header(
        name,
        &eal_args,
        &[("loop0", &ports[0].dev), ("far", &far_dev)],
    );
    let out: Box<dyn Write> = Box::new(std::io::BufWriter::new(
        std::fs::File::create(&path).expect("the report should be writable"),
    ));
    let mut report = Report::new(out, header).expect("the report should take its header");

    let workers = Subsystem::new("workers", CancellationToken::new());
    let (status, _status_reader) = driver_status_access();
    let (_control_plane_tx, control_plane) = watch::channel(ControlPlane::new([], []));

    thread::scope(|scope| {
        // Stop the workers however this closure ends, or a failed assertion would leave the scope
        // waiting on them forever.
        let _stop = workers.cancel_token().drop_guard();
        let pipeline = gateway
            .pipeline
            .map_or_else(empty_pipeline, PipelineIngredients::factory);
        DriverDpdk::start(
            scope,
            &workers,
            timers.handle(),
            &ports,
            NonZero::new(WORKERS).unwrap(),
            SUPERVISOR_POLL,
            &pipeline,
            status,
            Some(&mut bridge),
            control_plane,
        )
        .unwrap();

        wait_for_link(&kernel);

        exchange(&mut Loopback {
            far: &mut far,
            kernel: &mut kernel,
            report: &mut report,
            ports: [("loop0", &ports[0].dev), ("far", &far_dev)],
        });
    });

    report
        .finish()
        .expect("the report should take the run's end");

    drop(far);
    drop(far_dev);
    for port in ports {
        port.shutdown();
    }

    assert_passed(&path);
}

/// The EAL a loopback test runs in: no hugepages, no PCI, nothing shared.
fn eal_args() -> Vec<String> {
    [
        "--no-huge",
        // Without hugepages the EAL reserves 64 MiB, less than one port's pools.
        "-m",
        "512",
        "--no-pci",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--no-hpet",
        "--iova-mode=va",
        "--lcores",
        &eal::main_lcore_arg(),
    ]
    .map(str::to_string)
    .to_vec()
}

/// Wait for the driver to report `kernel`'s port up.
fn wait_for_link(kernel: &DetachedPort) {
    let deadline = clock::now() + PATIENCE;
    while *kernel.link.borrow() != Link::Up {
        assert!(
            clock::now() < deadline,
            "a started ring port should be reported up"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The report header for the loopback test `name`, over `ports`.
fn header(name: &str, eal_args: &[String], ports: &[(&str, &Dev<'_, Started>)]) -> Header {
    Header::new(
        Build {
            name: "dataplane loopback tests".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: None,
        },
        Environment {
            host: None,
            cpus: std::thread::available_parallelism().ok().map(NonZero::get),
            workers: Some(WORKERS),
            ports: ports
                .iter()
                .map(|(name, dev)| ReportPort {
                    name: (*name).to_string(),
                    driver: Some(dev.info().driver_name().to_string()),
                    device: dev.info().name().ok(),
                })
                .collect(),
            eal_args: eal_args.to_vec(),
        },
        serde_json::json!({ "test": name }),
    )
}

/// `sample`, with `ports`' device counters less `baseline`: counters since the case began, when
/// `baseline` is what they were then.
pub(super) fn with_ports(
    sample: Sample,
    ports: &[(&str, &Dev<'_, Started>)],
    baseline: &Sample,
) -> Sample {
    let devices = ports
        .iter()
        .fold(Sample::new(), |sample, (port, dev)| match dev.stats() {
            Ok(stats) => port_counters(sample, port, &stats),
            Err(_) => sample,
        });
    devices
        .counters
        .into_iter()
        .fold(sample, |sample, (path, n)| {
            let before = baseline.counters.get(&path).copied().unwrap_or(0);
            sample.counter(path, n.saturating_sub(before))
        })
}

/// Sample `ports`' device counters into `case` and check them against `counters`: totals since
/// the ports started, for a test whose only case is all their traffic.
pub(super) fn check_counters(
    case: &mut TestCase<'_>,
    ports: &[(&str, &Dev<'_, Started>)],
    counters: &[CounterExpectation],
) {
    let sample = with_ports(Sample::new(), ports, &Sample::new());
    let totals = sample.counters.clone();
    case.sample(sample)
        .expect("the report should take the sample");
    for &(id, path, bound) in counters {
        let observed = totals.get(path).copied();
        case.expect_counter(id, path, bound, observed, vec![])
            .expect("the report should take the check");
    }
}

/// Fail unless the report at `path` is of a run that passed, naming what did not.
fn assert_passed(path: &Path) {
    let run = flowgen_report::read(std::io::BufReader::new(
        std::fs::File::open(path).expect("the report should be readable"),
    ))
    .expect("the report should read back");
    let failed: Vec<String> = run
        .cases
        .iter()
        .flat_map(|case| &case.checks)
        .filter(|check| check.status != Status::Pass)
        .map(|check| {
            format!(
                "{} ({:?}): expected {:?}, observed {:?}",
                check.id, check.status, check.expected, check.observed
            )
        })
        .collect();
    assert_eq!(
        run.status(),
        Status::Pass,
        "{} check(s) did not pass; the report is {}:\n{}",
        failed.len(),
        path.display(),
        failed.join("\n")
    );
}

/// Where the test `name` writes its report.
fn report_path(name: &str) -> PathBuf {
    let dir = std::env::var_os("DATAPLANE_REPORT_DIR").map_or_else(
        || std::env::temp_dir().join("dataplane-loopback-reports"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir).expect("the report directory should be creatable");
    dir.join(format!("{name}.jsonl"))
}

/// `sample`, with port `port`'s device counters.
fn port_counters(sample: Sample, port: &str, stats: &PortStats) -> Sample {
    [
        ("rx_packets", stats.ipackets),
        ("tx_packets", stats.opackets),
        ("rx_bytes", stats.ibytes),
        ("tx_bytes", stats.obytes),
        ("rx_missed", stats.imissed),
        ("rx_errors", stats.ierrors),
        ("tx_errors", stats.oerrors),
        ("rx_no_mbuf", stats.rx_nombuf),
    ]
    .into_iter()
    .fold(sample, |sample, (counter, n)| {
        sample.counter(format!("port.{port}.{counter}"), n)
    })
}

/// The fixture gateway, built as the pipeline tests build it.
pub(super) fn fixture_gateway() -> (Gateway, impl Sized) {
    let tables = topology(&[vni(LOCAL_VNI), vni(REMOTE_VNI)]);
    let overlay = overlay_with_exposes_and_acl(exposes(), None)
        .unwrap()
        .validate()
        .unwrap();
    let fleet = Fleet::lowering(&overlay, Some(&tables), Arc::new(FlowTable::default()));
    let workers = NonZeroUsize::new(usize::from(WORKERS)).unwrap();
    let (pipeline, upkeep) = fleet.ingredients(&tables, workers);
    let gateway = Gateway {
        mac: GATEWAY_MAC,
        index: uplink(),
        pipeline: Some(pipeline),
    };
    (gateway, (tables, fleet, upkeep))
}
