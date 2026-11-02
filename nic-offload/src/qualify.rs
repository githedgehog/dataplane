// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hardware qualification: a real NIC held to the [model](crate::model).
//!
//! The differential test holds the model to the software; this holds a NIC to the model. Generated
//! rate limits are compiled and lowered as on a port, installed on a real one, and generated
//! frames are sent to it from a second port wired to it. Every frame's fate on the hardware must be
//! one the model allows, so a disagreement is a NIC or PMD defect, or an assumption of the model
//! that does not hold for this NIC; bolero shrinks it to a small case.
//!
//! - The port under test is isolated: only what the plan sends to its queue arrives there, and a
//!   frame arrives or it does not. A frame that arrives must arrive unchanged.
//! - Each frame carries its index in the outer IP identification, which nothing matches.
//! - Classification is checked without timing: every meter passes everything (green). A first
//!   phase installs the plan as it is; then, one phase per meter, that meter's color group drops
//!   every color. What a phase drops is exactly what its meter charged. The model walks the same
//!   rewired plan.
//! - The hardware counters must agree with what was observed: the rules that drop count what did
//!   not arrive because of a meter.
//! - Where the model allows a frame either to arrive or not (how a NIC parses fragments, IPv6
//!   extension headers and inner VLAN tags), what the NIC did is tallied by the frame's features
//!   and reported at the end: it settles the model's assumptions for this NIC.
//!
//! Needs two ports wired to each other and the privileges DPDK needs for them:
//!
//! ```text
//! cargo test -p dataplane-nic-offload --lib --no-run   # prints the test binary
//! sudo NIC_OFFLOAD_QUALIFY=0000:02:00.0,0000:02:00.1 <test binary> qualify --ignored --nocapture
//! ```
//!
//! The first address is the port under test, the second the one that sends.
//! `NIC_OFFLOAD_QUALIFY_CASES` sets how many cases run (default 20). Unset
//! `BOLERO_RANDOM_TEST_TIME_MS` if the environment sets it: it cuts the cases short.
//! `NIC_OFFLOAD_PROBE` (frame indices, comma-separated) makes `integrity_protocols` report which
//! validation rule counts each of those frames.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use rekon::{SyncObserve, SyncReconcile};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use acl::table::Backend;
use dpdk::dev::{Dev, DevConfig, RxOffload, Started, TxOffloadConfig};
use dpdk::eal::Eal;
use dpdk::flow::template::{
    Color, MeterAlgorithm, MeterProfile, MeterUnit, TemplateAction, TemplateFlows,
};
use dpdk::mem::{Pool, PoolConfig, PoolParams};
use dpdk::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use dpdk::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use dpdk::socket;
use net::buffer::Append;
use rate_limit::{PeeringRules, RateLimitWriter, RateLimits};

use crate::differential::{
    RawAcls, RawFragment, RawFrame, RawMeter, RawRule, overlay, targets, vteps,
};
use crate::mlx5::{Plan, Port, RESOURCES, Role, with_installed};
use crate::model::{Outcome, Verdict};
use crate::program::{Peering, Program};
use acl_filter::AclFilterContext;

/// How long frames may take to arrive after they are sent.
const SETTLE: Duration = Duration::from_millis(30);
/// How long hardware counters take to catch up.
const COUNTER_LAG: Duration = Duration::from_millis(700);

/// The ports: the one under test with its flows, and the link to it.
struct Rig {
    flows: TemplateFlows<'static>,
    link: Link,
}

/// The receive queue of the port under test, and the transmit queue of the one wired to it.
struct Link {
    rx: RxQueue<'static>,
    tx: TxQueue<'static>,
    pool: Pool<'static>,
    mac: [u8; 6],
}

fn mac(pci: &str) -> [u8; 6] {
    let dir = std::fs::read_dir(format!("/sys/bus/pci/devices/{pci}/net"))
        .unwrap_or_else(|e| panic!("{pci} has no kernel interface: {e}"));
    let name = dir.flatten().next().expect("one interface").file_name();
    let text = std::fs::read_to_string(format!(
        "/sys/bus/pci/devices/{pci}/net/{}/address",
        name.to_string_lossy()
    ))
    .expect("an address");
    let bytes: Vec<u8> = text
        .trim()
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).expect("hex"))
        .collect();
    bytes.try_into().expect("six bytes")
}

/// Configure and start `pci`; the port under test is isolated and reserves template resources.
fn start(
    eal: &'static Eal,
    pci: &str,
    pool: &Pool<'static>,
    under_test: bool,
) -> &'static Dev<'static, Started> {
    let index = eal
        .dev
        .iter()
        .find(|d| d.name().is_ok_and(|name| name == pci))
        .unwrap_or_else(|| panic!("no port {pci}"))
        .index();
    let mut dev = DevConfig {
        num_rx_queues: 1,
        num_tx_queues: 1,
        num_hairpin_queues: 0,
        tx_offloads: TxOffloadConfig::none(),
        rx_offloads: RxOffload::NONE,
        mtu: None,
        rss: None,
        rx_interrupts: false,
    }
    .apply(eal.claim(index).unwrap())
    .map_err(|e| e.error)
    .unwrap();
    if under_test {
        dev.isolate().unwrap();
        dev.configure_templates(&RESOURCES).unwrap();
    }
    dev.new_rx_queue(RxQueueConfig {
        queue_index: RxQueueIndex(0),
        num_descriptors: 512,
        socket_preference: socket::Preference::Dev(index),
        offloads: RxOffload::NONE,
        pool: pool.clone(),
    })
    .unwrap();
    dev.new_tx_queue(TxQueueConfig {
        queue_index: TxQueueIndex(0),
        num_descriptors: 512,
        socket_preference: socket::Preference::Dev(index),
        config: (),
    })
    .unwrap();
    Box::leak(Box::new(dev.start().map_err(|e| e.error).unwrap()))
}

impl Rig {
    /// The ports named by `NIC_OFFLOAD_QUALIFY`; they live until the process exits.
    fn new() -> Rig {
        let ports = std::env::var("NIC_OFFLOAD_QUALIFY")
            .expect("NIC_OFFLOAD_QUALIFY=<port under test>,<sending port>");
        let (dut, gen_) = ports.split_once(',').expect("two PCI addresses");
        let eal: &'static Eal = Box::leak(Box::new(dpdk::eal::init([
            "--in-memory".to_string(),
            "--lcores".to_string(),
            dpdk::eal::main_lcore_arg(),
            "--no-huge".to_string(),
            "-m".to_string(),
            "1024".to_string(),
            "-a".to_string(),
            format!("{dut},dv_flow_en=2"),
            "-a".to_string(),
            gen_.to_string(),
            format!(
                "--log-level=pmd.net.mlx5:{}",
                std::env::var("NIC_OFFLOAD_QUALIFY_LOG").unwrap_or_else(|_| "error".into())
            ),
        ])));
        let pool = eal
            .mem
            .new_pkt_pool(
                PoolConfig::new(
                    "qualify".to_string(),
                    PoolParams {
                        size: 4095,
                        cache_size: 0,
                        ..Default::default()
                    },
                )
                .unwrap(),
            )
            .unwrap();
        let under_test = start(eal, dut, &pool, true);
        let sender = start(eal, gen_, &pool, false);
        let rx = under_test
            .take_queues()
            .unwrap()
            .take_rx(RxQueueIndex(0))
            .unwrap();
        let tx = sender
            .take_queues()
            .unwrap()
            .take_tx(TxQueueIndex(0))
            .unwrap();
        Rig {
            flows: TemplateFlows::new(under_test).unwrap(),
            link: Link {
                rx,
                tx,
                pool,
                mac: mac(dut),
            },
        }
    }
}

impl Link {
    /// Send `frames`, and return what arrived (and with which MARK), by frame index.
    #[allow(clippy::option_option)] // whether a frame arrived, then whether it carried a mark
    fn exchange_marked(&mut self, frames: &[Vec<u8>]) -> Vec<Option<Option<u32>>> {
        self.drain();
        for chunk in frames.chunks(dpdk::mem::MBUF_BURST) {
            let mut burst = self.pool.alloc_bulk(chunk.len()).unwrap();
            for (mbuf, frame) in burst.iter_mut().zip(chunk) {
                mbuf.append(u16::try_from(frame.len()).unwrap()).unwrap();
                mbuf.raw_data_mut().copy_from_slice(frame);
            }
            let mut unsent = self.tx.transmit(burst);
            while !unsent.is_empty() {
                unsent = self.tx.transmit(unsent);
            }
        }
        let mut arrived = vec![None; frames.len()];
        let deadline = clock::now() + SETTLE;
        while clock::now() < deadline {
            for mbuf in &self.rx.receive() {
                let data = mbuf.raw_data();
                let Some(id) = data.get(18..20) else { continue };
                let id = usize::from(u16::from_be_bytes([id[0], id[1]]));
                if let Some(slot) = arrived.get_mut(id) {
                    *slot = Some(mbuf.rx_mark());
                }
            }
        }
        arrived
    }

    /// Discard whatever the port under test has received.
    fn drain(&mut self) {
        let deadline = clock::now() + SETTLE;
        while clock::now() < deadline {
            drop(self.rx.receive());
        }
    }

    /// Send `frames`, and return what arrived, by frame index.
    fn exchange(&mut self, frames: &[Vec<u8>]) -> Vec<Option<Vec<u8>>> {
        self.drain();
        for chunk in frames.chunks(dpdk::mem::MBUF_BURST) {
            let mut burst = self.pool.alloc_bulk(chunk.len()).unwrap();
            for (mbuf, frame) in burst.iter_mut().zip(chunk) {
                let len = u16::try_from(frame.len()).unwrap();
                mbuf.append(len).unwrap();
                mbuf.raw_data_mut().copy_from_slice(frame);
            }
            let mut unsent = self.tx.transmit(burst);
            while !unsent.is_empty() {
                unsent = self.tx.transmit(unsent);
            }
        }
        let mut arrived = vec![None; frames.len()];
        let deadline = clock::now() + SETTLE;
        while clock::now() < deadline {
            for mbuf in &self.rx.receive() {
                let data = mbuf.raw_data();
                // The outer IP identification, after Ethernet (14) and 4 bytes of IPv4.
                let Some(id) = data.get(18..20) else { continue };
                let id = usize::from(u16::from_be_bytes([id[0], id[1]]));
                if let Some(slot) = arrived.get_mut(id) {
                    *slot = Some(data.to_vec());
                }
            }
        }
        arrived
    }
}

/// A meter that colors everything green.
///
/// Meters are not what classification is checked with: on a BlueField-3 a meter lets a packet
/// through while its bucket holds any tokens at all (it goes into debt), so even a tiny bucket
/// passes a first packet, and mlx5 refuses an empty one.
fn passes_everything() -> MeterProfile {
    MeterProfile {
        algorithm: MeterAlgorithm::Srtcm {
            cir: 12_500_000_000,
            cbs: 1 << 24,
            ebs: 0,
        },
        unit: MeterUnit::Bytes,
    }
}

/// Make meter `dropping`'s color group drop every color, and every other one keep its own
/// actions: what that meter charged is then exactly what does not arrive.
fn rewire(plan: &mut Plan, dropping: Option<usize>) {
    for table in plan.tables_mut() {
        for rule in &mut table.rules {
            if let Role::Color(meter, color) = rule.role {
                rule.actions = usize::from(Some(meter) == dropping || color == Color::Red);
            }
        }
    }
}

/// Whether `outcome` could happen when every meter colors green.
fn consistent(outcome: &Outcome) -> bool {
    outcome.color.is_none_or(|c| c == Color::Green)
}

/// Whether a frame reaches the port's queue in `outcome`.
fn arrives(outcome: &Outcome) -> bool {
    matches!(outcome.verdict, Verdict::Delivered)
}

/// Run one generated case on the rig, panicking with the first disagreement.
/// A generated case, compiled and lowered.
struct Case {
    program: Program,
    plan: Plan,
    /// What frames are aimed at: the rate-limit rules, then the ACL rules.
    targets: Vec<RawRule>,
    /// The targets the NIC was given some of: rate limits it took, and ACL denies.
    offloaded: Vec<usize>,
}

impl Case {
    fn new(meters: &[RawMeter; 4], rules: &[RawRule], acls: &RawAcls) -> Case {
        Case::excluding(meters, rules, acls, &BTreeSet::new())
    }

    /// The case with the peerings in `excluded` left in software, as after the NIC refused them.
    fn excluding(
        meters: &[RawMeter; 4],
        rules: &[RawRule],
        acls: &RawAcls,
        excluded: &BTreeSet<Peering>,
    ) -> Case {
        let overlay = overlay(meters, rules, acls).expect("generated configurations are valid");
        let writer: RateLimitWriter<PeeringRules> =
            RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
        writer.apply(&overlay, Backend::Reference).unwrap();
        let filter = AclFilterContext::reference(&overlay).unwrap();
        let destinations = crate::differential::destinations(&overlay);
        let program = Program::compile(&filter, &writer.load(), &destinations, excluded);
        // Meters mlx5 cannot encode stay in software with their peerings, as `run` leaves them.
        let mut excluded = excluded.clone();
        excluded.extend(crate::mlx5::unfit(&program));
        let program = Program::compile(&filter, &writer.load(), &destinations, &excluded);
        let plan = Plan::new(
            &program,
            &vteps(&program),
            &TemplateAction::Queue(RxQueueIndex(0)),
        )
        .unwrap();
        // Aim at the rate limits the NIC took, and the denies of the peerings it took.
        let offloaded_peerings: BTreeSet<Peering> = program
            .rules
            .iter()
            .map(|r| r.peering)
            .chain(program.denies.iter().map(|d| d.peering))
            .collect();
        let vni = |n| net::vxlan::Vni::new_checked(n).unwrap();
        let mut offloaded: Vec<usize> = program.rules.iter().map(|r| r.rule).collect();
        offloaded.dedup();
        for (i, rule) in acls.rules.iter().enumerate().take(6) {
            let (src, dst) = rule.rule.vnis();
            if rule.deny && offloaded_peerings.contains(&Peering::new(vni(src), vni(dst))) {
                offloaded.push(rules.len() + i);
            }
        }
        Case {
            program,
            plan,
            targets: targets(rules, acls),
            offloaded,
        }
    }
}

/// The frames of a case: a frame no rule charges says little about the NIC, so most are aimed
/// at a rule the NIC was given, whole and untagged. One in eight is left as generated (perhaps not
/// aimed), and one in eight of the aimed ones keeps its fragment and inner VLAN tag: those check
/// what the NIC must leave alone.
fn aimed(frames: &[RawFrame], offloaded: &[usize]) -> Vec<RawFrame> {
    (0u8..)
        .zip(&frames[..frames.len().min(32)])
        .map(|(i, frame)| {
            let mut frame = frame.clone();
            if i % 8 == 0 || offloaded.is_empty() {
                return frame;
            }
            let pick = usize::from(frame.aim.unwrap_or(i)) % offloaded.len();
            frame.aim = Some(u8::try_from(offloaded[pick]).unwrap_or(0));
            if i % 8 != 1 {
                frame.vlan = None;
                frame.fragment = RawFragment::Whole;
            }
            frame
        })
        .collect()
}

/// The case as production installs it: peerings with a rule the NIC refuses stay in software,
/// whole.
fn installable(rig: &Rig, meters: &[RawMeter; 4], rules: &[RawRule], acls: &RawAcls) -> Case {
    let mut excluded = BTreeSet::new();
    loop {
        let case = Case::excluding(meters, rules, acls, &excluded);
        let refused: BTreeSet<Peering> = with_installed(&rig.flows, &case.plan, |installed| {
            installed
                .refused()
                .iter()
                .filter_map(|(role, _)| match *role {
                    Role::Police(rule) => Some(case.program.rules[rule].peering),
                    Role::Deny(deny) => Some(case.program.denies[deny].peering),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_else(|e| fail(&format!("the NIC refused the plan: {e}")));
        if refused.is_empty() {
            break case;
        }
        eprintln!("qualify: the NIC refused rules of {refused:?}: they stay in software");
        excluded.extend(refused);
    }
}

fn qualify_case(
    rig: &mut Rig,
    meters: &[RawMeter; 4],
    rules: &[RawRule],
    acls: &RawAcls,
    frames: &[RawFrame],
) {
    let case = installable(rig, meters, rules, acls);
    let frames = &aimed(frames, &case.offloaded)[..];
    let Case {
        program,
        mut plan,
        targets,
        ..
    } = case;
    let wires = wires(frames, &targets, rig.link.mac);
    let frames: Vec<&RawFrame> = frames.iter().cycle().take(wires.len()).collect();
    for meter in &mut plan.meters {
        meter.key.profile = passes_everything();
    }
    let started = clock::now();

    // Frames that do not arrive even when every meter passes: not the meters' doing.
    let mut unmetered = 0;
    for red in std::iter::once(None).chain((0..plan.meters.len()).map(Some)) {
        rewire(&mut plan, red);
        let (arrived, counts, refused) = with_installed(&rig.flows, &plan, |installed| {
            let arrived = rig.link.exchange(&wires);
            std::thread::sleep(COUNTER_LAG);
            let refused: Vec<Role> = installed.refused().iter().map(|(role, _)| *role).collect();
            if red.is_none() {
                for (role, why) in installed.refused() {
                    eprintln!("qualify: the NIC refused {role:?}: {why}");
                }
            }
            (arrived, installed.counts(), refused)
        })
        .unwrap_or_else(|e| {
            fail(&format!(
                "the NIC refused the plan: {e}\nprogram: {program:#?}"
            ))
        });

        // The model of what is installed: the plan without what the NIC refused.
        let outcomes: Vec<Vec<Outcome>> = wires
            .iter()
            .map(|w| plan.outcomes_without(w, &refused).unwrap())
            .collect();
        let mut dropped = 0;
        let mut disagreements = Vec::new();
        for (i, ((wire, arrived), outcomes)) in
            wires.iter().zip(&arrived).zip(&outcomes).enumerate()
        {
            let allowed: Vec<&Outcome> = outcomes.iter().filter(|o| consistent(o)).collect();
            match arrived {
                Some(got) if got != wire => {
                    disagreements.push(format!("frame {i} arrived changed: {:?}", frames[i]));
                }
                Some(_) => {}
                None => dropped += 1,
            }
            if allowed.iter().any(|o| arrives(o)) && allowed.iter().any(|o| !arrives(o)) {
                settle(frames[i], wire, arrived.is_some());
            }
            if !allowed.iter().any(|o| arrives(o) == arrived.is_some()) {
                disagreements.push(format!(
                    "frame {i} {} with meter {red:?} dropping, but the model allows only {allowed:?}\n  frame: {:?}",
                    if arrived.is_some() { "arrived" } else { "did not arrive" },
                    frames[i]
                ));
            }
        }
        // What the rules that drop counted.
        let drop_counted: usize = counts
            .iter()
            .filter(
                |(role, _)| matches!(*role, Role::Color(m, c) if Some(m) == red || c == Color::Red),
            )
            .map(|(_, c)| usize::try_from(c.packets).unwrap_or(usize::MAX))
            .sum();
        if red.is_none() {
            unmetered = dropped;
        }
        let expected = dropped - unmetered;
        eprintln!(
            "qualify: {} rate limit(s), {} deny(s), {} matching TCP flags ({} refused), {} meter(s), meter {red:?} dropping: {} of {} frames arrived, dropping rules counted {drop_counted}",
            program.rules.len(),
            program.denies.len(),
            flag_rules(&program),
            refused.len(),
            plan.meters.len(),
            wires.len() - dropped,
            wires.len(),
        );
        if drop_counted != expected {
            disagreements.push(format!(
                "the dropping rules counted {drop_counted} packets, but {expected} frames were dropped by meters: {counts:?}"
            ));
        }
        if !disagreements.is_empty() {
            fail(&format!(
                "{} disagreement(s) with meter {red:?} dropping:\n{}\nprogram: {program:#?}",
                disagreements.len(),
                disagreements.join("\n")
            ));
        }
    }
    took(started);
}

/// `frames` on the wire to `mac`, each to the gateway's VTEP, then each again as transit VXLAN
/// (which the NIC leaves alone), told apart by their outer IP identification.
fn wires(frames: &[RawFrame], targets: &[RawRule], mac: [u8; 6]) -> Vec<Vec<u8>> {
    let transit = u16::try_from(frames.len()).unwrap_or(u16::MAX);
    (0u16..)
        .zip(frames)
        .map(|(id, raw)| raw.frame(targets).wire_to(mac, id))
        .chain(
            (transit..)
                .zip(frames)
                .map(|(id, raw)| raw.frame(targets).transit_to(mac, id)),
        )
        .collect()
}

/// How many rules of `program` match TCP flags.
fn flag_rules(program: &Program) -> usize {
    program
        .rules
        .iter()
        .map(|r| &r.matches)
        .chain(program.denies.iter().map(|d| &d.matches))
        .filter(|m| m.tcp_flags.is_some())
        .count()
}

/// Report a disagreement and fail; bolero hides panic messages while it shrinks a case.
fn fail(why: &str) -> ! {
    eprintln!("qualify: FAILED: {why}");
    panic!("{why}");
}

/// Report the time a case took.
fn took(started: Instant) {
    eprintln!(
        "qualify: case took {:.2} s",
        clock::elapsed(started).as_secs_f64()
    );
}

/// What the model leaves open, by the frame's features, and what the NIC did: arrived, or not.
type Ledger = std::collections::BTreeMap<String, (usize, usize)>;

/// Record how the NIC settled a frame the model allowed either to arrive or not.
fn settle(raw: &RawFrame, wire: &[u8], arrived: bool) {
    // The inner EtherType, after outer Ethernet, IPv4, UDP and VXLAN, and an inner VLAN tag.
    let at = 50 + if raw.vlan.is_some() { 16 } else { 12 };
    let v6 = wire.get(at..at + 2) == Some(&[0x86, 0xdd][..]);
    let mut features = vec![if v6 { "IPv6" } else { "IPv4" }];
    if raw.vlan.is_some() {
        features.push("inner VLAN");
    }
    if v6 && raw.hop_by_hop {
        features.push("hop-by-hop");
    }
    match raw.fragment {
        RawFragment::Whole => {}
        RawFragment::First => features.push("first fragment"),
        RawFragment::Later(_) => features.push("later fragment"),
    }
    LEDGER.with_borrow_mut(|ledger| {
        let entry = ledger.entry(features.join(" + ")).or_default();
        if arrived {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    });
}

thread_local! {
    static LEDGER: RefCell<Ledger> = const { RefCell::new(Ledger::new()) };
    static RIG: RefCell<Option<Rig>> = const { RefCell::new(None) };
}

/// Print the ledger however the run ends.
struct Report;
impl Drop for Report {
    fn drop(&mut self) {
        LEDGER.with_borrow(|ledger| {
            for (features, (arrived, not)) in ledger {
                eprintln!(
                    "qualify: model left open, {features}: arrived {arrived}, did not arrive {not}"
                );
            }
        });
    }
}

#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
fn qualify() {
    // Each case takes seconds on hardware (several installs, and waits for the counters).
    let cases = std::env::var("NIC_OFFLOAD_QUALIFY_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    let _report = Report;
    bolero::check!()
        .with_iterations(cases)
        .with_shrink_time(Duration::from_secs(120))
        .with_type::<([RawMeter; 4], Vec<RawRule>, RawAcls, Vec<RawFrame>)>()
        .for_each(|(meters, rules, acls, frames)| {
            let rules = &rules[..rules.len().min(6)];
            let acls = hardware_acls(acls);
            RIG.with_borrow_mut(|rig| {
                let rig = rig.get_or_insert_with(Rig::new);
                qualify_case(rig, meters, rules, &acls, frames);
            });
        });
}

/// These campaigns need installed denies and meters to exercise the NIC. Logged policies stay
/// in the differential and transition suites, where falling back to software is the behavior
/// under test.
fn hardware_acls(acls: &RawAcls) -> RawAcls {
    let mut acls = acls.clone();
    for rule in &mut acls.rules {
        rule.log = false;
    }
    acls
}

/// How many generated frames the model says a meter charges or a deny drops, and why the others
/// are not: the runner learns about the NIC only from frames a rule acts on.
#[test]
fn coverage() {
    let stats = std::panic::AssertUnwindSafe(RefCell::new(
        std::collections::BTreeMap::<&str, usize>::new(),
    ));
    bolero::check!()
        .with_iterations(300)
        .with_type::<([RawMeter; 4], Vec<RawRule>, RawAcls, Vec<RawFrame>)>()
        .for_each(|(meters, rules, acls, frames)| {
            let rules = &rules[..rules.len().min(6)];
            let case = Case::new(meters, rules, &hardware_acls(acls));
            let mut stats = stats.borrow_mut();
            for raw in aimed(frames, &case.offloaded) {
                let wire = raw.frame(&case.targets).wire_to([2, 0, 0, 0, 0, 1], 0);
                let outcomes = case.plan.outcomes(&wire).unwrap();
                let why = if outcomes
                    .iter()
                    .any(|o| o.path.iter().any(|r| matches!(r, Role::Deny(_))))
                {
                    "denied"
                } else if outcomes
                    .iter()
                    .any(|o| o.path.iter().any(|r| matches!(r, Role::Corrupt(_))))
                {
                    "corrupt"
                } else if outcomes.iter().any(|o| !o.meters.is_empty()) {
                    "charged"
                } else if raw.aim.is_none() || case.targets.is_empty() {
                    "not aimed"
                } else {
                    let index = usize::from(raw.aim.unwrap_or(0)) % case.targets.len();
                    if !case.offloaded.contains(&index) {
                        "aimed rule not offloaded"
                    } else if raw.vlan.is_some() {
                        "inner VLAN"
                    } else if !matches!(raw.fragment, RawFragment::Whole) {
                        "fragment"
                    } else {
                        "other"
                    }
                };
                *stats.entry(why).or_default() += 1;
            }
        });
    let stats = stats.0.into_inner();
    let total: usize = stats.values().sum();
    for (why, n) in &stats {
        eprintln!("coverage: {why:>26}: {n:6} ({} %)", n * 100 / total.max(1));
    }
    let acted = ["charged", "denied", "corrupt"]
        .iter()
        .map(|why| stats.get(why).copied().unwrap_or(0))
        .sum::<usize>();
    // About half are (49 % on average over 30 runs, with a standard deviation of 1.8 points):
    // frames aimed at a rule's destination outside its peer's exposes, and frames aimed at
    // nothing, are neither. The inputs are not seeded, and a loaded runner reaches fewer cases in
    // the time bolero has, so the share wanders; a bound near it failed about one run in twelve.
    // This only has to catch a generator that stopped reaching the rules.
    assert!(
        acted * 6 >= total,
        "only {acted} of {total} generated frames are charged by a meter, denied or corrupt"
    );
}

/// One step of a sequence of policies: a configuration, and the peerings (bits of `keep`) that
/// keep the rules and ACL of the step before.
#[derive(Debug, bolero::TypeGenerator)]
struct RawStep {
    rules: Vec<RawRule>,
    acls: RawAcls,
    keep: u8,
}

/// The configurations of a sequence: the first, then each step's.
fn sequence(rules: &[RawRule], acls: &RawAcls, steps: &[RawStep]) -> Vec<(Vec<RawRule>, RawAcls)> {
    let mut configs = vec![(rules[..rules.len().min(6)].to_vec(), acls.clone())];
    for step in steps.iter().take(4) {
        let (prev_rules, prev_acls) = configs.last().cloned().unwrap_or_default();
        let kept = |peering: usize| step.keep & (1 << peering) != 0;
        let mut rules: Vec<RawRule> = prev_rules
            .into_iter()
            .filter(|r| kept(r.peering_index()))
            .chain(
                step.rules
                    .iter()
                    .filter(|r| !kept(r.peering_index()))
                    .cloned(),
            )
            .collect();
        rules.truncate(6);
        let mut acls = RawAcls {
            exposes: Default::default(),
            defaults: std::array::from_fn(|p| {
                if kept(p) {
                    prev_acls.defaults[p]
                } else {
                    step.acls.defaults[p]
                }
            }),
            rules: prev_acls
                .rules
                .iter()
                .filter(|r| kept(r.rule.peering_index()))
                .chain(
                    step.acls
                        .rules
                        .iter()
                        .filter(|r| !kept(r.rule.peering_index())),
                )
                .cloned()
                .collect(),
        };
        acls.rules.truncate(6);
        configs.push((rules, acls));
    }
    configs
}

/// `frame` with outer IP identification `id`, its header checksum updated.
fn with_id(frame: &[u8], id: u16) -> Vec<u8> {
    let mut frame = frame.to_vec();
    frame[18..20].copy_from_slice(&id.to_be_bytes());
    frame[24..26].copy_from_slice(&[0, 0]);
    let sum = frame[14..34]
        .chunks(2)
        .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
        .sum::<u32>();
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = !u16::try_from((sum & 0xffff) + (sum >> 16)).unwrap_or(0);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
    frame
}

/// Frames per cycle: the frame's index in a cycle is the low bits of its identification.
const FRAME_BITS: u32 = 5;

/// What arrived of continuous traffic around one reconciliation.
#[derive(Debug, Default)]
struct Traffic {
    /// Per cycle: the phase when it started and when it ended (0 before the reconciliation, 1
    /// during, 2 after), and which frames arrived.
    cycles: Vec<(u8, u8, Vec<bool>)>,
}

/// Send `wires` in cycles while `reconcile` runs, and record what arrived.
fn around(link: &mut Link, wires: &[Vec<u8>], reconcile: impl FnOnce()) -> Traffic {
    use concurrency::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    link.drain();
    let phase = AtomicU8::new(0);
    let stop = AtomicBool::new(false);
    let Link { rx, tx, pool, .. } = link;
    let mut sent: Vec<(u8, u8)> = Vec::new();
    let mut arrived: Vec<(usize, usize)> = Vec::new();
    std::thread::scope(|scope| {
        let (phase, stop) = (&phase, &stop);
        let sender = scope.spawn(move || {
            let mut cycles = Vec::new();
            let max_cycles = 1usize << (16 - FRAME_BITS);
            // Diagnostics: no traffic at all.
            let quiet = std::env::var_os("NIC_OFFLOAD_QUALIFY_QUIET").is_some();
            while !stop.load(Ordering::Acquire) && cycles.len() < max_cycles {
                let cycle = cycles.len();
                let start = phase.load(Ordering::Acquire);
                for (index, wire) in wires.iter().enumerate().filter(|_| !quiet) {
                    let id = u16::try_from((cycle << FRAME_BITS) | index).unwrap_or(u16::MAX);
                    let frame = with_id(wire, id);
                    let mut burst = pool.alloc_bulk(1).unwrap();
                    for mbuf in &mut burst {
                        mbuf.append(u16::try_from(frame.len()).unwrap()).unwrap();
                        mbuf.raw_data_mut().copy_from_slice(&frame);
                    }
                    let mut unsent = tx.transmit(burst);
                    while !unsent.is_empty() {
                        unsent = tx.transmit(unsent);
                    }
                }
                cycles.push((start, phase.load(Ordering::Acquire)));
                std::thread::sleep(Duration::from_micros(200));
            }
            cycles
        });
        let receiver = scope.spawn(move || {
            let mut got = Vec::new();
            let mut deadline = None;
            loop {
                if stop.load(Ordering::Acquire) {
                    let d = *deadline.get_or_insert_with(|| clock::now() + SETTLE);
                    if clock::now() > d {
                        break;
                    }
                }
                for mbuf in &rx.receive() {
                    let data = mbuf.raw_data();
                    let Some(id) = data.get(18..20) else { continue };
                    let id = usize::from(u16::from_be_bytes([id[0], id[1]]));
                    got.push((id >> FRAME_BITS, id & ((1 << FRAME_BITS) - 1)));
                }
            }
            got
        });
        std::thread::sleep(Duration::from_millis(20));
        phase.store(1, Ordering::Release);
        reconcile();
        phase.store(2, Ordering::Release);
        std::thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        sent = sender.join().unwrap();
        arrived = receiver.join().unwrap();
    });
    let mut traffic = Traffic {
        cycles: sent
            .into_iter()
            .map(|(start, end)| (start, end, vec![false; wires.len()]))
            .collect(),
    };
    for (cycle, index) in arrived {
        if let Some((_, _, frames)) = traffic.cycles.get_mut(cycle)
            && let Some(slot) = frames.get_mut(index)
        {
            *slot = true;
        }
    }
    traffic
}

/// Whether each frame may arrive, and may not, under a plan (every meter green).
fn allowed(plan: &Plan, wires: &[Vec<u8>]) -> Vec<(bool, bool)> {
    wires
        .iter()
        .map(|wire| {
            let outcomes = plan.outcomes(wire).unwrap();
            let allowed: Vec<&Outcome> = outcomes.iter().filter(|o| consistent(o)).collect();
            (
                allowed.iter().any(|o| arrives(o)),
                allowed.iter().any(|o| !arrives(o)),
            )
        })
        .collect()
}

/// Count of each meter, by name, under the plan last reconciled.
fn meter_counts(port: &Port<'_>, plan: &Plan) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for (role, c) in port.counts() {
        if let Role::Color(meter, _) = role {
            *counts
                .entry(plan.meters[meter].key.name.clone())
                .or_insert(0) += c.packets;
        }
    }
    counts
}

/// What each plan holds, to tell a failure apart.
fn summary(plans: &[Plan]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (step, plan) in plans.iter().enumerate() {
        let meters: Vec<&String> = plan.meters.iter().map(|m| &m.key.name).collect();
        let _ = writeln!(out, "plan {step}: meters {meters:?}");
        for (vni, vpc) in &plan.vpcs {
            let limits: Vec<_> = vpc
                .spec
                .limits
                .iter()
                .map(|(m, _, k)| (m, &k.name))
                .collect();
            let _ = writeln!(
                out,
                "  vpc {vni}: denies {:?}\n    limits {limits:?}",
                vpc.spec.denies
            );
        }
    }
    out
}

/// Run one generated sequence of policies on the rig: reconcile from each to the next under
/// traffic, and check every cycle of frames against the policies around it.
fn transitions_case(
    rig: &mut Rig,
    meters: &[RawMeter; 4],
    rules: &[RawRule],
    acls: &RawAcls,
    steps: &[RawStep],
    frames: &[RawFrame],
) {
    let configs = sequence(rules, acls, steps);
    let targets: Vec<RawRule> = configs.iter().flat_map(|(r, a)| targets(r, a)).collect();
    let everything: Vec<usize> = (0..targets.len()).collect();
    let frames = aimed(frames, &everything);
    let wires: Vec<Vec<u8>> = frames
        .iter()
        .take(1 << FRAME_BITS)
        .map(|raw| raw.frame(&targets).wire_to(rig.link.mac, 0))
        .collect();
    let mut plans = Vec::new();
    for (rules, acls) in &configs {
        let Case { mut plan, .. } = Case::new(meters, rules, acls);
        for meter in &mut plan.meters {
            meter.key.profile = passes_everything();
        }
        plans.push(plan);
    }
    let allowed: Vec<Vec<(bool, bool)>> = plans.iter().map(|p| allowed(p, &wires)).collect();
    let mut port = Port::new(&rig.flows);
    let reconcile = |port: &mut Port<'_>, plan: &Plan| {
        let observed = port.observe();
        match port.reconcile(plan, observed) {
            Ok(reconciled) if reconciled.refused.is_empty() => {}
            Ok(reconciled) => fail(&format!("the NIC refused: {:?}", reconciled.refused)),
            Err(e) => fail(&format!("reconciliation failed: {e}\n{}", summary(&plans))),
        }
    };
    reconcile(&mut port, &plans[0]);
    let mut disagreements = Vec::new();
    for step in 1..plans.len() {
        let before = meter_counts(&port, &plans[step - 1]);
        let (old, new) = (&allowed[step - 1], &allowed[step]);
        let traffic = around(&mut rig.link, &wires, || reconcile(&mut port, &plans[step]));
        std::thread::sleep(COUNTER_LAG);
        let after = meter_counts(&port, &plans[step]);
        let (mut exact, mut overlapping) = (0, 0);
        let quiet = std::env::var_os("NIC_OFFLOAD_QUALIFY_QUIET").is_some();
        for (cycle, (start, end, arrived)) in traffic.cycles.iter().enumerate() {
            for (i, &arrived) in arrived.iter().enumerate().filter(|_| !quiet) {
                let ok = match (start, end) {
                    (0, 0) => {
                        if arrived {
                            old[i].0
                        } else {
                            old[i].1
                        }
                    }
                    (2, 2) => {
                        if arrived {
                            new[i].0
                        } else {
                            new[i].1
                        }
                    }
                    // During the reconciliation: either policy, or software alone (which the NIC
                    // passes on), for the VPCs being switched.
                    _ => arrived || old[i].1 || new[i].1,
                };
                if !ok && disagreements.len() < 10 {
                    disagreements.push(format!(
                        "step {step}, cycle {cycle} ({start}->{end}): frame {i} {}",
                        if arrived { "arrived" } else { "did not arrive" }
                    ));
                }
            }
            if (*start, *end) == (0, 0) || (*start, *end) == (2, 2) {
                exact += 1;
            } else {
                overlapping += 1;
            }
        }
        // A meter both policies have (same key) is left alone: its counters keep counting.
        for (name, &was) in &before {
            if let Some(&now) = after.get(name)
                && was > 0
                && now < was
            {
                disagreements.push(format!(
                    "step {step}: meter {name} counted {was}, then {now}: it was made again"
                ));
            }
        }
        eprintln!(
            "transitions: step {step}: {} cycle(s) checked exactly, {overlapping} overlapping the reconciliation, {} attached VPC(s)",
            exact,
            port.observe().vpcs.len()
        );
    }
    drop(port);
    if !disagreements.is_empty() {
        fail(&format!(
            "{} disagreement(s):\n{}\nconfigurations: {configs:#?}",
            disagreements.len(),
            disagreements.join("\n")
        ));
    }
}

/// Reconfiguration under traffic, on a real NIC: see [`transitions_case`].
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
fn qualify_transitions() {
    let cases = std::env::var("NIC_OFFLOAD_QUALIFY_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(10);
    bolero::check!()
        .with_iterations(cases)
        .with_shrink_time(Duration::from_secs(120))
        .with_type::<(
            [RawMeter; 4],
            Vec<RawRule>,
            RawAcls,
            Vec<RawStep>,
            Vec<RawFrame>,
        )>()
        .for_each(|(meters, rules, acls, steps, frames)| {
            if steps.is_empty() {
                return;
            }
            RIG.with_borrow_mut(|rig| {
                let rig = rig.get_or_insert_with(Rig::new);
                transitions_case(rig, meters, rules, acls, steps, frames);
            });
        });
}

/// Named sequences of plans, each reconciled in turn on a fresh port, without traffic: a port
/// must never fail to remove what it installed. (Found this way: mlx5 takes two identical rules
/// into one table, but fails to remove the second.)
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
#[allow(clippy::too_many_lines)] // a table of scenarios
fn reconcile_scenarios() {
    use crate::program::{Match, Peering, PoliceMeter, PoliceRule, Prefix};
    use std::net::Ipv4Addr;
    let vni = |n| net::vxlan::Vni::new_checked(n).unwrap();
    let rule = |src: u32, dst: u8, len: u8, meter: usize| PoliceRule {
        rule: 0,
        peering: Peering::new(vni(src), vni(999)),
        matches: Match {
            src_vni: vni(src),
            source: Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 16),
            destination: Prefix::V4(Ipv4Addr::new(10, dst, 0, 0), len),
            proto: None,
            src_port: None,
            dst_port: None,
            tcp_flags: None,
        },
        meter,
        level: len,
    };
    let meter = |name: &str| PoliceMeter {
        name: name.to_string(),
        lease_slack: [0, 0],
        unit: rate_limit::Unit::Bytes,
        profile: policer::Profile::new(
            policer::Rate::new(std::num::NonZeroU64::new(1_000_000).unwrap()),
            100_000,
            None,
            0,
        )
        .unwrap(),
    };
    let program = |rules: Vec<PoliceRule>, meters: Vec<PoliceMeter>| Program {
        denies: Vec::new(),
        meters,
        rules,
        refused: Vec::new(),
        passes: std::collections::BTreeMap::new(),
        validate: false,
    };
    let deny = |src: u32, dst: u8| crate::program::DenyRule {
        origin: crate::program::Origin::Acl { v6: false, row: 0 },
        peering: Peering::new(vni(src), vni(999)),
        matches: Match {
            src_vni: vni(src),
            source: Prefix::V4(Ipv4Addr::new(10, 0, 0, 0), 16),
            destination: Prefix::V4(Ipv4Addr::new(10, dst, 0, 0), 24),
            proto: Some(17),
            src_port: None,
            dst_port: None,
            tcp_flags: None,
        },
        level: 24,
    };
    let with_denies = |mut p: Program, denies: Vec<crate::program::DenyRule>| {
        p.denies = denies;
        p
    };
    let scenarios: Vec<(&str, Vec<Program>)> = vec![
        (
            "one VPC, its rule changes",
            vec![
                program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                program(vec![rule(100, 1, 24, 0)], vec![meter("a")]),
            ],
        ),
        (
            "one VPC, goes",
            vec![
                program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                program(vec![], vec![]),
            ],
        ),
        (
            "two VPCs share a meter, one changes",
            vec![
                program(
                    vec![rule(100, 1, 16, 0), rule(200, 2, 16, 0)],
                    vec![meter("a")],
                ),
                program(
                    vec![rule(100, 1, 24, 0), rule(200, 2, 16, 0)],
                    vec![meter("a")],
                ),
            ],
        ),
        (
            "one VPC, its meter changes",
            vec![
                program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                program(vec![rule(100, 1, 16, 0)], vec![meter("b")]),
            ],
        ),
        (
            "denies and rate limits, the rate limit changes",
            vec![
                with_denies(
                    program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                    vec![deny(100, 1)],
                ),
                with_denies(
                    program(vec![rule(100, 1, 24, 0)], vec![meter("a")]),
                    vec![deny(100, 1)],
                ),
            ],
        ),
        (
            "denies and rate limits, the deny goes",
            vec![
                with_denies(
                    program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                    vec![deny(100, 1)],
                ),
                program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
            ],
        ),
        (
            "denies and rate limits, everything goes",
            vec![
                with_denies(
                    program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
                    vec![deny(100, 1)],
                ),
                program(vec![], vec![]),
            ],
        ),
        (
            "one VPC, two identical rules, it goes",
            vec![
                program(
                    vec![rule(100, 1, 16, 0), rule(100, 1, 16, 0)],
                    vec![meter("a")],
                ),
                program(vec![], vec![]),
            ],
        ),
        (
            "one VPC, two rules, one goes",
            vec![
                program(
                    vec![rule(100, 1, 16, 0), rule(100, 2, 16, 0)],
                    vec![meter("a")],
                ),
                program(vec![rule(100, 1, 16, 0)], vec![meter("a")]),
            ],
        ),
    ];
    RIG.with_borrow_mut(|rig| {
        let rig = rig.get_or_insert_with(Rig::new);
        let fate = TemplateAction::Queue(RxQueueIndex(0));
        for (name, programs) in &scenarios {
            for attempt in 0..3 {
                let mut port = Port::new(&rig.flows);
                let mut result = "ok".to_string();
                for (step, program) in programs.iter().enumerate() {
                    let plan = Plan::new(program, &vteps(program), &fate).unwrap();
                    let observed = port.observe();
                    if let Err(e) = port.reconcile(&plan, observed) {
                        result = format!("step {step}: {e}");
                        break;
                    }
                }
                drop(port);
                eprintln!("scenario: {name}, attempt {attempt}: {result}");
                assert_eq!(result, "ok", "{name}");
            }
        }
    });
}

/// Hand-built frames for the integrity probe, with correct checksums unless a case breaks one.
mod crafted {
    fn sum(bytes: &[u8], mut acc: u32) -> u32 {
        for w in bytes.chunks(2) {
            acc += u32::from(u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)]));
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc > 0xffff {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !u16::try_from(acc).unwrap_or(0)
    }

    /// An IPv4 header carrying `payload` of protocol `proto`, with fragment field `frag`.
    pub(super) fn ipv4(
        src: [u8; 4],
        dst: [u8; 4],
        proto: u8,
        frag: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap();
        let mut h = vec![0x45, 0];
        h.extend(total.to_be_bytes());
        h.extend([0, 1]);
        h.extend(frag.to_be_bytes());
        h.extend([64, proto, 0, 0]);
        h.extend(src);
        h.extend(dst);
        let c = fold(sum(&h, 0));
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend(payload);
        h
    }

    /// An IPv6 header carrying `payload` with next header `next`.
    pub(super) fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0];
        h.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
        h.extend([next, 64]);
        h.extend(src);
        h.extend(dst);
        h.extend(payload);
        h
    }

    /// The pseudo-header sum of an IP packet `ip` (as `ipv4` or `ipv6` build) for its payload.
    fn pseudo(ip: &[u8], proto: u8, len: usize) -> u32 {
        let len = u32::try_from(len).unwrap();
        if ip[0] >> 4 == 4 {
            sum(&ip[12..20], u32::from(proto) + len)
        } else {
            sum(&ip[8..40], u32::from(proto) + len)
        }
    }

    /// `ip` with its transport checksum (at `offset` into the transport header) computed.
    pub(super) fn checksummed(mut ip: Vec<u8>, offset: usize) -> Vec<u8> {
        let (header, proto) = if ip[0] >> 4 == 4 {
            (usize::from(ip[0] & 0xf) * 4, ip[9])
        } else {
            (40, ip[6])
        };
        let len = ip.len() - header;
        ip[header + offset..header + offset + 2].copy_from_slice(&[0, 0]);
        let mut c = fold(sum(&ip[header..], pseudo(&ip, proto, len)));
        if proto == 17 && c == 0 {
            c = 0xffff;
        }
        ip[header + offset..header + offset + 2].copy_from_slice(&c.to_be_bytes());
        ip
    }

    /// `frame` with the IPv4 header at `at` given a correct checksum again.
    pub(super) fn rechecked(mut frame: Vec<u8>, at: usize) -> Vec<u8> {
        let ihl = usize::from(frame[at] & 0xf).max(5) * 4;
        frame[at + 10..at + 12].copy_from_slice(&[0, 0]);
        let c = fold(sum(&frame[at..at + ihl], 0));
        frame[at + 10..at + 12].copy_from_slice(&c.to_be_bytes());
        frame
    }

    /// A UDP header and payload.
    pub(super) fn udp(payload: &[u8]) -> Vec<u8> {
        let mut h = vec![0x30, 0x39, 0x00, 0x35];
        h.extend(u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        h.extend([0, 0]);
        h.extend(payload);
        h
    }

    /// A TCP header (ACK) and payload.
    pub(super) fn tcp(payload: &[u8]) -> Vec<u8> {
        let mut h = vec![
            0x30, 0x39, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0,
        ];
        h.extend(payload);
        h
    }

    /// An Ethernet frame of `ethertype` around `body`.
    pub(super) fn eth(ethertype: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
        f.extend(ethertype.to_be_bytes());
        f.extend(body);
        f
    }

    /// A VXLAN frame to `dst` around inner Ethernet frame `inner`, outer IP identification `id`.
    pub(super) fn vxlan(dst: [u8; 6], id: u16, inner: &[u8]) -> Vec<u8> {
        let mut vx = vec![0xc0, 0x00, 0x12, 0xb5];
        vx.extend(u16::try_from(16 + inner.len()).unwrap().to_be_bytes());
        vx.extend([0, 0, 0x08, 0, 0, 0, 0, 0, 100, 0]);
        vx.extend(inner);
        let mut ip = ipv4([192, 0, 2, 1], [192, 0, 2, 2], 17, 0x4000, &vx);
        ip[4..6].copy_from_slice(&id.to_be_bytes());
        ip[10..12].copy_from_slice(&[0, 0]);
        let c = fold(sum(&ip[..20], 0));
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        let mut f = Vec::from(dst);
        f.extend([0x02, 0, 0, 0, 0, 3, 0x08, 0x00]);
        f.extend(ip);
        f
    }
}

/// The integrity probe's frames: a name, and the frame for outer IP identification `id`.
#[allow(clippy::too_many_lines)] // a table of cases
fn integrity_cases(mac: [u8; 6]) -> Vec<(&'static str, Vec<u8>)> {
    use crafted::{checksummed, eth, ipv4, ipv6, rechecked, tcp, udp, vxlan};
    let (a4, b4) = ([10, 0, 0, 1], [10, 1, 0, 1]);
    let (a6, b6) = (
        [0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xfd, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1],
    );
    let payload = [0xabu8; 16];
    let v4udp = || checksummed(ipv4(a4, b4, 17, 0x4000, &udp(&payload)), 6);
    let v4tcp = || checksummed(ipv4(a4, b4, 6, 0x4000, &tcp(&payload)), 16);
    let v6udp = || checksummed(ipv6(a6, b6, 17, &udp(&payload)), 6);
    let v6tcp = || checksummed(ipv6(a6, b6, 6, &tcp(&payload)), 16);
    let inner4 = |ip: Vec<u8>| eth(0x0800, &ip);
    let inner6 = |ip: Vec<u8>| eth(0x86dd, &ip);
    let with = |mut f: Vec<u8>, at: usize, b: u8| {
        f[at] ^= b;
        f
    };
    // Offsets of an IPv4 inner header in an inner frame: 14 (Ethernet); transport at 34.
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("v4 UDP good", inner4(v4udp())),
        ("v4 TCP good", inner4(v4tcp())),
        ("v6 UDP good", inner6(v6udp())),
        ("v6 TCP good", inner6(v6tcp())),
        (
            "v4 ICMP good",
            inner4(checksummed(
                ipv4(a4, b4, 1, 0x4000, &[8, 0, 0, 0, 0, 1, 0, 1]),
                2,
            )),
        ),
        (
            "ARP",
            eth(
                0x0806,
                &[
                    0, 1, 8, 0, 6, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0,
                ],
            ),
        ),
        (
            "inner v4 header checksum bad",
            with(inner4(v4udp()), 14 + 10, 0x01),
        ),
        (
            "inner v4 total length short",
            rechecked(with(inner4(v4udp()), 14 + 3, 0x04), 14),
        ),
        (
            "inner v4 total length long",
            rechecked(with(inner4(v4udp()), 14 + 2, 0x01), 14),
        ),
        (
            "inner v4 IHL 4",
            rechecked(with(inner4(v4udp()), 14, 0x01), 14),
        ),
        (
            "inner v4 IHL 6 (options into the payload)",
            rechecked(with(inner4(v4udp()), 14, 0x03), 14),
        ),
        (
            "inner v4 UDP checksum bad",
            with(inner4(v4udp()), 34 + 6, 0x01),
        ),
        ("inner v4 UDP checksum zero", {
            let mut f = inner4(v4udp());
            f[34 + 6..34 + 8].copy_from_slice(&[0, 0]);
            f
        }),
        (
            "inner v4 UDP length bad",
            with(inner4(v4udp()), 34 + 5, 0x02),
        ),
        (
            "inner v4 TCP checksum bad",
            with(inner4(v4tcp()), 34 + 16, 0x01),
        ),
        (
            "inner v6 UDP checksum bad",
            with(inner6(v6udp()), 54 + 6, 0x01),
        ),
        ("inner v6 UDP checksum zero", {
            let mut f = inner6(v6udp());
            f[54 + 6..54 + 8].copy_from_slice(&[0, 0]);
            f
        }),
        (
            "inner v6 TCP checksum bad",
            with(inner6(v6tcp()), 54 + 16, 0x01),
        ),
        (
            "inner v6 payload length bad",
            with(inner6(v6udp()), 14 + 5, 0x04),
        ),
        (
            "inner v4 first fragment",
            inner4(checksummed(ipv4(a4, b4, 17, 0x2000, &udp(&payload)), 6)),
        ),
        (
            "inner v4 later fragment",
            inner4(ipv4(a4, b4, 17, 0x0003, &payload)),
        ),
    ];
    // Valid traffic a careless rule could drop.
    let v4opts = {
        // IHL 6: one 4-byte option (NOP, NOP, NOP, end), then a correct UDP datagram.
        let datagram = udp(&payload);
        let total = u16::try_from(24 + datagram.len()).unwrap();
        let mut h = vec![0x46, 0];
        h.extend(total.to_be_bytes());
        h.extend([0, 1, 0x40, 0, 64, 17, 0, 0]);
        h.extend(a4);
        h.extend(b4);
        h.extend([1, 1, 1, 0]);
        h.extend(datagram);
        let h = rechecked(h, 0);
        checksummed(h, 6)
    };
    let v6hbh = {
        let mut ext = vec![17, 0, 1, 4, 0, 0, 0, 0];
        let mut ip = checksummed(ipv6(a6, b6, 17, &udp(&payload)), 6);
        let datagram = ip.split_off(40);
        ip[6] = 0;
        ip[4..6].copy_from_slice(&u16::try_from(8 + datagram.len()).unwrap().to_be_bytes());
        ext.extend(datagram);
        ip.extend(ext);
        ip
    };
    let v6frag = {
        let mut ip = checksummed(ipv6(a6, b6, 17, &udp(&payload)), 6);
        let datagram = ip.split_off(40);
        ip[6] = 44;
        ip[4..6].copy_from_slice(&u16::try_from(8 + datagram.len()).unwrap().to_be_bytes());
        ip.extend([17, 0, 0, 1, 0, 0, 0, 7]);
        ip.extend(datagram);
        ip
    };
    let tagged = {
        let mut f = vec![
            0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x81, 0x00, 0x00, 0x05, 0x08, 0x00,
        ];
        f.extend(v4udp());
        f
    };
    cases.push(("v4 UDP with IP options good", inner4(v4opts)));
    cases.push(("v6 hop-by-hop UDP good", inner6(v6hbh)));
    cases.push(("v6 fragment header (first) UDP", inner6(v6frag)));
    cases.push(("inner VLAN-tagged v4 UDP good", tagged));
    // A small frame padded to Ethernet's minimum inside the tunnel.
    let mut padded = inner4(checksummed(ipv4(a4, b4, 6, 0x4000, &tcp(&[])), 16));
    padded.extend([0; 6]);
    cases.push(("inner v4 TCP padded to 60 good", padded));
    // Bytes after the UDP datagram, inside the IP packet: Linux trims them and accepts it.
    let trailing = {
        let mut ip = checksummed(ipv4(a4, b4, 17, 0x4000, &udp(&payload)), 6);
        ip.extend([0; 4]);
        let total = u16::try_from(ip.len()).unwrap();
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        rechecked(ip, 0)
    };
    cases.push(("inner v4 UDP shorter than its IP payload", inner4(trailing)));
    // IPv6 extension chains before a correct UDP datagram: (type, header length in 8-byte
    // units beyond the first 8) each.
    let chained = |exts: &[(u8, u8)]| {
        let mut ip = checksummed(ipv6(a6, b6, 17, &udp(&payload)), 6);
        let datagram = ip.split_off(40);
        for (i, &(_, len)) in exts.iter().enumerate() {
            let next = exts.get(i + 1).map_or(17, |e| e.0);
            let size = 8 * (usize::from(len) + 1);
            // Options: one PadN filling the header; a routing header: type 0, no segments left.
            let mut h = vec![next, len, 1, u8::try_from(size - 4).unwrap()];
            h.resize(size, 0);
            ip.extend(h);
        }
        ip[6] = exts[0].0;
        ip.extend(datagram);
        let len = u16::try_from(ip.len() - 40).unwrap();
        ip[4..6].copy_from_slice(&len.to_be_bytes());
        inner6(ip)
    };
    cases.push(("v6 routing header UDP good", chained(&[(43, 0)])));
    cases.push(("v6 destination options UDP good", chained(&[(60, 1)])));
    cases.push((
        "v6 hop-by-hop not first (after destination options) UDP",
        chained(&[(60, 0), (0, 0)]),
    ));
    cases.push(("v6 two hop-by-hop UDP", chained(&[(0, 0), (0, 0)])));
    // The hop-by-hop header claims 88 bytes, more than the packet holds.
    let mut overflow = chained(&[(0, 0)]);
    overflow[14 + 40 + 1] = 10;
    cases.push(("v6 hop-by-hop overflowing the packet bad", overflow));
    // The routing header claims 16 bytes and so swallows the UDP header: a chain within the
    // packet, ending in garbage.
    let mut swallowed = chained(&[(43, 0)]);
    swallowed[14 + 40 + 1] = 1;
    cases.push(("v6 routing header swallowing the UDP header", swallowed));
    // A binding refresh request: a mobility header, payload protocol 59 (none), length 0.
    let mobility = inner6(ipv6(a6, b6, 135, &[59, 0, 0, 0, 0, 0, 0, 0]));
    cases.push(("v6 mobility header good", mobility));
    let shorter6 = |mut f: Vec<u8>, by: u16| {
        let len = u16::from_be_bytes([f[14 + 4], f[14 + 5]]) - by;
        f[14 + 4..14 + 6].copy_from_slice(&len.to_be_bytes());
        f
    };
    let short6 = |f| shorter6(f, 4);
    cases.push(("inner v6 payload length short UDP", short6(inner6(v6udp()))));
    cases.push(("inner v6 payload length short TCP", short6(inner6(v6tcp()))));
    cases.push((
        "inner v6 payload length short hop-by-hop UDP",
        short6(chained(&[(0, 0)])),
    ));
    cases.push((
        "inner v6 payload length 8 short hop-by-hop UDP",
        shorter6(chained(&[(0, 0)]), 8),
    ));
    cases.push((
        "inner v6 payload length 12 short hop-by-hop UDP",
        shorter6(chained(&[(0, 0)]), 12),
    ));
    let hbh_tcp = {
        let mut ip = checksummed(ipv6(a6, b6, 6, &tcp(&payload)), 16);
        let segment = ip.split_off(40);
        ip[6] = 0;
        ip.extend([6, 0, 1, 4, 0, 0, 0, 0]);
        ip.extend(segment);
        let len = u16::try_from(ip.len() - 40).unwrap();
        ip[4..6].copy_from_slice(&len.to_be_bytes());
        inner6(ip)
    };
    cases.push(("v6 hop-by-hop TCP good", hbh_tcp.clone()));
    cases.push((
        "inner v6 payload length short hop-by-hop TCP",
        short6(hbh_tcp),
    ));
    let mut frames: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (id, (name, inner)) in (0u16..).zip(cases.drain(..)) {
        frames.push((name, vxlan(mac, id, &inner)));
    }
    // Outer defects, on a good inner frame.
    let n = u16::try_from(frames.len()).unwrap();
    let outer = |id, at: usize, b: u8| with(vxlan(mac, id, &inner4(v4udp())), at, b);
    frames.push(("outer v4 header checksum bad", outer(n, 14 + 10, 0x01)));
    frames.push((
        "outer v4 total length short",
        rechecked(outer(n + 1, 14 + 3, 0x04), 14),
    ));
    frames.push((
        "outer v4 total length long",
        rechecked(outer(n + 2, 14 + 2, 0x01), 14),
    ));
    frames.push((
        "outer UDP checksum bad (zero is the norm)",
        outer(n + 3, 34 + 6, 0x01),
    ));
    frames
}

/// The integrity truth table measured on a BlueField-3 by `integrity_truth_table`, one row per
/// case of `integrity_cases`; columns as there.
const MEASURED_INTEGRITY: [&str; 45] = [
    "YYYYYYYYYY", // v4 UDP good
    "YYYYYYYYYY", // v4 TCP good
    "YYYYY.YYY.", // v6 UDP good
    "YYYYY.YYY.", // v6 TCP good
    "YYYYYY....", // v4 ICMP good
    "YYYY......", // ARP
    "YYYYY.YYY.", // inner v4 header checksum bad
    "YYYYYY.Y..", // inner v4 total length short
    "YYYY..YYY.", // inner v4 total length long
    "YYYY......", // inner v4 IHL 4
    "YYYYYY....", // inner v4 IHL 6
    "YYYYYY....", // inner v4 UDP checksum bad
    "YYYYYYYYYY", // inner v4 UDP checksum zero
    "YYYYYY....", // inner v4 UDP length bad
    "YYYYYY....", // inner v4 TCP checksum bad
    "YYYYY.....", // inner v6 UDP checksum bad
    "YYYYY.YYY.", // inner v6 UDP checksum zero
    "YYYYY.....", // inner v6 TCP checksum bad
    "YYYY..YYY.", // inner v6 payload length bad
    "YYYYYY.Y..", // inner v4 first fragment
    "YYYYYY....", // inner v4 later fragment
    "YYYYYYYYYY", // v4 UDP with IP options good
    "YYYYY.YYY.", // v6 hop-by-hop UDP good
    "YYYYY..Y..", // v6 fragment header (first) UDP
    "YYYYYYYYYY", // inner VLAN-tagged v4 UDP good
    "YYYYYYYYYY", // inner v4 TCP padded to 60 good
    "YYYYYYYYYY", // inner v4 UDP shorter than its IP payload
    "YYYYY.YYY.", // v6 routing header UDP good
    "YYYYY.YYY.", // v6 destination options UDP good
    "YYYYY.YYY.", // v6 hop-by-hop not first (after destination options) UDP
    "YYYYY.YYY.", // v6 two hop-by-hop UDP
    "YYYY......", // v6 hop-by-hop overflowing the packet bad
    "YYYYY.....", // v6 routing header swallowing the UDP header
    "YYYYY.....", // v6 mobility header good
    "YYYYY..Y..", // inner v6 payload length short UDP
    "YYYYY.....", // inner v6 payload length short TCP
    "YYYYY.YYY.", // inner v6 payload length short hop-by-hop UDP
    "YYYYY.YYY.", // inner v6 payload length 8 short hop-by-hop UDP
    "YYYYY..Y..", // inner v6 payload length 12 short hop-by-hop UDP
    "YYYYY.YYY.", // v6 hop-by-hop TCP good
    "YYYYY.....", // inner v6 payload length short hop-by-hop TCP
    "Y.YYYYYYY.", // outer v4 header checksum bad
    "YY.Y...Y..", // outer v4 total length short
    "Y.YY...Y..", // outer v4 total length long
    "YY..YYYYYY", // outer UDP checksum bad
];

/// The model's integrity verdicts agree with what the hardware measured, case by case.
#[test]
fn integrity_model_matches_hardware() {
    use dpdk::flow::IntegrityMatch as I;
    let columns: [[u64; 2]; 10] = [
        [0, 0],
        [I::L3_OK | I::IPV4_CSUM_OK, 0],
        [I::L4_OK, 0],
        [I::L4_CSUM_OK, 0],
        [0, I::L3_OK],
        [0, I::L3_OK | I::IPV4_CSUM_OK],
        [0, I::L4_OK],
        [0, I::L4_CSUM_OK],
        [0, I::L4_OK | I::L4_CSUM_OK],
        [
            I::L3_OK | I::IPV4_CSUM_OK,
            I::L3_OK | I::IPV4_CSUM_OK | I::L4_OK | I::L4_CSUM_OK,
        ],
    ];
    let cases = integrity_cases([0x02, 0, 0, 0, 0, 9]);
    assert_eq!(cases.len(), MEASURED_INTEGRITY.len());
    let mut wrong = Vec::new();
    for ((name, frame), measured) in cases.iter().zip(MEASURED_INTEGRITY) {
        let [outer, inner] = dpdk::flow::model::verdicts(frame);
        let modelled: String = columns
            .iter()
            .map(|[o, i]| {
                if outer & o == *o && inner & i == *i {
                    'Y'
                } else {
                    '.'
                }
            })
            .collect();
        if modelled != measured {
            wrong.push(format!("{name}: measured {measured}, modelled {modelled}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Which crafted frames mlx5 finds intact, per integrity verdict: a table for the design of the
/// integrity offload.
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
#[allow(clippy::too_many_lines)] // a table of conditions, and one of cases
fn integrity_truth_table() {
    use dpdk::flow::template::{SharedTable, TableConfig};
    use dpdk::flow::{
        EthMatch, FlowGroup, IntegrityMatch as I, Ipv4Match, Priority, UdpMatch, VxlanMatch,
    };
    let conditions: Vec<(&str, Vec<I>)> = vec![
        ("none", vec![]),
        ("outer L3+csum", vec![I::outer(I::L3_OK | I::IPV4_CSUM_OK)]),
        ("outer L4", vec![I::outer(I::L4_OK)]),
        ("outer L4csum", vec![I::outer(I::L4_CSUM_OK)]),
        ("inner L3", vec![I::inner(I::L3_OK)]),
        ("inner L3+csum", vec![I::inner(I::L3_OK | I::IPV4_CSUM_OK)]),
        ("inner L4", vec![I::inner(I::L4_OK)]),
        ("inner L4csum", vec![I::inner(I::L4_CSUM_OK)]),
        ("inner L4+csum", vec![I::inner(I::L4_OK | I::L4_CSUM_OK)]),
        (
            "all",
            vec![
                I::outer(I::L3_OK | I::IPV4_CSUM_OK),
                I::inner(I::L3_OK | I::IPV4_CSUM_OK | I::L4_OK | I::L4_CSUM_OK),
            ],
        ),
    ];
    RIG.with_borrow_mut(|rig| {
        let rig = rig.get_or_insert_with(Rig::new);
        let cases = integrity_cases(rig.link.mac);
        let wires: Vec<Vec<u8>> = cases.iter().map(|(_, f)| f.clone()).collect();
        let flows = &rig.flows;
        let mut columns: Vec<(String, Vec<char>)> = Vec::new();
        for (name, items) in &conditions {
            let mut pattern = dpdk::flow::template::Pattern::new();
            for item in items {
                pattern = pattern.integrity(*item);
            }
            let ok_pattern = pattern
                .eth(EthMatch::default())
                .ipv4(Ipv4Match::default())
                .udp(UdpMatch::default().dst(4789))
                .vxlan(VxlanMatch::default())
                .complete();
            let any = dpdk::flow::template::Pattern::new()
                .eth(EthMatch::default())
                .complete();
            let root = dpdk::flow::template::Pattern::new()
                .eth(EthMatch::default())
                .ipv4(Ipv4Match::default())
                .udp(UdpMatch::default().dst(4789))
                .complete();
            let result = (|| -> Result<Vec<Option<Option<u32>>>, String> {
                let tpl = |p: &dpdk::flow::template::Pattern<dpdk::flow::template::Complete>| {
                    flows
                        .pattern_template::<dpdk::flow::Ingress, _>(p)
                        .map(std::rc::Rc::new)
                        .map_err(|e| e.to_string())
                };
                let act = |a: &[TemplateAction]| {
                    flows
                        .actions_template::<dpdk::flow::Ingress>(a)
                        .map(std::rc::Rc::new)
                        .map_err(|e| e.to_string())
                };
                let table = |group, priority, p, a| {
                    SharedTable::new(
                        flows,
                        TableConfig {
                            group: FlowGroup(group),
                            priority: Priority(priority),
                            capacity: 1,
                        },
                        &[p],
                        &[a],
                    )
                    .map_err(|e| e.to_string())
                };
                let ok = table(
                    1,
                    0,
                    tpl(&ok_pattern)?,
                    act(&[
                        TemplateAction::Mark(1),
                        TemplateAction::Queue(RxQueueIndex(0)),
                    ])?,
                )?;
                let rest = table(
                    1,
                    1,
                    tpl(&any)?,
                    act(&[
                        TemplateAction::Mark(2),
                        TemplateAction::Queue(RxQueueIndex(0)),
                    ])?,
                )?;
                let roots = table(
                    0,
                    0,
                    tpl(&root)?,
                    act(&[TemplateAction::Jump(FlowGroup(1))])?,
                )?;
                let _ok = ok
                    .insert(0, &ok_pattern, 0, &[])
                    .map_err(|e| e.to_string())?;
                let _rest = rest.insert(0, &any, 0, &[]).map_err(|e| e.to_string())?;
                let root_rule = roots.insert(0, &root, 0, &[]).map_err(|e| e.to_string())?;
                let marks = rig.link.exchange_marked(&wires);
                drop(root_rule);
                Ok(marks)
            })();
            let column = match result {
                Ok(marks) => marks
                    .iter()
                    .map(|m| match m {
                        Some(Some(1)) => 'Y',
                        Some(Some(2)) => '.',
                        Some(_) => '?',
                        None => '-',
                    })
                    .collect(),
                Err(e) => {
                    eprintln!("integrity: {name}: refused: {e}");
                    vec!['R'; wires.len()]
                }
            };
            columns.push(((*name).to_string(), column));
        }
        eprintln!("integrity: Y = intact by the verdict, . = not, - = never arrived, R = refused");
        for (c, (name, _)) in columns.iter().enumerate() {
            eprintln!("integrity: column {c}: {name}");
        }
        for (row, (name, _)) in cases.iter().enumerate() {
            let cells: String = columns.iter().map(|(_, col)| col[row]).collect();
            eprintln!("integrity: {cells}  {name}");
        }
    });
}

/// Whether a crafted frame is corrupt: what an integrity rule set must drop (`Some(true)`), must
/// pass (`Some(false)`), or may do either with (`None`).
fn corrupt(name: &str) -> Option<bool> {
    if name.contains("short hop-by-hop UDP") {
        // Corrupt, but mlx5 does not subtract the extension headers before holding the UDP
        // length to the IPv6 payload length: it may pass.
        return None;
    }
    if name.contains("hop-by-hop not first") || name.contains("two hop-by-hop") {
        // Malformed by RFC 8200, but not what a checksum or a length catches: either is fine.
        return None;
    }
    if name.contains("v6 UDP checksum zero") {
        // Invalid by RFC 8200, but endpoints of tunnels accept it (RFC 6935).
        return None;
    }
    let corrupt = [
        "bad",
        "long",
        "IHL 4",
        "IHL 6",
        "total length short",
        "payload length short",
        "swallowing",
    ];
    Some(
        corrupt.iter().any(|c| name.contains(c)) && !name.contains("zero is the norm")
            || name.contains("outer UDP checksum bad"),
    )
}

/// A whole integrity rule set, by category and priority (no negative matching): which crafted
/// frames it passes and which it drops.
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
#[allow(clippy::too_many_lines)] // the rule set, table by table
fn integrity_rule_set() {
    use dpdk::flow::template::{Complete, Pattern, SharedTable, TableConfig};
    use dpdk::flow::{
        EthMatch, FlowGroup, IntegrityMatch as I, Ipv4Match, Ipv6Match, Priority, UdpMatch,
        VxlanMatch,
    };
    let outer_ok = I::outer(I::L3_OK | I::IPV4_CSUM_OK | I::L4_OK | I::L4_CSUM_OK);
    let tunnel = |items: &[I]| {
        let mut p = Pattern::new();
        for i in items {
            p = p.integrity(*i);
        }
        p.eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(4789))
            .vxlan(VxlanMatch::default())
            .inner_eth(EthMatch::default().tagged(false))
    };
    let v4 = |items: &[I], proto: Option<u8>| -> Pattern<Complete> {
        let ip = match proto {
            Some(p) => Ipv4Match::default().unfragmented().proto(p),
            None => Ipv4Match::default(),
        };
        tunnel(items).ipv4(ip).complete()
    };
    let v6 = |items: &[I], proto: Option<u8>| -> Pattern<Complete> {
        let ip = match proto {
            Some(p) => Ipv6Match::default().unfragmented().proto(p),
            None => Ipv6Match::default(),
        };
        tunnel(items).ipv6(ip).complete()
    };
    let any_inner = |items: &[I]| -> Pattern<Complete> {
        let mut p = Pattern::new();
        for i in items {
            p = p.integrity(*i);
        }
        p.eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(4789))
            .vxlan(VxlanMatch::default())
            .complete()
    };
    let l4 = I::L3_OK | I::L4_OK | I::L4_CSUM_OK;
    // (priority, patterns of the table's rules, pass)
    let tables: Vec<(u32, Vec<Pattern<Complete>>, bool)> = vec![
        (
            0,
            vec![
                v4(&[outer_ok, I::inner(l4 | I::IPV4_CSUM_OK)], Some(6)),
                v4(&[outer_ok, I::inner(l4 | I::IPV4_CSUM_OK)], Some(17)),
            ],
            true,
        ),
        (
            0,
            vec![
                v6(&[outer_ok, I::inner(l4)], Some(6)),
                v6(&[outer_ok, I::inner(l4)], Some(17)),
            ],
            true,
        ),
        (1, vec![v4(&[], Some(6)), v4(&[], Some(17))], false),
        (1, vec![v6(&[], Some(6)), v6(&[], Some(17))], false),
        (
            2,
            vec![v4(&[outer_ok, I::inner(I::L3_OK | I::IPV4_CSUM_OK)], None)],
            true,
        ),
        (2, vec![v6(&[outer_ok, I::inner(I::L3_OK)], None)], true),
        (3, vec![v4(&[], None)], false),
        (3, vec![v6(&[], None)], false),
        (4, vec![any_inner(&[outer_ok])], true),
        (5, vec![any_inner(&[])], false),
    ];
    RIG.with_borrow_mut(|rig| {
        let rig = rig.get_or_insert_with(Rig::new);
        let cases = integrity_cases(rig.link.mac);
        let wires: Vec<Vec<u8>> = cases.iter().map(|(_, f)| f.clone()).collect();
        let flows = &rig.flows;
        let act = |a: &[TemplateAction]| {
            std::rc::Rc::new(flows.actions_template::<dpdk::flow::Ingress>(a).unwrap())
        };
        let pass = act(&[
            TemplateAction::Mark(1),
            TemplateAction::Queue(RxQueueIndex(0)),
        ]);
        let drop_ = act(&[
            TemplateAction::Mark(3),
            TemplateAction::Queue(RxQueueIndex(0)),
        ]);
        let mut installed = Vec::new();
        for (priority, patterns, passes) in &tables {
            let template = std::rc::Rc::new(
                flows
                    .pattern_template::<dpdk::flow::Ingress, _>(&patterns[0])
                    .unwrap(),
            );
            let table = SharedTable::new(
                flows,
                TableConfig {
                    group: FlowGroup(1),
                    priority: Priority(*priority),
                    capacity: 4,
                },
                &[template],
                &[if *passes { pass.clone() } else { drop_.clone() }],
            )
            .unwrap_or_else(|e| panic!("table at priority {priority}: {e}"));
            for p in patterns {
                installed.push(table.insert(0, p, 0, &[]).unwrap());
            }
        }
        let root_pattern = Pattern::new()
            .eth(EthMatch::default())
            .ipv4(Ipv4Match::default())
            .udp(UdpMatch::default().dst(4789))
            .complete();
        let root_t = std::rc::Rc::new(
            flows
                .pattern_template::<dpdk::flow::Ingress, _>(&root_pattern)
                .unwrap(),
        );
        let root = SharedTable::new(
            flows,
            TableConfig {
                group: FlowGroup(0),
                priority: Priority(0),
                capacity: 1,
            },
            &[root_t],
            &[act(&[TemplateAction::Jump(FlowGroup(1))])],
        )
        .unwrap();
        let root_rule = root.insert(0, &root_pattern, 0, &[]).unwrap();
        let marks = rig.link.exchange_marked(&wires);
        drop(root_rule);
        drop(installed);
        let mut wrong = 0;
        for ((name, _), mark) in cases.iter().zip(&marks) {
            let dropped = match mark {
                Some(Some(1)) => Some(false),
                Some(Some(3)) => Some(true),
                _ => None,
            };
            let expected = corrupt(name);
            let ok = match (dropped, expected) {
                (Some(d), Some(e)) => d == e,
                (Some(_), None) => true,
                (None, _) => false,
            };
            wrong += usize::from(!ok);
            eprintln!(
                "integrity rule set: {} {:>8}  {name}",
                if ok { "ok   " } else { "WRONG" },
                match dropped {
                    Some(true) => "dropped",
                    Some(false) => "passed",
                    None => "missing",
                }
            );
        }
        assert_eq!(
            wrong, 0,
            "the rule set dropped or passed what it should not"
        );
    });
}

/// The validation group as planned and installed: the crafted frames arrive as the model says,
/// corrupt ones are dropped and counted, valid ones pass.
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
fn integrity_plan() {
    let program = Program {
        validate: true,
        ..Program::default()
    };
    let plan = Plan::new(
        &program,
        &vteps(&program),
        &TemplateAction::Queue(RxQueueIndex(0)),
    )
    .unwrap();
    RIG.with_borrow_mut(|rig| {
        let rig = rig.get_or_insert_with(Rig::new);
        let cases = integrity_cases(rig.link.mac);
        let wires: Vec<Vec<u8>> = cases.iter().map(|(_, f)| f.clone()).collect();
        let (arrived, counts) = with_installed(&rig.flows, &plan, |installed| {
            assert!(installed.refused().is_empty(), "{:?}", installed.refused());
            let arrived = rig.link.exchange(&wires);
            std::thread::sleep(COUNTER_LAG);
            (arrived, installed.counts())
        })
        .unwrap();
        let mut wrong = Vec::new();
        for (((name, wire), arrived), id) in cases.iter().zip(&arrived).zip(0..) {
            let outcomes = plan.outcomes(wire).unwrap();
            let modelled = outcomes.iter().any(arrives);
            let expected = corrupt(name);
            let ok = outcomes.iter().all(|o| arrives(o) == arrived.is_some())
                && expected.is_none_or(|corrupt| corrupt != arrived.is_some());
            eprintln!(
                "integrity plan: {} {:>11}  {name}",
                if ok { "ok   " } else { "WRONG" },
                if arrived.is_some() {
                    "arrived"
                } else {
                    "dropped"
                },
            );
            if !ok {
                wrong.push(format!(
                    "{id} {name}: arrived {}, model {modelled}, corrupt {expected:?}",
                    arrived.is_some()
                ));
            }
        }
        let dropped = arrived.iter().filter(|a| a.is_none()).count();
        let counted: u64 = counts
            .iter()
            .filter(|(role, _)| matches!(role, Role::Corrupt(_)))
            .map(|(_, c)| c.packets)
            .sum();
        eprintln!("integrity plan: {dropped} dropped, validation counted {counted}");
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        assert_eq!(counted, u64::try_from(dropped).unwrap());
    });
}

/// Every IP protocol number, IPv4 and IPv6, with and without a hop-by-hop header, through the
/// validation group: the NIC must do what the model says.
#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
fn integrity_protocols() {
    let program = Program {
        validate: true,
        ..Program::default()
    };
    let mut plan = Plan::new(
        &program,
        &vteps(&program),
        &TemplateAction::Queue(RxQueueIndex(0)),
    )
    .unwrap();
    // Count what passes validation too, for NIC_OFFLOAD_PROBE.
    plan.actions.push(vec![
        TemplateAction::Count,
        TemplateAction::Jump(crate::mlx5::SWITCH),
    ]);
    let counted = plan.actions.len() - 1;
    for table in &mut plan.validation {
        if table
            .rules
            .iter()
            .all(|r| matches!(r.role, Role::Intact(_)))
        {
            table.actions = vec![counted];
        }
    }
    let mut frames = Vec::new();
    for (v6, hop_by_hop) in [(false, false), (true, false), (true, true)] {
        for proto in 0..=u8::MAX {
            frames.push((
                (v6, hop_by_hop, proto),
                crate::differential::protocol_frame(v6, proto, hop_by_hop),
            ));
        }
    }
    RIG.with_borrow_mut(|rig| {
        let rig = rig.get_or_insert_with(Rig::new);
        // Identified by outer IP identification within each chunk of 128.
        let wires: Vec<Vec<u8>> = (0u16..)
            .zip(&frames)
            .map(|(id, (_, f))| f.wire_to(rig.link.mac, id % 128))
            .collect();
        let probe: Vec<usize> = std::env::var("NIC_OFFLOAD_PROBE")
            .ok()
            .map(|v| v.split(',').filter_map(|i| i.parse().ok()).collect())
            .unwrap_or_default();
        let arrived = with_installed(&rig.flows, &plan, |installed| {
            // Which rule takes each probed frame, by the counters it moves.
            for &i in &probe {
                let before = installed.counts();
                rig.link
                    .exchange(&[frames[i].1.wire_to(rig.link.mac, 0)]);
                std::thread::sleep(COUNTER_LAG);
                let moved: Vec<Role> = installed
                    .counts()
                    .iter()
                    .zip(&before)
                    .filter(|((_, a), (_, b))| a.packets != b.packets)
                    .map(|((role, _), _)| *role)
                    .collect();
                eprintln!("integrity protocols: probe {:?}: counted by {moved:?}", frames[i].0);
            }
            // In chunks the receive ring holds.
            wires
                .chunks(128)
                .flat_map(|chunk| rig.link.exchange(chunk))
                .collect::<Vec<_>>()
        })
        .unwrap();
        let mut wrong = Vec::new();
        for (((what, _), wire), arrived) in frames.iter().zip(&wires).zip(&arrived) {
            let outcomes = plan.outcomes(wire).unwrap();
            if !outcomes.iter().all(|o| arrives(o) == arrived.is_some()) {
                let path: Vec<_> = outcomes.iter().map(|o| o.path.clone()).collect();
                let verdicts = dpdk::flow::model::verdicts(wire);
                wrong.push(format!(
                    "(v6, hop-by-hop, proto) {what:?}: arrived {}, model {path:?}, verdicts {verdicts:x?}",
                    arrived.is_some()
                ));
            }
        }
        eprintln!("integrity protocols: {} of {} disagree", wrong.len(), frames.len());
        for w in &wrong {
            eprintln!("integrity protocols: {w}");
        }
        assert!(wrong.is_empty(), "the NIC and the model disagree");
    });
}
