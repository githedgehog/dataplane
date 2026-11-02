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
//! `NIC_OFFLOAD_QUALIFY_CASES` sets how many cases run (default 20).

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
        let program = Program::compile(
            &filter,
            &writer.load(),
            &crate::differential::destinations(&overlay),
            excluded,
        );
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
    let acted =
        stats.get("charged").copied().unwrap_or(0) + stats.get("denied").copied().unwrap_or(0);
    // About half are: frames aimed at a rule's destination outside its peer's exposes, and frames
    // aimed at nothing, are neither.
    assert!(
        acted * 5 >= total * 2,
        "only {acted} of {total} generated frames are charged by a meter or denied"
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
            let limits: Vec<_> = vpc.spec.limits.iter().map(|(m, k)| (m, &k.name)).collect();
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
