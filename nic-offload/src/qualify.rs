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

use crate::differential::{RawFrame, RawMeter, RawRule, overlay};
use crate::mlx5::{Plan, RESOURCES, Role, with_installed};
use crate::model::{Outcome, Verdict};
use crate::program::Program;

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
            "--log-level=pmd.net.mlx5:error".to_string(),
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
    for table in &mut plan.tables {
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
fn qualify_case(rig: &mut Rig, meters: &[RawMeter; 4], rules: &[RawRule], frames: &[RawFrame]) {
    let overlay = overlay(meters, rules).expect("generated configurations are valid");
    let writer: RateLimitWriter<PeeringRules> =
        RateLimitWriter::new(RateLimits::empty(), NonZeroUsize::MIN);
    writer.apply(&overlay, Backend::Reference).unwrap();
    let program = Program::compile(&writer.load());
    let mut plan = Plan::new(&program, &TemplateAction::Queue(RxQueueIndex(0))).unwrap();
    let wires: Vec<Vec<u8>> = (0u16..)
        .zip(frames)
        .map(|(id, raw)| raw.frame(rules).wire_to(rig.link.mac, id))
        .collect();
    for profile in &mut plan.profiles {
        *profile = passes_everything();
    }
    let started = clock::now();

    // Frames that do not arrive even when every meter passes: not the meters' doing.
    let mut unmetered = 0;
    for red in std::iter::once(None).chain((0..plan.profiles.len()).map(Some)) {
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
            "qualify: {} rule(s) ({} refused), {} meter(s), meter {red:?} dropping: {} of {} frames arrived, dropping rules counted {drop_counted}",
            program.rules.len(),
            refused.len(),
            plan.profiles.len(),
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

thread_local! {
    static RIG: RefCell<Option<Rig>> = const { RefCell::new(None) };
}

#[test]
#[ignore = "needs two wired NIC ports: see the module documentation"]
fn qualify() {
    // Each case takes seconds on hardware (several installs, and waits for the counters).
    let cases = std::env::var("NIC_OFFLOAD_QUALIFY_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20);
    bolero::check!()
        .with_iterations(cases)
        .with_shrink_time(Duration::from_secs(120))
        .with_type::<([RawMeter; 4], Vec<RawRule>, Vec<RawFrame>)>()
        .for_each(|(meters, rules, frames)| {
            let rules = &rules[..rules.len().min(6)];
            // Aim most frames at a rule: a frame no rule charges says little about the NIC.
            let frames: Vec<RawFrame> = (0u8..)
                .zip(&frames[..frames.len().min(32)])
                .map(|(i, frame)| {
                    let mut frame = frame.clone();
                    if i % 4 != 0 {
                        frame.aim = Some(frame.aim.unwrap_or(i));
                    }
                    frame
                })
                .collect();
            let frames = &frames[..];
            RIG.with_borrow_mut(|rig| {
                let rig = rig.get_or_insert_with(Rig::new);
                qualify_case(rig, meters, rules, frames);
            });
        });
}
