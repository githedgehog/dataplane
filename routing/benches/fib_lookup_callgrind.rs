// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The same fib lookup as `fib_lookup.rs`, counted instead of timed.
//!
//! Callgrind executes the program on a synthetic machine and counts what it does: instructions
//! retired, and hits and misses against a modelled cache hierarchy. That buys repeatability a
//! wall-clock benchmark cannot have -- no scheduler, no frequency scaling, no neighbours -- at the
//! cost of measuring a CPU nobody ships. It does not model this machine's out-of-order execution,
//! it has no AVX-512, and its cache model is a simplification of any real one.
//!
//! So the numbers here are not predictions of time. They are useful for two things: catching a
//! change in how much *work* a path does, which is stable enough to gate in CI; and, read next to
//! `fib_lookup.rs`, showing where counting and timing disagree -- which is where a real machine's
//! behaviour is doing something the model cannot see.
//!
//! The fixtures are deliberately identical to the criterion bench so the two can be compared.

use std::hint::black_box;

use iai_callgrind::{library_benchmark, library_benchmark_group, main};

use dataplane_routing::testing::{Fib, FibGroup, FibWriter, FwAction, NhopKey, RouteOrigin};
use dataplane_routing::{EgressObject, FibEntry, PktInstruction};
use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::packet::Packet;
use net::packet::test_utils::build_test_ipv4_packet_with_transport;

/// The prefix every shape installs. Covers the test packet's destination.
const ROUTE_ADDR: (&str, u8) = ("5.0.0.0", 8);

fn nhop_key(n: u8) -> NhopKey {
    NhopKey::new(
        RouteOrigin::default(),
        Some(format!("10.0.{n}.1").parse().expect("valid address")),
        InterfaceIndex::try_new(u32::from(n) + 1).ok(),
        None,
        FwAction::Forward,
    )
}

fn fib_group(n: u8, entries: u8) -> FibGroup {
    let mut group = FibGroup::new();
    for e in 0..entries {
        group.add(FibEntry::with_inst(PktInstruction::Egress(
            EgressObject::new(
                InterfaceIndex::try_new(u32::from(n) * 256 + u32::from(e) + 1).ok(),
                Some(format!("10.{n}.{e}.1").parse().expect("valid address")),
            ),
        )));
    }
    group
}

/// Everything the measured body needs, built outside the measurement.
struct Fixture {
    writer: FibWriter,
    packet: Packet<TestBuffer>,
}

/// Build a fixture and leak it.
///
/// Leaking is the point, not laziness. Callgrind counts everything the benchmark function does,
/// including dropping whatever it owns -- and a fib is an expensive thing to drop. Taking the
/// fixture by value costs several thousand instructions of teardown, which swamps a lookup that
/// should be tens, and scales with the fixture, so the result still looks like a plausible
/// measurement of the lookup. Handing the body a `&'static` makes the drop a no-op and leaves the
/// measured region to be the lookup alone. The process exits immediately afterwards.
fn fixture(groups: u8, entries_per_group: u8) -> &'static Fixture {
    let (mut writer, _reader) = FibWriter::new(0);
    let keys: Vec<NhopKey> = (0..groups).map(nhop_key).collect();
    for (n, key) in keys.iter().enumerate() {
        let n = u8::try_from(n).expect("group count fits a byte");
        writer.register_fibgroup(key, &fib_group(n, entries_per_group), false);
    }
    writer.add_fibroute(Prefix::expect_from(ROUTE_ADDR), keys, true);

    let packet = build_test_ipv4_packet_with_transport(64, Some(NextHeader::UDP))
        .expect("a well-formed test packet");

    // Same guard as the criterion bench: if the packet and the route drift apart, every shape
    // silently measures the fib's default route instead of the one built here.
    {
        let fib = writer.enter().expect("fib is readable");
        let (hit, _) = Fib::lpm_entry_prefix(&fib, &packet);
        assert_eq!(
            hit,
            Prefix::expect_from(ROUTE_ADDR),
            "{groups}g x{entries_per_group}e: lookup missed the installed route"
        );
    }
    Box::leak(Box::new(Fixture { writer, packet }))
}

// Acquiring the read guard, which the measured body below has to do and the criterion bench
// hoists out of its loop. Subtract this to compare the two.
#[library_benchmark]
#[bench::guard_only(args = (1, 1), setup = fixture)]
fn enter_only(fixture: &'static Fixture) {
    black_box(fixture.writer.enter().expect("fib is readable"));
}

// The shapes, matching `fib_lookup.rs` exactly.
#[library_benchmark]
#[bench::g1_e1(args = (1, 1), setup = fixture)]
#[bench::g1_e4(args = (1, 4), setup = fixture)]
#[bench::g4_e1(args = (4, 1), setup = fixture)]
#[bench::g4_e4(args = (4, 4), setup = fixture)]
#[bench::g8_e1(args = (8, 1), setup = fixture)]
#[bench::g16_e1(args = (16, 1), setup = fixture)]
#[bench::g16_e4(args = (16, 4), setup = fixture)]
fn lpm_entry_prefix(fixture: &'static Fixture) {
    let fib = fixture.writer.enter().expect("fib is readable");
    let (prefix, entry) = Fib::lpm_entry_prefix(&fib, black_box(&fixture.packet));
    black_box((prefix, entry));
}

library_benchmark_group!(name = fib_lookup; benchmarks = enter_only, lpm_entry_prefix);
main!(library_benchmark_groups = fib_lookup);
