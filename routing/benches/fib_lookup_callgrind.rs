// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::hint::black_box;

use iai_callgrind::{
    Cachegrind, Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};

use dataplane_routing::testing::{Fib, FibGroup, FibWriter, FwAction, NhopKey, RouteOrigin};
use dataplane_routing::{EgressObject, FibEntry, PktInstruction};
use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::packet::Packet;
use net::packet::test_utils::build_test_ipv4_packet_with_transport;

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

struct Fixture {
    writer: FibWriter,
    packet: Packet<TestBuffer>,
}

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

#[library_benchmark]
#[bench::guard_only(args = (1, 1), setup = fixture)]
fn enter_only(fixture: &'static Fixture) {
    black_box(fixture.writer.enter().expect("fib is readable"));
}

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

#[library_benchmark(
    config = LibraryBenchmarkConfig::default()
        .tool(Cachegrind::default().args([
            "--D1=32768,8,64",
            "--I1=32768,8,64",
            "--LL=33554432,16,64",
        ]))
        .tool(Dhat::default())
)]
#[bench::g1_e1(args = (1, 1), setup = fixture)]
#[bench::g16_e4(args = (16, 4), setup = fixture)]
fn under_other_tools(fixture: &'static Fixture) {
    let fib = fixture.writer.enter().expect("fib is readable");
    let (prefix, entry) = Fib::lpm_entry_prefix(&fib, black_box(&fixture.packet));
    black_box((prefix, entry));
}

library_benchmark_group!(
    name = fib_lookup;
    benchmarks = enter_only, lpm_entry_prefix, under_other_tools
);
main!(library_benchmark_groups = fib_lookup);
