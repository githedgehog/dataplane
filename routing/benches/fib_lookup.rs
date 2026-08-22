// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a packet costs to route.
//!
//! `Fib::lpm_entry_prefix` walks a route's fib groups twice: once in `FibRoute::len`, to learn how
//! many entries there are to hash across, and again in `FibRoute::get_fibentry`, to turn the
//! resulting virtual index back into a group and an offset. The second walk is unavoidable; the
//! first exists because the count is not stored anywhere.
//!
//! The shapes below vary groups and entries-per-group independently, because that is what
//! separates the two costs: the walk is per *group*, while the hash is over the entry *total*. A
//! route with one group and one entry is the common case and the floor.
//!
//! Measured on this bench, caching the count in `FibRoute` is **not** an improvement: it makes the
//! one-group case ~3% slower (both walks hit the same cache lines, so the second is nearly free,
//! while the extra field grows `FibRoute` from 24 to 32 bytes and costs more in the trie than it
//! saves) and only pays from about eight groups up, where it is worth 16-22%. Whether that trade
//! is worth taking depends on how wide real ECMP gets; the `fib_lpm_floor` group is there to keep
//! it in proportion, since the trie lookup alone is around 58% of the total either way.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use dataplane_routing::testing::{Fib, FibGroup, FibWriter, FwAction, NhopKey, RouteOrigin};
use dataplane_routing::{EgressObject, FibEntry, PktInstruction};
use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::packet::Packet;
use net::packet::test_utils::build_test_ipv4_packet_with_transport;

/// A next-hop key distinguishable from every other one this bench builds.
fn nhop_key(n: u8) -> NhopKey {
    NhopKey::new(
        RouteOrigin::default(),
        Some(format!("10.0.{n}.1").parse().expect("valid address")),
        InterfaceIndex::try_new(u32::from(n) + 1).ok(),
        None,
        FwAction::Forward,
    )
}

/// A fib group holding `entries` distinct egress entries.
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

/// A fib whose default v4 route is served by `groups` groups of `entries_per_group` entries each.
fn fib_of_shape(groups: u8, entries_per_group: u8) -> FibWriter {
    let (mut writer, _reader) = FibWriter::new(0);
    let keys: Vec<NhopKey> = (0..groups).map(nhop_key).collect();
    for (n, key) in keys.iter().enumerate() {
        let n = u8::try_from(n).expect("group count fits a byte");
        writer.register_fibgroup(key, &fib_group(n, entries_per_group), false);
    }
    // Must cover the test packet's destination, or the lookup falls through to the default route
    // the fib is born with -- which is one group of one entry, and would make every shape here
    // measure the same thing.
    writer.add_fibroute(Prefix::expect_from(ROUTE_ADDR), keys, true);
    writer
}

/// The prefix every shape installs. Covers `TEST_PACKET_DST`.
const ROUTE_ADDR: (&str, u8) = ("5.0.0.0", 8);

fn packet() -> Packet<TestBuffer> {
    build_test_ipv4_packet_with_transport(64, Some(NextHeader::UDP))
        .expect("a well-formed test packet")
}

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("fib_lpm_entry_prefix");
    let packet = packet();

    for (groups, entries) in [(1u8, 1u8), (1, 4), (4, 1), (4, 4), (8, 1), (16, 1), (16, 4)] {
        let writer = fib_of_shape(groups, entries);
        {
            // Check the lookup lands on the route this shape built. Without this the packet's
            // destination and the installed prefix can drift apart and every shape silently
            // measures the fib's default route instead.
            let fib = writer.enter().expect("fib is readable");
            let (hit, _) = Fib::lpm_entry_prefix(&fib, &packet);
            assert_eq!(
                hit,
                Prefix::expect_from(ROUTE_ADDR),
                "{groups}g x{entries}e: lookup missed the installed route"
            );
        }
        let total = u64::from(groups) * u64::from(entries);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{groups}g x{entries}e ({total} entries)")),
            &writer,
            |b, writer| {
                let fib = writer.enter().expect("fib is readable");
                b.iter(|| {
                    let (prefix, entry) = Fib::lpm_entry_prefix(&fib, black_box(&packet));
                    black_box((prefix, entry));
                });
            },
        );
    }
    group.finish();
}

/// The trie lookup on its own, which is the floor: everything `lpm_entry_prefix` adds on top is
/// the entry-selection machinery, and no change to that can take the total below this line.
fn bench_trie_floor(c: &mut Criterion) {
    let mut group = c.benchmark_group("fib_lpm_floor");
    let packet = packet();
    let destination = packet
        .ip_destination()
        .expect("the test packet has a destination");

    for (groups, entries) in [(1u8, 1u8), (16, 1)] {
        let writer = fib_of_shape(groups, entries);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{groups}g x{entries}e")),
            &writer,
            |b, writer| {
                let fib = writer.enter().expect("fib is readable");
                b.iter(|| {
                    black_box(fib.lpm_with_prefix(black_box(&destination)));
                });
            },
        );
    }
    group.finish();
}

/// Pulling the destination out of the packet, which `lpm_entry_prefix` does before it can look
/// anything up. Separated because the floor above hoists it out of the loop, so it would otherwise
/// be counted as part of the entry-selection machinery.
fn bench_destination(c: &mut Criterion) {
    let packet = packet();
    c.bench_function("packet_ip_destination", |b| {
        b.iter(|| black_box(black_box(&packet).ip_destination()));
    });
}

criterion_group!(benches, bench_lookup, bench_trie_floor, bench_destination);
criterion_main!(benches);
