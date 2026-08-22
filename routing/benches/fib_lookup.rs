// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

fn fib_of_shape(groups: u8, entries_per_group: u8) -> FibWriter {
    let (mut writer, _reader) = FibWriter::new(0);
    let keys: Vec<NhopKey> = (0..groups).map(nhop_key).collect();
    for (n, key) in keys.iter().enumerate() {
        let n = u8::try_from(n).expect("group count fits a byte");
        writer.register_fibgroup(key, &fib_group(n, entries_per_group), false);
    }
    writer.add_fibroute(Prefix::expect_from(ROUTE_ADDR), keys, true);
    writer
}

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

fn bench_destination(c: &mut Criterion) {
    let packet = packet();
    c.bench_function("packet_ip_destination", |b| {
        b.iter(|| black_box(black_box(&packet).ip_destination()));
    });
}

criterion_group!(benches, bench_lookup, bench_trie_floor, bench_destination);
criterion_main!(benches);
