// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a packet costs to route, in wall-clock time.
//!
//! `Fib::lpm_entry_prefix` walks a route's fib groups twice: once in `FibRoute::len`, to learn how
//! many entries there are to hash across, and again in `FibRoute::get_fibentry`, to turn the
//! resulting virtual index back into a group and an offset. The shapes vary groups and
//! entries-per-group independently, because that is what separates the two costs: the walk is per
//! *group*, while the hash is over the entry *total*.
//!
//! Measured on this bench, caching the count in `FibRoute` is **not** an improvement: it makes the
//! one-group case ~3% slower and only pays from about eight groups up. See
//! `development/code/benchmarking.md`, and `fib_lookup_callgrind.rs` for the same fixtures counted
//! rather than timed.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

mod common;
use common::{Fixture, fixture, lookup, packet};

/// Expand the shared shape list into an array this bench can loop over.
macro_rules! shape_table {
    ($($id:ident = ($groups:expr, $entries:expr)),* $(,)?) => {
        &[$((stringify!($id), $groups, $entries)),*]
    };
}
const SHAPES: &[(&str, u8, u8)] = for_each_shape!(shape_table);

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("fib_lpm_entry_prefix");
    for &(id, groups, entries) in SHAPES {
        let fixture: &'static Fixture = fixture(groups, entries);
        let total = u64::from(groups) * u64::from(entries);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{id} ({total} entries)")),
            &fixture,
            |b, fixture| b.iter(|| lookup(black_box(fixture))),
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

    for &(groups, entries) in &[(1u8, 1u8), (16, 1)] {
        let fixture = fixture(groups, entries);
        group.bench_function(
            BenchmarkId::from_parameter(format!("{groups}g x{entries}e")),
            |b| {
                let fib = fixture.writer.enter().expect("fib is readable");
                b.iter(|| black_box(fib.lpm_with_prefix(black_box(&destination))));
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
