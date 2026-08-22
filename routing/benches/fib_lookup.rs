// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

mod common;
use common::{Fixture, fixture, lookup, packet};

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

fn bench_destination(c: &mut Criterion) {
    let packet = packet();
    c.bench_function("packet_ip_destination", |b| {
        b.iter(|| black_box(black_box(&packet).ip_destination()));
    });
}

criterion_group!(benches, bench_lookup, bench_trie_floor, bench_destination);
criterion_main!(benches);
