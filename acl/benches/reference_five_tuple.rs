// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used)]

use core::net::{Ipv4Addr, Ipv6Addr};
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use dataplane_acl::reference::{Erased, RefRule, ReferenceTable};
use lookup::Lookup;
use match_action::{ExactSpec, FixedSize, MatchKey, PrefixSpec, RangeSpec};

mod sealed {
    use core::net::{Ipv4Addr, Ipv6Addr};
    pub trait Sealed {}
    impl Sealed for Ipv4Addr {}
    impl Sealed for Ipv6Addr {}
}

trait IpAddress: FixedSize + sealed::Sealed {
    const UNSPECIFIED: Self;
}
impl IpAddress for Ipv4Addr {
    const UNSPECIFIED: Self = Ipv4Addr::UNSPECIFIED;
}
impl IpAddress for Ipv6Addr {
    const UNSPECIFIED: Self = Ipv6Addr::UNSPECIFIED;
}
const RULE_COUNTS: [usize; 15] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
];

#[derive(MatchKey)]
struct FiveTuple<A: IpAddress> {
    #[exact]
    proto: u8,
    #[prefix]
    src: A,
    #[prefix]
    dst: A,
    #[range]
    sport: u16,
    #[range]
    dport: u16,
}
fn deep_scan_table<A: IpAddress>(
    n: usize,
    src: A,
    src_len: u8,
) -> ReferenceTable<FiveTuple<A>, u32> {
    let rules = (0..n)
        .map(|i| {
            RefRule::new(
                FiveTupleRule::<A> {
                    proto: ExactSpec::new(6),
                    src: PrefixSpec::new(src, src_len),
                    dst: PrefixSpec::new(A::UNSPECIFIED, 0),
                    sport: RangeSpec::new(0, u16::MAX),
                    dport: RangeSpec::exact(u16::try_from(i).unwrap_or(u16::MAX)),
                }
                .into_backend_fields::<Erased>(),
                u32::try_from(i).unwrap_or(u32::MAX),
            )
        })
        .collect();
    ReferenceTable::new(rules)
}
fn bench_width<A: IpAddress>(
    c: &mut Criterion,
    name: &str,
    prefix: A,
    prefix_len: u8,
    in_prefix: A,
    dst: A,
) {
    let mut group = c.benchmark_group(name);
    for n in RULE_COUNTS {
        let table = deep_scan_table(n, prefix, prefix_len);
        let miss = FiveTuple {
            proto: 6,
            src: in_prefix,
            dst,
            sport: 1234,
            dport: u16::MAX,
        };
        let hit = FiveTuple {
            proto: 6,
            src: in_prefix,
            dst,
            sport: 1234,
            dport: 0,
        };

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("deep_miss", n), &miss, |b, pkt| {
            b.iter(|| black_box(table.lookup(black_box(pkt))));
        });
        group.bench_with_input(BenchmarkId::new("hit_first", n), &hit, |b, pkt| {
            b.iter(|| black_box(table.lookup(black_box(pkt))));
        });
    }
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_width::<Ipv4Addr>(
        c,
        "reference_five_tuple_v4",
        Ipv4Addr::new(10, 0, 0, 0),
        8,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 0, 2, 1),
    );
    bench_width::<Ipv6Addr>(
        c,
        "reference_five_tuple_v6",
        "2001:db8::".parse().unwrap(),
        32,
        "2001:db8::1".parse().unwrap(),
        "::1".parse().unwrap(),
    );
}

criterion_group!(benchmarks, benches);
criterion_main!(benchmarks);
