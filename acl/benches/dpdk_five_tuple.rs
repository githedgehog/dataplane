// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "dpdk")]
mod bench {
    use core::net::{Ipv4Addr, Ipv6Addr};
    use core::num::NonZero;

    use std::hint::black_box;

    use criterion::measurement::WallTime;
    use criterion::{BenchmarkGroup, BenchmarkId, Criterion, Throughput};

    use dataplane_acl::dpdk::install::install_table;
    use dataplane_acl::dpdk::lookup::DpdkAclLookup;
    use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
    use dataplane_acl::dpdk_table_alias;
    use dpdk::acl::{CategoryMask, Priority};
    use lookup::Lookup;
    use match_action::{ExactSpec, MatchKey, PrefixSpec, RangeSpec};

    #[derive(MatchKey)]
    struct FiveTuple {
        #[exact]
        proto: u8,
        #[prefix]
        src: Ipv4Addr,
        #[prefix]
        dst: Ipv4Addr,
        #[range]
        sport: u16,
        #[range]
        dport: u16,
    }

    #[derive(MatchKey)]
    struct FiveTuple6 {
        #[exact]
        proto: u8,
        #[prefix]
        src: Ipv6Addr,
        #[prefix]
        dst: Ipv6Addr,
        #[range]
        sport: u16,
        #[range]
        dport: u16,
    }

    dpdk_table_alias!(type FiveTupleTable<A> = FiveTuple);
    dpdk_table_alias!(type FiveTuple6Table<A> = FiveTuple6);
    const RULE_COUNTS: [usize; 15] = [
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
    ];
    const BATCH: usize = 32;
    fn build_table_v4(n: usize) -> FiveTupleTable<u32> {
        let specs: Vec<RuleSpec<FiveTuple, u32>> = (0..n)
            .map(|i| {
                let prio = i32::try_from(i + 1).unwrap_or(i32::MAX);
                let dport = u16::try_from(i).unwrap_or(u16::MAX);
                let action = u32::try_from(i).unwrap_or(u32::MAX);
                RuleSpec::new(
                    Priority::new(prio).expect("nonzero priority"),
                    CategoryMask::new(1).expect("nonzero mask"),
                    FiveTupleRule {
                        proto: ExactSpec::new(6),
                        src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
                        dst: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
                        sport: RangeSpec::new(0, u16::MAX),
                        dport: RangeSpec::exact(dport),
                    }
                    .into_backend_fields::<Dpdk>(),
                    action,
                )
                .expect("valid RuleSpec")
            })
            .collect();
        let max_rules = NonZero::new(u32::try_from(n).unwrap_or(u32::MAX)).expect("n >= 1");
        install_table(&format!("bench_dpdk_v4_{n}"), max_rules, specs).expect("install_table")
    }
    fn build_table_v6(n: usize) -> FiveTuple6Table<u32> {
        let src: Ipv6Addr = "2001:db8::".parse().expect("v6 literal");
        let specs: Vec<RuleSpec<FiveTuple6, u32>> = (0..n)
            .map(|i| {
                let prio = i32::try_from(i + 1).unwrap_or(i32::MAX);
                let dport = u16::try_from(i).unwrap_or(u16::MAX);
                let action = u32::try_from(i).unwrap_or(u32::MAX);
                RuleSpec::new(
                    Priority::new(prio).expect("nonzero priority"),
                    CategoryMask::new(1).expect("nonzero mask"),
                    FiveTuple6Rule {
                        proto: ExactSpec::new(6),
                        src: PrefixSpec::new(src, 32),
                        dst: PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 0),
                        sport: RangeSpec::new(0, u16::MAX),
                        dport: RangeSpec::exact(dport),
                    }
                    .into_backend_fields::<Dpdk>(),
                    action,
                )
                .expect("valid RuleSpec")
            })
            .collect();
        let max_rules = NonZero::new(u32::try_from(n).unwrap_or(u32::MAX)).expect("n >= 1");
        install_table(&format!("bench_dpdk_v6_{n}"), max_rules, specs).expect("install_table")
    }
    fn run_lookups<K, const N: usize, const STRIDE: usize>(
        group: &mut BenchmarkGroup<'_, WallTime>,
        n: usize,
        table: &DpdkAclLookup<K, N, STRIDE, u32>,
        miss: &K,
        hit: &K,
        batch: &[K],
    ) where
        K: MatchKey,
    {
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("single_miss", n), |b| {
            b.iter(|| black_box(table.lookup(black_box(miss))));
        });
        group.bench_function(BenchmarkId::new("single_hit", n), |b| {
            b.iter(|| black_box(table.lookup(black_box(hit))));
        });
        group.throughput(Throughput::Elements(
            u64::try_from(batch.len()).unwrap_or(0),
        ));
        group.bench_function(BenchmarkId::new("batch", n), |b| {
            let mut out: [Option<&u32>; BATCH] = [None; BATCH];
            b.iter(|| {
                table
                    .lookup_batch(black_box(batch), &mut out)
                    .expect("batch");
                black_box(&out);
            });
        });
    }

    fn bench_v4(c: &mut Criterion) {
        let batch: Vec<FiveTuple> = (0..BATCH)
            .map(|j| FiveTuple {
                proto: 6,
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(192, 0, 2, 1),
                sport: 1234,
                dport: u16::try_from(j).unwrap_or(0),
            })
            .collect();

        let mut group = c.benchmark_group("dpdk_five_tuple_v4");
        for n in RULE_COUNTS {
            let table = build_table_v4(n);
            let miss = FiveTuple {
                proto: 6,
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(192, 0, 2, 1),
                sport: 1234,
                dport: u16::MAX,
            };
            let hit = FiveTuple { dport: 0, ..miss };
            run_lookups(&mut group, n, &table, &miss, &hit, &batch);
        }
        group.finish();
    }

    fn bench_v6(c: &mut Criterion) {
        let in_prefix: Ipv6Addr = "2001:db8::1".parse().expect("v6 literal");
        let dst: Ipv6Addr = "::1".parse().expect("v6 literal");
        let batch: Vec<FiveTuple6> = (0..BATCH)
            .map(|j| FiveTuple6 {
                proto: 6,
                src: in_prefix,
                dst,
                sport: 1234,
                dport: u16::try_from(j).unwrap_or(0),
            })
            .collect();

        let mut group = c.benchmark_group("dpdk_five_tuple_v6");
        for n in RULE_COUNTS {
            let table = build_table_v6(n);
            let miss = FiveTuple6 {
                proto: 6,
                src: in_prefix,
                dst,
                sport: 1234,
                dport: u16::MAX,
            };
            let hit = FiveTuple6 { dport: 0, ..miss };
            run_lookups(&mut group, n, &table, &miss, &hit, &batch);
        }
        group.finish();
    }

    pub fn benches(c: &mut Criterion) {
        let _eal = dpdk::test_support::start_eal();
        bench_v4(c);
        bench_v6(c);
    }
}

#[cfg(feature = "dpdk")]
criterion::criterion_group!(benchmarks, bench::benches);
#[cfg(feature = "dpdk")]
criterion::criterion_main!(benchmarks);
#[cfg(not(feature = "dpdk"))]
fn main() {}
