// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "dpdk")]
mod bench {
    use std::hint::black_box;

    use concurrency::sync::atomic::{AtomicU32, Ordering};
    use core::net::{Ipv4Addr, Ipv6Addr};
    use core::num::NonZero;

    use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};

    use dataplane_acl::dpdk::install::install_table;
    use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
    use dataplane_acl::dpdk_table_alias;
    use dataplane_acl::reference::{Erased, RefRule, ReferenceTable};
    use dpdk::acl::{CategoryMask, Priority};
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
    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn unique_name(prefix: &str) -> String {
        format!("{prefix}_{}", SEQ.fetch_add(1, Ordering::Relaxed))
    }
    fn rule_v4(i: usize) -> FiveTupleRule {
        FiveTupleRule {
            proto: ExactSpec::new(6),
            src: PrefixSpec::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            dst: PrefixSpec::new(Ipv4Addr::UNSPECIFIED, 0),
            sport: RangeSpec::new(0, u16::MAX),
            dport: RangeSpec::exact(u16::try_from(i).unwrap_or(u16::MAX)),
        }
    }
    fn rule_v6(i: usize) -> FiveTuple6Rule {
        FiveTuple6Rule {
            proto: ExactSpec::new(6),
            src: PrefixSpec::new("2001:db8::".parse().expect("v6 literal"), 32),
            dst: PrefixSpec::new(Ipv6Addr::UNSPECIFIED, 0),
            sport: RangeSpec::new(0, u16::MAX),
            dport: RangeSpec::exact(u16::try_from(i).unwrap_or(u16::MAX)),
        }
    }
    fn build_reference_v4(n: usize) -> ReferenceTable<FiveTuple, u32> {
        let rules = (0..n)
            .map(|i| {
                let action = u32::try_from(i).unwrap_or(u32::MAX);
                RefRule::new(rule_v4(i).into_backend_fields::<Erased>(), action)
            })
            .collect();
        ReferenceTable::new(rules)
    }

    fn build_reference_v6(n: usize) -> ReferenceTable<FiveTuple6, u32> {
        let rules = (0..n)
            .map(|i| {
                let action = u32::try_from(i).unwrap_or(u32::MAX);
                RefRule::new(rule_v6(i).into_backend_fields::<Erased>(), action)
            })
            .collect();
        ReferenceTable::new(rules)
    }
    fn build_dpdk_v4(n: usize) -> FiveTupleTable<u32> {
        let specs: Vec<RuleSpec<FiveTuple, u32>> = (0..n)
            .map(|i| make_spec(i, rule_v4(i).into_backend_fields::<Dpdk>()))
            .collect();
        let max = NonZero::new(u32::try_from(n).unwrap_or(u32::MAX)).expect("n >= 1");
        install_table(&unique_name("table_build_v4"), max, specs).expect("install_table")
    }

    fn build_dpdk_v6(n: usize) -> FiveTuple6Table<u32> {
        let specs: Vec<RuleSpec<FiveTuple6, u32>> = (0..n)
            .map(|i| make_spec(i, rule_v6(i).into_backend_fields::<Dpdk>()))
            .collect();
        let max = NonZero::new(u32::try_from(n).unwrap_or(u32::MAX)).expect("n >= 1");
        install_table(&unique_name("table_build_v6"), max, specs).expect("install_table")
    }
    fn make_spec<K: MatchKey>(
        i: usize,
        fields: Vec<dataplane_acl::dpdk::rule::AclFieldChunks>,
    ) -> RuleSpec<K, u32> {
        let prio = i32::try_from(i + 1).unwrap_or(i32::MAX);
        let action = u32::try_from(i).unwrap_or(u32::MAX);
        RuleSpec::new(
            Priority::new(prio).expect("nonzero priority"),
            CategoryMask::new(1).expect("nonzero mask"),
            fields,
            action,
        )
        .expect("valid RuleSpec")
    }
    fn bench_build_group<R, D>(
        c: &mut Criterion,
        name: &str,
        build_reference: impl Fn(usize) -> R,
        build_dpdk: impl Fn(usize) -> D,
    ) {
        let mut group = c.benchmark_group(name);
        for n in RULE_COUNTS {
            group.throughput(Throughput::Elements(u64::try_from(n).unwrap_or(0)));
            group.bench_function(BenchmarkId::new("reference", n), |b| {
                b.iter_batched(
                    || (),
                    |()| black_box(build_reference(n)),
                    BatchSize::PerIteration,
                );
            });
            group.bench_function(BenchmarkId::new("dpdk", n), |b| {
                b.iter_batched(
                    || (),
                    |()| black_box(build_dpdk(n)),
                    BatchSize::PerIteration,
                );
            });
        }
        group.finish();
    }

    pub fn benches(c: &mut Criterion) {
        let _eal = dpdk::test_support::start_eal();
        bench_build_group(c, "table_build_v4", build_reference_v4, build_dpdk_v4);
        bench_build_group(c, "table_build_v6", build_reference_v6, build_dpdk_v6);
    }
}

#[cfg(feature = "dpdk")]
criterion::criterion_group!(benchmarks, bench::benches);
#[cfg(feature = "dpdk")]
criterion::criterion_main!(benchmarks);
#[cfg(not(feature = "dpdk"))]
fn main() {}
