// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(feature = "dpdk")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use concurrency::sync::LazyLock;
use concurrency::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::net::{Ipv4Addr, Ipv6Addr};
use core::num::NonZero;
use core::ops::Bound;

use arrayvec::ArrayVec;
use bolero::generator::bolero_generator::driver::{ByteSliceDriver, Options};
use bolero::{Driver, TypeGenerator, ValueGenerator};
use dataplane_acl::dpdk::install::install_table;
use dataplane_acl::dpdk::rule::{Dpdk, RuleSpec};
use dataplane_acl::dpdk_table_alias;
use dataplane_acl::reference::{Erased, RefRule, ReferenceTable};
use dpdk::acl::{CategoryMask, Priority};
use lookup::Lookup;
use match_action::{
    ExactSpec, FieldHit, FieldMiss, FixedSize, IsUniversal, MaskSpec, MatchKey, PrefixSpec,
    RangeSpec,
};

mod sealed {
    use core::net::{Ipv4Addr, Ipv6Addr};
    pub trait Sealed {}
    impl Sealed for Ipv4Addr {}
    impl Sealed for Ipv6Addr {}
}
pub trait IpAddress:
    FixedSize + sealed::Sealed + TypeGenerator + Copy + core::fmt::Debug + 'static + Send + Sync
{
    const BITS: u8;
}

impl IpAddress for Ipv4Addr {
    const BITS: u8 = 32;
}

impl IpAddress for Ipv6Addr {
    const BITS: u8 = 128;
}

#[derive(MatchKey, Debug, Clone, Copy)]
struct FiveTuple<A: IpAddress> {
    #[exact]
    proto: u8,
    // A masked byte alongside the exact one: the flow-filter's keys rely on #[mask] for
    // protocol wildcarding, so the predicate fuzz must cover that field kind too.
    #[mask]
    tos: u8,
    #[prefix]
    src: A,
    #[prefix]
    dst: A,
    #[range]
    sport: u16,
    #[range]
    dport: u16,
}

dpdk_table_alias!(type FiveTupleTableV4<A> = FiveTuple<Ipv4Addr>);
dpdk_table_alias!(type FiveTupleTableV6<A> = FiveTuple<Ipv6Addr>);

#[derive(Debug, Clone, Copy, TypeGenerator)]
struct RawRule<A> {
    proto: u8,
    tos_value: u8,
    tos_mask: u8,
    src: A,
    src_len: u8,
    dst: A,
    dst_len: u8,
    sport_a: u16,
    sport_b: u16,
    dport_a: u16,
    dport_b: u16,
}

fn minmax<T: Ord>(a: T, b: T) -> (T, T) {
    if a <= b { (a, b) } else { (b, a) }
}

fn build_rule<A: IpAddress>(raw: &RawRule<A>) -> FiveTupleRule<A> {
    let (sport_lo, sport_hi) = minmax(raw.sport_a, raw.sport_b);
    let (dport_lo, dport_hi) = minmax(raw.dport_a, raw.dport_b);
    let bits = u16::from(A::BITS) + 1;
    let src_len = u8::try_from(u16::from(raw.src_len) % bits).unwrap_or(A::BITS);
    let dst_len = u8::try_from(u16::from(raw.dst_len) % bits).unwrap_or(A::BITS);
    FiveTupleRule {
        proto: ExactSpec::new(raw.proto),
        tos: MaskSpec::new(raw.tos_value, raw.tos_mask),
        src: PrefixSpec::new(raw.src, src_len),
        dst: PrefixSpec::new(raw.dst, dst_len),
        sport: RangeSpec::new(sport_lo, sport_hi),
        dport: RangeSpec::new(dport_lo, dport_hi),
    }
}

struct HitsGen<A: IpAddress> {
    rule: FiveTupleRule<A>,
}

impl<A: IpAddress> ValueGenerator for HitsGen<A>
where
    PrefixSpec<A>: FieldHit<A>,
{
    type Output = FiveTuple<A>;
    fn generate<D: Driver>(&self, d: &mut D) -> Option<FiveTuple<A>> {
        let r = &self.rule;
        Some(FiveTuple {
            proto: FieldHit::hits(&r.proto).generate(d)?,
            tos: FieldHit::hits(&r.tos).generate(d)?,
            src: FieldHit::hits(&r.src).generate(d)?,
            dst: FieldHit::hits(&r.dst).generate(d)?,
            sport: FieldHit::hits(&r.sport).generate(d)?,
            dport: FieldHit::hits(&r.dport).generate(d)?,
        })
    }
}

struct MissesGen<A: IpAddress> {
    rule: FiveTupleRule<A>,
}

impl<A: IpAddress> ValueGenerator for MissesGen<A>
where
    PrefixSpec<A>: FieldHit<A> + FieldMiss<A> + IsUniversal,
{
    type Output = FiveTuple<A>;
    fn generate<D: Driver>(&self, d: &mut D) -> Option<FiveTuple<A>> {
        let r = &self.rule;
        let mut nu: ArrayVec<u8, 6> = ArrayVec::new();
        if !r.proto.is_universal() {
            nu.push(0);
        }
        if !r.tos.is_universal() {
            nu.push(5);
        }
        if !r.src.is_universal() {
            nu.push(1);
        }
        if !r.dst.is_universal() {
            nu.push(2);
        }
        if !r.sport.is_universal() {
            nu.push(3);
        }
        if !r.dport.is_universal() {
            nu.push(4);
        }
        if nu.is_empty() {
            return None;
        }
        let pick: u8 = d.gen_u8(Bound::Unbounded, Bound::Unbounded)?;
        let target = nu[(pick as usize) % nu.len()];
        Some(FiveTuple {
            proto: if target == 0 {
                FieldMiss::misses(&r.proto).generate(d)?
            } else {
                FieldHit::hits(&r.proto).generate(d)?
            },
            tos: if target == 5 {
                FieldMiss::misses(&r.tos).generate(d)?
            } else {
                FieldHit::hits(&r.tos).generate(d)?
            },
            src: if target == 1 {
                FieldMiss::misses(&r.src).generate(d)?
            } else {
                FieldHit::hits(&r.src).generate(d)?
            },
            dst: if target == 2 {
                FieldMiss::misses(&r.dst).generate(d)?
            } else {
                FieldHit::hits(&r.dst).generate(d)?
            },
            sport: if target == 3 {
                FieldMiss::misses(&r.sport).generate(d)?
            } else {
                FieldHit::hits(&r.sport).generate(d)?
            },
            dport: if target == 4 {
                FieldMiss::misses(&r.dport).generate(d)?
            } else {
                FieldHit::hits(&r.dport).generate(d)?
            },
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Verdict {
    Drop,
}

// Lazily initialized so this compiles under the loom backend, whose AtomicU32::new is not const
static CTX_SEQ: LazyLock<AtomicU32> = LazyLock::new(|| AtomicU32::new(0));

fn unique_name(prefix: &str) -> String {
    format!("{prefix}_{}", CTX_SEQ.fetch_add(1, Ordering::Relaxed))
}
const INNER_DRAWS: usize = 32;

fn sweep<G, F>(g: &G, bytes: &[u8], pred: F) -> u64
where
    G: ValueGenerator,
    F: Fn(&G::Output),
{
    let opts = Options::default()
        .with_max_len(bytes.len())
        .with_max_depth(64);
    let mut driver = ByteSliceDriver::new(bytes, &opts);
    let mut count = 0;
    for _ in 0..INNER_DRAWS {
        if driver.as_slice().is_empty() {
            break;
        }
        if let Some(v) = g.generate(&mut driver) {
            pred(&v);
            count += 1;
        }
    }
    count
}
const MIN_ASSERTED_HITS: u64 = 200;
const MIN_ASSERTED_MISSES: u64 = 200;
fn run_property<A, T>(
    name_prefix: &str,
    install_dpdk: impl Fn(String, &FiveTupleRule<A>) -> T + core::panic::RefUnwindSafe,
) where
    A: IpAddress,
    PrefixSpec<A>: FieldHit<A> + FieldMiss<A> + IsUniversal,
    T: Lookup<FiveTuple<A>, Verdict>,
    RawRule<A>: TypeGenerator,
{
    let asserted_hits = AtomicU64::new(0);
    let asserted_misses = AtomicU64::new(0);

    bolero::check!()
        .with_type::<(RawRule<A>, Box<[u8]>, Box<[u8]>)>()
        .for_each(|(raw, hit_bytes, miss_bytes)| {
            let rule = build_rule(raw);
            let dpdk = install_dpdk(unique_name(name_prefix), &rule);
            let reference = ReferenceTable::<FiveTuple<A>, Verdict>::new(vec![RefRule::new(
                rule.into_backend_fields::<Erased>(),
                Verdict::Drop,
            )]);

            let hits = HitsGen { rule };
            let n_hits = sweep(&hits, hit_bytes, |k| {
                assert!(rule.accepts(k), "hits gen produced a rejected key: {k:?}");
                assert_eq!(reference.lookup(k), Some(&Verdict::Drop));
                assert_eq!(dpdk.lookup(k), Some(&Verdict::Drop));
            });
            asserted_hits.fetch_add(n_hits, Ordering::Relaxed);

            if !rule.is_universal() {
                let misses = MissesGen { rule };
                let n_misses = sweep(&misses, miss_bytes, |k| {
                    assert!(
                        !rule.accepts(k),
                        "misses gen produced an accepted key: {k:?}",
                    );
                    assert_eq!(reference.lookup(k), None);
                    assert_eq!(dpdk.lookup(k), None);
                });
                asserted_misses.fetch_add(n_misses, Ordering::Relaxed);
            }
        });

    let h = asserted_hits.load(Ordering::Relaxed);
    let m = asserted_misses.load(Ordering::Relaxed);
    assert!(
        h >= MIN_ASSERTED_HITS,
        "asserted only {h} hits (< {MIN_ASSERTED_HITS}); generator may have gone inert",
    );
    assert!(
        m >= MIN_ASSERTED_MISSES,
        "asserted only {m} misses (< {MIN_ASSERTED_MISSES}); generator may have gone inert",
    );
}

#[test]
#[ignore = "flaky"] // FIXME
#[dpdk::with_eal]
fn property_v4() {
    run_property::<Ipv4Addr, FiveTupleTableV4<Verdict>>("prop_v4", |name, rule| {
        install_table(
            &name,
            NonZero::new(2).expect("nonzero"),
            vec![
                RuleSpec::<FiveTuple<Ipv4Addr>, Verdict>::new(
                    Priority::new(1).expect("nonzero priority"),
                    CategoryMask::new(1).expect("nonzero mask"),
                    rule.into_backend_fields::<Dpdk>(),
                    Verdict::Drop,
                )
                .expect("RuleSpec"),
            ],
        )
        .expect("install_table")
    });
}

#[test]
#[ignore = "flaky"] // FIXME
#[dpdk::with_eal]
fn property_v6() {
    run_property::<Ipv6Addr, FiveTupleTableV6<Verdict>>("prop_v6", |name, rule| {
        install_table(
            &name,
            NonZero::new(2).expect("nonzero"),
            vec![
                RuleSpec::<FiveTuple<Ipv6Addr>, Verdict>::new(
                    Priority::new(1).expect("nonzero priority"),
                    CategoryMask::new(1).expect("nonzero mask"),
                    rule.into_backend_fields::<Dpdk>(),
                    Verdict::Drop,
                )
                .expect("RuleSpec"),
            ],
        )
        .expect("install_table")
    });
}
