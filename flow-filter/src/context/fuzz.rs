// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for the routing-context build and lookup over generated overlays.
//!
//! The oracle here answers a route lookup *directly from the validated config* -- LPM by hand
//! over the expose prefixes, direct protocol/port semantics -- without going through rule
//! lowering, `FieldPredicate` encoding, priorities, or any classifier. Backend-differential
//! tests cannot see a bug in `RuleSet::from_overlay` (both backends consume the same lowered
//! rules); this oracle can, which is what makes it worth the duplication.

#![cfg(test)]

use super::tables::{Backend, LookupInput, LookupResult, PeeringTables};
use crate::NatRequirement;
use crate::fuzz_gen::{OverlaySpec, Probe, ProbeSpec, bogus_vpcd};
use concurrency::sync::LazyLock;
use concurrency::sync::atomic::{AtomicU64, Ordering};
use config::external::overlay::ValidatedOverlay;
use lpm::prefix::{IpPrefix, L4Protocol, Prefix, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::net::IpAddr;

// -------------------------------------------------------------------------------------------------
// The config-semantics oracle.

/// Direct semantics of an expose's L4 protocol constraint (the tables encode this as a masked
/// key byte; the equivalence of that encoding is property-tested separately in `tables.rs`).
fn proto_allows(rule: Option<L4Protocol>, packet: NextHeader) -> bool {
    match rule.unwrap_or(L4Protocol::Any) {
        L4Protocol::Any => true,
        L4Protocol::Tcp => packet == NextHeader::TCP,
        L4Protocol::Udp => packet == NextHeader::UDP,
    }
}

/// Direct semantics of one expose prefix: address containment plus port-range containment
/// (`None` ports = wildcard). `port` is the lowered value: 0 when the packet has no ports, which
/// only a wildcard can match since config forbids port 0 in expose ranges.
fn prefix_allows(prefix: &PrefixWithOptionalPorts, ip: IpAddr, port: u16) -> bool {
    let covers = match (prefix.prefix(), ip) {
        (Prefix::IPV4(p), IpAddr::V4(a)) => p.covers_addr(&a),
        (Prefix::IPV6(p), IpAddr::V6(a)) => p.covers_addr(&a),
        _ => false,
    };
    covers
        && prefix
            .ports()
            .is_none_or(|r| r.start() <= port && port <= r.end())
}

/// Rule precedence, in structural form: longest prefix first, port forwarding breaking
/// equal-length ties. Mirrors `rule_priority` without sharing its encoding.
type Precedence = (u8, bool);

/// Keep the strictly-better candidate; equal precedence between candidates that can match the
/// same packet is a generator invariant violation, so fail loudly rather than pick one.
fn consider<T>(best: &mut Option<(Precedence, T)>, precedence: Precedence, value: T) {
    match best {
        Some((current, _)) if *current == precedence => {
            panic!("ambiguous match at precedence {precedence:?}: generator invariant violated")
        }
        Some((current, _)) if *current > precedence => {}
        _ => *best = Some((precedence, value)),
    }
}

/// Answer a route lookup directly from the validated overlay.
fn oracle_lookup(overlay: &ValidatedOverlay, probe: &Probe) -> LookupResult {
    let Some(src_vpc) = overlay
        .vpc_table()
        .values()
        .find(|vpc| VpcDiscriminant::from_vni(vpc.vni()) == probe.src_vpcd)
    else {
        return LookupResult::DestinationMiss;
    };
    if probe.src_ip.is_ipv4() != probe.dst_ip.is_ipv4() {
        return LookupResult::DestinationMiss;
    }
    let (sport, dport) = probe.ports.unwrap_or((0, 0));

    // Stage 1: the destination against every peer's public prefixes. Masquerade exposes are
    // included (marker rules); a default expose acts as a /0 of the peering's IP version.
    let mut verdict: Option<(Precedence, (VpcDiscriminant, Option<NatRequirement>))> = None;
    for peering in src_vpc.peerings() {
        let dst_vpcd = VpcDiscriminant::from_vni(peering.remote_vni());
        for expose in peering.remote().valexp() {
            if !proto_allows(expose.nat_proto(), probe.proto) {
                continue;
            }
            for prefix in expose.public_ips() {
                if prefix_allows(prefix, probe.dst_ip, dport) {
                    consider(
                        &mut verdict,
                        (prefix.prefix().length(), expose.has_port_forwarding()),
                        (dst_vpcd, NatRequirement::from_expose(expose)),
                    );
                }
            }
        }
        if peering.remote().has_default_expose() && probe.dst_ip.is_ipv4() == peering.is_v4() {
            consider(&mut verdict, (0, false), (dst_vpcd, None));
        }
    }
    let Some((_, (dst_vpcd, dst_nat))) = verdict else {
        return LookupResult::DestinationMiss;
    };

    // Stage 2: the source against that peering's private prefixes. Port-forwarding sources are
    // excluded (they cannot initiate); a default expose acts as a /0 of the peering's version.
    let peering = src_vpc
        .peerings()
        .iter()
        .find(|p| VpcDiscriminant::from_vni(p.remote_vni()) == dst_vpcd)
        .unwrap_or_else(|| unreachable!("stage 1 hit implies a peering to the verdict VPC"));
    let mut src_nat: Option<(Precedence, Option<NatRequirement>)> = None;
    for expose in peering
        .local()
        .valexp()
        .iter()
        .filter(|expose| expose.can_init_connection())
    {
        if !proto_allows(expose.nat_proto(), probe.proto) {
            continue;
        }
        for prefix in expose.ips() {
            if prefix_allows(prefix, probe.src_ip, sport) {
                consider(
                    &mut src_nat,
                    (prefix.prefix().length(), false),
                    NatRequirement::from_expose(expose),
                );
            }
        }
    }
    if peering.local().has_default_expose() && probe.src_ip.is_ipv4() == peering.is_v4() {
        consider(&mut src_nat, (0, false), None);
    }
    match src_nat {
        Some((_, src_nat)) => LookupResult::Route((dst_vpcd, dst_nat, src_nat)),
        None => LookupResult::SourceMiss(dst_vpcd),
    }
}

// -------------------------------------------------------------------------------------------------
// Properties.

/// The rte_acl backend agrees with the reference backend on every probe of every generated
/// overlay -- single lookups and the chunked batch path alike. This is the fuzz form of
/// `tests::reference_and_dpdk_backends_agree`: it validates the wide-key encoding and the
/// priority mapping against real rte_acl under configs nobody hand-picked.
///
/// Coverage is asserted, not assumed (the acl property suites' pattern): the counters fail the
/// test if the time-boxed run never exercised full routes, source misses, or destination misses.
#[test]
#[dpdk::with_eal]
fn dpdk_backend_matches_reference_on_generated_overlays() {
    // Lazily initialized so this compiles under the loom backend, whose AtomicU64::new is not
    // const (each instance registers with the loom executor).
    static ROUTES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
    static SOURCE_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
    static DESTINATION_MISSES: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 40])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let reference =
                PeeringTables::build(&built.overlay, Backend::Reference).expect("reference build");
            let dpdk = PeeringTables::build(&built.overlay, Backend::Dpdk).expect("dpdk build");

            let probes: Vec<Probe> = probe_specs
                .iter()
                .map(|p| p.resolve(built.blocks))
                .collect();
            let inputs: Vec<LookupInput> = probes
                .iter()
                .map(|p| LookupInput {
                    src_vpcd: p.src_vpcd,
                    src_ip: p.src_ip,
                    dst_ip: p.dst_ip,
                    proto: p.proto,
                    ports: p.ports,
                })
                .collect();

            let mut expected = Vec::with_capacity(probes.len());
            for probe in &probes {
                let want = reference.lookup(
                    probe.src_vpcd,
                    probe.src_ip,
                    probe.dst_ip,
                    probe.proto,
                    probe.ports,
                );
                assert_eq!(
                    dpdk.lookup(
                        probe.src_vpcd,
                        probe.src_ip,
                        probe.dst_ip,
                        probe.proto,
                        probe.ports
                    ),
                    want,
                    "backends disagree on single lookup of {probe:?}\nspec: {overlay_spec:?}",
                );
                match want {
                    LookupResult::Route(_) => ROUTES.fetch_add(1, Ordering::Relaxed),
                    LookupResult::SourceMiss(_) => SOURCE_MISSES.fetch_add(1, Ordering::Relaxed),
                    LookupResult::DestinationMiss => {
                        DESTINATION_MISSES.fetch_add(1, Ordering::Relaxed)
                    }
                };
                expected.push(want);
            }

            // Batch path: 40 inputs > MAX_BATCH exercises the chunked scatter; every slot must
            // equal the corresponding single lookup.
            let mut out = vec![LookupResult::DestinationMiss; inputs.len()];
            dpdk.lookup_batch(&inputs, &mut out);
            assert_eq!(
                out, expected,
                "dpdk batch != single\nspec: {overlay_spec:?}"
            );

            // All-miss batch: an unknown source VPC misses stage 1 for every input, so stage 2
            // runs on an empty key set -- rte_acl classify with zero buffers must be harmless.
            // 33 inputs of one version make the first chunk a full MAX_BATCH.
            let all_miss: Vec<LookupInput> = (0..33u8)
                .map(|i| LookupInput {
                    src_vpcd: bogus_vpcd(),
                    src_ip: format!("10.0.0.{i}").parse().unwrap(),
                    dst_ip: "10.0.0.99".parse().unwrap(),
                    proto: NextHeader::TCP,
                    ports: Some((1, 2)),
                })
                .collect();
            let mut out = vec![LookupResult::DestinationMiss; all_miss.len()];
            dpdk.lookup_batch(&all_miss, &mut out);
            assert!(
                out.iter().all(|r| *r == LookupResult::DestinationMiss),
                "unknown source VPC must miss stage 1 for every input",
            );
        });

    eprintln!(
        "coverage: {} routes, {} source misses, {} destination misses",
        ROUTES.load(Ordering::Relaxed),
        SOURCE_MISSES.load(Ordering::Relaxed),
        DESTINATION_MISSES.load(Ordering::Relaxed),
    );
    assert!(ROUTES.load(Ordering::Relaxed) >= 20, "too few full routes");
    assert!(
        SOURCE_MISSES.load(Ordering::Relaxed) >= 20,
        "too few source misses"
    );
    assert!(
        DESTINATION_MISSES.load(Ordering::Relaxed) >= 100,
        "too few destination misses"
    );
}

/// The reference backend agrees with the config-semantics oracle on every probe, for every
/// generated overlay. This is the test that can catch rule-lowering bugs.
#[test]
fn reference_lookup_matches_config_oracle() {
    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables =
                PeeringTables::build(&built.overlay, Backend::Reference).expect("reference build");
            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(built.blocks);
                assert_eq!(
                    tables.lookup(
                        probe.src_vpcd,
                        probe.src_ip,
                        probe.dst_ip,
                        probe.proto,
                        probe.ports
                    ),
                    oracle_lookup(&built.overlay, &probe),
                    "reference tables disagree with the config oracle on {probe:?}\nspec: {overlay_spec:?}",
                );
            }
        });
}
