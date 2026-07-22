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

use super::tables::{Backend, LookupResult, PeeringTables};
use crate::NatRequirement;
use crate::fuzz_gen::{OverlaySpec, Probe, ProbeSpec};
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
