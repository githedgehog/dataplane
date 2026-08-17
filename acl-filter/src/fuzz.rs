// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for ACL lowering and lookup.
//!
//! The oracle evaluates the validated config directly, without using lowered rules or a
//! classifier. This keeps lowering mistakes independent from the expected result.

#![cfg(test)]

use crate::PacketSummary;
use crate::context::{AclTables, Backend, LookupResult};
use crate::fuzz_gen::{OverlaySpec, ProbeSpec, vni};
use concurrency::sync::LazyLock;
use concurrency::sync::atomic::{AtomicU64, Ordering};
use config::external::overlay::ValidatedOverlay;
use config::external::overlay::acl::{AclAction, AclProtoMatch, AclScope, ValidatedAclRule};
use config::external::overlay::vpc::ValidatedPeering;
use lpm::prefix::{IpPrefix, Prefix, PrefixPortsSet, PrefixWithOptionalPorts};
use net::ip::NextHeader;
use net::vxlan::Vni;
use std::net::IpAddr;

// -------------------------------------------------------------------------------------------------
// The config-semantics oracle.

/// The outcome of the first matching config rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OracleVerdict {
    action: AclAction,
    log: bool,
    scope: AclScope,
}

impl From<&LookupResult> for OracleVerdict {
    fn from(result: &LookupResult) -> Self {
        Self {
            action: result.action,
            log: result.log,
            scope: result.scope,
        }
    }
}

fn proto_allows(rule: AclProtoMatch, packet: NextHeader) -> bool {
    match rule {
        AclProtoMatch::Any => true,
        AclProtoMatch::Tcp => packet == NextHeader::TCP,
        AclProtoMatch::Udp => packet == NextHeader::UDP,
        AclProtoMatch::Other(p) => packet == NextHeader::new(p),
    }
}

fn entry_allows(entry: &PrefixWithOptionalPorts, ip: IpAddr, port: u16) -> bool {
    let covers = match (entry.prefix(), ip) {
        (Prefix::IPV4(p), IpAddr::V4(a)) => p.covers_addr(&a),
        (Prefix::IPV6(p), IpAddr::V6(a)) => p.covers_addr(&a),
        _ => false,
    };
    covers
        && entry
            .ports()
            .is_none_or(|r| r.start() <= port && port <= r.end())
}

fn side_allows(set: &PrefixPortsSet, ip: IpAddr, port: u16) -> bool {
    set.iter().any(|entry| entry_allows(entry, ip, port))
}

fn rule_matches(rule: &ValidatedAclRule, packet: &PacketSummary) -> bool {
    // Match `AclTables::lookup`: cross-version packets consult neither table.
    if packet.src_ip.is_ipv4() != packet.dst_ip.is_ipv4() {
        return false;
    }
    let pattern = rule.pattern();
    let (sport, dport) = packet.ports.unwrap_or((0, 0));
    proto_allows(pattern.proto(), packet.proto)
        && side_allows(pattern.src(), packet.src_ip, sport)
        && side_allows(pattern.dst(), packet.dst_ip, dport)
}

/// Find a peering in the packet's direction.
fn directed_peering(
    overlay: &ValidatedOverlay,
    src_vni: Vni,
    dst_vni: Vni,
) -> Option<&ValidatedPeering> {
    overlay
        .vpc_table()
        .values()
        .find(|vpc| vpc.vni() == src_vni)?
        .peerings()
        .iter()
        .find(|peering| peering.remote_vni() == dst_vni)
}

/// Return the first matching rule from the directed peering.
/// Exact VNI fields prevent rules from other peerings or directions from competing.
fn oracle_lookup(overlay: &ValidatedOverlay, packet: &PacketSummary) -> Option<OracleVerdict> {
    let peering = directed_peering(overlay, packet.src_vni, packet.dst_vni)?;
    let acl = peering.acl().as_ref()?;
    acl.rules()
        .iter()
        .filter(|rule| rule.from() == peering.local().name())
        .find(|rule| rule_matches(rule, packet))
        .map(|rule| OracleVerdict {
            action: rule.action(),
            log: rule.log(),
            scope: rule.scope(),
        })
}

fn oracle_default_action(
    overlay: &ValidatedOverlay,
    src_vni: Vni,
    dst_vni: Vni,
) -> Option<AclAction> {
    Some(
        directed_peering(overlay, src_vni, dst_vni)?
            .acl()
            .as_ref()?
            .default_action(),
    )
}

fn resolved_action(rule: Option<OracleVerdict>, default: Option<AclAction>) -> AclAction {
    rule.map_or_else(|| default.unwrap_or(AclAction::Allow), |v| v.action)
}

pub(crate) fn oracle_resolved_action(
    overlay: &ValidatedOverlay,
    packet: &PacketSummary,
) -> AclAction {
    resolved_action(
        oracle_lookup(overlay, packet),
        oracle_default_action(overlay, packet.src_vni, packet.dst_vni),
    )
}

// -------------------------------------------------------------------------------------------------
// Properties.

/// Ensure short property-test runs exercise each outcome.
struct Coverage {
    rule_allows: LazyLock<AtomicU64>,
    rule_denies: LazyLock<AtomicU64>,
    default_falls: LazyLock<AtomicU64>,
    unconfigured: LazyLock<AtomicU64>,
}

impl Coverage {
    const fn new() -> Self {
        Self {
            rule_allows: LazyLock::new(|| AtomicU64::new(0)),
            rule_denies: LazyLock::new(|| AtomicU64::new(0)),
            default_falls: LazyLock::new(|| AtomicU64::new(0)),
            unconfigured: LazyLock::new(|| AtomicU64::new(0)),
        }
    }

    fn record(&self, verdict: Option<OracleVerdict>, has_default: bool) {
        let counter = match (verdict, has_default) {
            (Some(v), _) if v.action == AclAction::Allow => &self.rule_allows,
            (Some(_), _) => &self.rule_denies,
            (None, true) => &self.default_falls,
            (None, false) => &self.unconfigured,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn assert_reached(&self, label: &str) {
        let (allows, denies) = (
            self.rule_allows.load(Ordering::Relaxed),
            self.rule_denies.load(Ordering::Relaxed),
        );
        let (defaults, unconfigured) = (
            self.default_falls.load(Ordering::Relaxed),
            self.unconfigured.load(Ordering::Relaxed),
        );
        eprintln!(
            "{label} coverage: {allows} rule allows, {denies} rule denies, \
             {defaults} default fallbacks, {unconfigured} unconfigured pairs"
        );
        assert!(allows >= 1, "{label}: no rule ever allowed a packet");
        assert!(denies >= 1, "{label}: no rule ever denied a packet");
        assert!(defaults >= 1, "{label}: never fell through to a default");
        assert!(
            unconfigured >= 1,
            "{label}: never probed a pair with no ACL at all"
        );
    }
}

/// Lowered reference tables must match the validated config.
#[test]
fn reference_lookup_matches_config_oracle() {
    static COVERAGE: Coverage = Coverage::new();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("validated overlay must lower");

            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(&built);
                let want = oracle_lookup(&built.overlay, &probe);
                let got = tables.lookup(&probe).map(OracleVerdict::from);
                assert_eq!(
                    got, want,
                    "tables disagree with the config oracle on {probe:?}\nspec: {overlay_spec:?}",
                );

                // Defaults are lowered separately from rules, so compare them separately.
                let want_default =
                    oracle_default_action(&built.overlay, probe.src_vni, probe.dst_vni);
                let got_default = tables.find_default_action(probe.src_vni, probe.dst_vni);
                assert_eq!(
                    got_default, want_default,
                    "default action disagrees for {} -> {}\nspec: {overlay_spec:?}",
                    probe.src_vni, probe.dst_vni,
                );

                assert_eq!(
                    resolved_action(got, got_default),
                    resolved_action(want, want_default),
                    "resolved action disagrees on {probe:?}\nspec: {overlay_spec:?}",
                );

                COVERAGE.record(want, want_default.is_some());
            }
        });

    COVERAGE.assert_reached("reference vs oracle");
}

/// Earlier matching rules must take precedence.
/// The DPDK differential test covers the priority encoding; the reference backend is first-match.
#[test]
fn earlier_rules_win_over_later_matching_rules() {
    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("validated overlay must lower");

            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(&built);
                let Some(peering) = directed_peering(&built.overlay, probe.src_vni, probe.dst_vni)
                else {
                    continue;
                };
                let Some(acl) = peering.acl().as_ref() else {
                    continue;
                };

                let matching: Vec<&ValidatedAclRule> = acl
                    .rules()
                    .iter()
                    .filter(|rule| rule.from() == peering.local().name())
                    .filter(|rule| rule_matches(rule, &probe))
                    .collect();

                let got = tables.lookup(&probe).map(OracleVerdict::from);
                match matching.first() {
                    Some(first) => assert_eq!(
                        got,
                        Some(OracleVerdict {
                            action: first.action(),
                            log: first.log(),
                            scope: first.scope(),
                        }),
                        "a later rule beat the first of {} matching rules on {probe:?}\n\
                         spec: {overlay_spec:?}",
                        matching.len(),
                    ),
                    None => assert_eq!(
                        got, None,
                        "table matched a rule the config says cannot match {probe:?}\n\
                         spec: {overlay_spec:?}",
                    ),
                }
            }
        });
}

/// Generated cases must behave identically under rte_acl and the reference backend.
#[test]
#[dpdk::with_eal]
fn dpdk_backend_matches_reference_on_generated_overlays() {
    static COVERAGE: Coverage = Coverage::new();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let reference = AclTables::build(&built.overlay, Backend::Reference)
                .expect("validated overlay must lower");
            let dpdk =
                AclTables::build(&built.overlay, Backend::Dpdk).expect("rte_acl backend build");

            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(&built);
                let want = reference.lookup(&probe).map(OracleVerdict::from);
                assert_eq!(
                    dpdk.lookup(&probe).map(OracleVerdict::from),
                    want,
                    "backends disagree on {probe:?}\nspec: {overlay_spec:?}",
                );

                let want_default = reference.find_default_action(probe.src_vni, probe.dst_vni);
                assert_eq!(
                    dpdk.find_default_action(probe.src_vni, probe.dst_vni),
                    want_default,
                    "backends disagree on the default action for {} -> {}\nspec: {overlay_spec:?}",
                    probe.src_vni,
                    probe.dst_vni,
                );

                COVERAGE.record(want, want_default.is_some());
            }
        });

    COVERAGE.assert_reached("dpdk vs reference");
}

/// A default exists exactly when the directed peering has an ACL.
#[test]
fn absent_acl_and_absent_peering_have_no_default_action() {
    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 4])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("validated overlay must lower");

            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(&built);
                let peering = directed_peering(&built.overlay, probe.src_vni, probe.dst_vni);
                let configured = peering.is_some_and(|p| p.acl().is_some());
                assert_eq!(
                    tables
                        .find_default_action(probe.src_vni, probe.dst_vni)
                        .is_some(),
                    configured,
                    "a default action exists exactly when the pair is peered and has an ACL: \
                     {} -> {}\nspec: {overlay_spec:?}",
                    probe.src_vni,
                    probe.dst_vni,
                );
                if !configured {
                    assert_eq!(
                        tables.lookup(&probe).map(OracleVerdict::from),
                        None,
                        "an unconfigured pair must match no rule: {probe:?}\n\
                         spec: {overlay_spec:?}",
                    );
                }
            }
        });
}

/// Keep the bogus probe VNI distinct from generated VPCs.
#[test]
fn generated_overlays_use_the_declared_vnis() {
    use crate::fuzz_gen::VNIS;

    bolero::check!()
        .with_type::<OverlaySpec>()
        .for_each(|overlay_spec| {
            let built = overlay_spec.build();
            let vnis: Vec<Vni> = built
                .overlay
                .vpc_table()
                .values()
                .map(|vpc| vpc.vni())
                .collect();
            assert_eq!(
                vnis,
                VNIS.iter().copied().map(vni).collect::<Vec<_>>(),
                "generated VPC table drifted from the declared VNIs",
            );
        });
}
