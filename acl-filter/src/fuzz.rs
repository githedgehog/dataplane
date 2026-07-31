// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for the ACL context build and lookup over generated overlays.
//!
//! The oracle here answers an ACL lookup *directly from the validated config*: it walks the
//! peering's own rule list in order, matching each rule's pattern by address/port containment and
//! direct protocol semantics. It never sees the cross-product expansion of a rule's source and
//! destination prefix sets, the positional priority encoding, the per-IP-version table split, or
//! any classifier. Backend-differential tests cannot find a bug in any of those (both backends
//! consume the same lowered rules); this oracle can, which is what makes it worth the duplication.

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

/// What the config says about one packet: the matching rule's outcome, or `None` if no rule
/// matched. Mirrors the fields of the table's own `LookupResult` without sharing its construction.
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

/// Direct semantics of a rule's protocol constraint (the tables encode this as a masked key byte).
fn proto_allows(rule: AclProtoMatch, packet: NextHeader) -> bool {
    match rule {
        AclProtoMatch::Any => true,
        AclProtoMatch::Tcp => packet == NextHeader::TCP,
        AclProtoMatch::Udp => packet == NextHeader::UDP,
        AclProtoMatch::Other(p) => packet == NextHeader::new(p),
    }
}

/// Direct semantics of one pattern entry: address containment plus port-range containment (`None`
/// ports = wildcard). `port` is the lowered value: 0 when the packet carries no ports, which only a
/// wildcard can match since config forbids port 0 in a rule's ranges.
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

/// Whether one side of a pattern matches. A validated pattern's set is never empty (validation
/// substitutes the manifest's coverage for an empty one), and the set is a union: any entry
/// matching is enough. This is the claim the N x M rule expansion in the lowering has to preserve.
fn side_allows(set: &PrefixPortsSet, ip: IpAddr, port: u16) -> bool {
    set.iter().any(|entry| entry_allows(entry, ip, port))
}

fn rule_matches(rule: &ValidatedAclRule, packet: &PacketSummary) -> bool {
    let pattern = rule.pattern();
    let (sport, dport) = packet.ports.unwrap_or((0, 0));
    proto_allows(pattern.proto(), packet.proto)
        && side_allows(pattern.src(), packet.src_ip, sport)
        && side_allows(pattern.dst(), packet.dst_ip, dport)
}

/// The peering that carries traffic from `src_vni` to `dst_vni`, viewed from the source VPC (so its
/// `local()` manifest is the source side and its rules' `from` field selects the direction).
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

/// Answer an ACL lookup directly from the validated overlay: the first rule of the peering that
/// applies in the packet's direction and whose pattern matches.
///
/// Rules from different peerings, and from the two directions of one peering, can never compete:
/// the source and destination VNIs are exact key fields. So the oracle resolves the peering first
/// and then scans that one list in order -- no global ordering, no priorities.
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

/// The default action the config assigns to a directed VPC pair: the peering's, if it has an ACL.
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

/// The action a packet ultimately receives: its matching rule's, else the peering default, else
/// allow (an unconfigured peering permits everything).
fn resolved_action(rule: Option<OracleVerdict>, default: Option<AclAction>) -> AclAction {
    rule.map_or_else(|| default.unwrap_or(AclAction::Allow), |v| v.action)
}

// -------------------------------------------------------------------------------------------------
// Properties.

/// Coverage counters, so a time-boxed run that never reached the interesting outcomes fails rather
/// than passing vacuously (the pattern the acl property suites use). Lazily initialized so this
/// compiles under the loom backend, whose `AtomicU64::new` is not const.
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

    /// `has_default` distinguishes the two no-rule outcomes: falling through to a peering's default
    /// action, versus finding no default at all (an unpeered pair, or a peering with no ACL), which
    /// is the path that ends in the NF's implicit allow.
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

/// The lowered tables agree with the config-semantics oracle on every probe of every generated
/// overlay. This is the test that can catch a rule-lowering bug: a mis-expanded source/destination
/// cross product, a rule attributed to the wrong direction or the wrong VNI pair, a lost `log` or
/// `scope`, or an ordering inversion in the positional priority encoding.
#[test]
fn reference_lookup_matches_config_oracle() {
    static COVERAGE: Coverage = Coverage::new();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("reference backend build is infallible");

            for probe_spec in probe_specs {
                let probe = probe_spec.resolve(&built);
                let want = oracle_lookup(&built.overlay, &probe);
                let got = tables.lookup(&probe).map(OracleVerdict::from);
                assert_eq!(
                    got, want,
                    "tables disagree with the config oracle on {probe:?}\nspec: {overlay_spec:?}",
                );

                // The default action is a second, separate lowering (a map keyed on the directed
                // VNI pair, consulted only on a rule miss), so it gets its own comparison.
                let want_default =
                    oracle_default_action(&built.overlay, probe.src_vni, probe.dst_vni);
                let got_default = tables.find_default_action(probe.src_vni, probe.dst_vni);
                assert_eq!(
                    got_default, want_default,
                    "default action disagrees for {} -> {}\nspec: {overlay_spec:?}",
                    probe.src_vni, probe.dst_vni,
                );

                // And the verdict the two compose into, which is what the NF acts on.
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

/// Rule order is precedence: an earlier rule always beats a later one that also matches. Asserted
/// against the config directly -- every rule that matches the packet is collected, and the table's
/// verdict must be the first of them.
///
/// Worth stating separately from the oracle comparison: the oracle expresses precedence with a
/// `find`, so a shared misunderstanding of it would satisfy both. Here the claim is spelled out
/// over the whole matching set rather than assumed by construction.
///
/// Note what this does *not* cover. The reference backend is first-match over the rule list, so it
/// never consults a priority; the positional encoding (`priority = n - i` in `build_table`) that
/// reproduces this order under rte_acl is pinned by the differential test below, which is the only
/// test here that fails if that encoding is inverted.
#[test]
fn earlier_rules_win_over_later_matching_rules() {
    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("reference backend build is infallible");

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

/// The rte_acl backend agrees with the reference backend on every probe of every generated overlay.
/// This is the fuzz form of `tests::dpdk_backend::dpdk_agrees_with_reference`: it validates the
/// wide-key encoding, the mask-protocol and range-port fields, and the positional priority mapping
/// against real rte_acl under configs nobody hand-picked.
#[test]
#[dpdk::with_eal]
fn dpdk_backend_matches_reference_on_generated_overlays() {
    static COVERAGE: Coverage = Coverage::new();

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let reference = AclTables::build(&built.overlay, Backend::Reference)
                .expect("reference backend build is infallible");
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

/// A peering with no ACL configured allows everything, and a VPC pair with no peering has no
/// default at all. Both are the "absence" paths, which the generated overlays reach only
/// incidentally; pinning them here keeps the fallback in `AclFilter::lookup` honest.
#[test]
fn absent_acl_and_absent_peering_have_no_default_action() {
    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 4])>()
        .for_each(|(overlay_spec, probe_specs)| {
            let built = overlay_spec.build();
            let tables = AclTables::build(&built.overlay, Backend::Reference)
                .expect("reference backend build is infallible");

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

/// A generated overlay's VNIs are the ones the generator promises. Cheap, but it is what licenses
/// every "unpeered pair" assertion above: if the VPC table drifted, probes drawing the bogus VNI
/// would silently start hitting a real VPC.
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
