// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use lpm::prefix::with_ports::{L4Protocol, PrefixPortsSet};

use super::Overlay;
use super::acl::{Acl, AclAction, AclPattern, AclProtoMatch, AclRule, AclScope};
use super::algebra::Sequence;
use super::vpc::Vpc;
use super::vpcpeering::{
    VpcExpose, VpcExposeMasquerade, VpcExposeNat, VpcExposeNatConfig, VpcExposePortForwarding,
    VpcExposeStaticNat, VpcManifest, VpcPeering,
};

#[derive(Debug)]
enum Reach {
    Spans(&'static [&'static str]),
    Determined(&'static str),
    Derived(&'static str),
    Fixed(&'static str),
}

const REACH: &[(&str, Reach)] = &[
    (
        "Overlay.vpc_table",
        Reach::Determined("one vpc per `AddVpc`, in handle order"),
    ),
    (
        "Overlay.peering_table",
        Reach::Determined("one peering per `AddPeering`, in handle order"),
    ),
    ("Vpc.name", Reach::Determined("`VpcHandle::name`")),
    ("Vpc.id", Reach::Determined("`VpcHandle::id`")),
    ("Vpc.vni", Reach::Determined("`VpcHandle::vni`")),
    (
        "Vpc.interfaces",
        Reach::Fixed("empty; the algebra has no operation that attaches VPC interfaces."),
    ),
    (
        "Vpc.peerings",
        Reach::Derived(
            "collected from the peering table by `Overlay::validate`, not by the algebra",
        ),
    ),
    (
        "VpcPeering.name",
        Reach::Determined("`PeeringHandle::name`"),
    ),
    (
        "VpcPeering.no_multipath",
        Reach::Fixed(
            "false; the algebra never disables multipath. Only the Kubernetes converter sets \
             this from `GatewayAgentPeerings::no_multi_path`.",
        ),
    ),
    (
        "VpcPeering.left",
        Reach::Determined("the peering's left handle"),
    ),
    (
        "VpcPeering.right",
        Reach::Determined("the peering's right handle"),
    ),
    (
        "VpcPeering.gwgroup",
        Reach::Fixed("the default group; the algebra only calls `with_default_group`."),
    ),
    ("VpcPeering.acl", Reach::Spans(&["absent", "present"])),
    ("Acl.default", Reach::Spans(&["allow", "deny"])),
    ("Acl.rules", Reach::Spans(&["1", "2", "3"])),
    (
        "AclRule.name",
        Reach::Determined("the two vpc handles, as `<from>-to-<to>`, and `-except` for a denial"),
    ),
    (
        "AclRule.from",
        Reach::Determined("the vpc handle on the rule's side"),
    ),
    (
        "AclRule.to",
        Reach::Determined("the vpc handle on the other side"),
    ),
    ("AclRule.action", Reach::Spans(&["allow", "deny"])),
    ("AclRule.scope", Reach::Spans(&["flow", "packet"])),
    (
        "AclRule.log",
        Reach::Fixed("false. Nothing generated asks for a rule's verdict to be logged."),
    ),
    (
        "AclPattern.src",
        Reach::Determined(
            "empty, or the excepted expose's private prefix from its peering, side and slot",
        ),
    ),
    (
        "AclPattern.dst",
        Reach::Fixed(
            "empty, so `AclRule::validate` fills it in from the `to` manifest and every generated \
             rule reaches all of what its far side advertises. `AclPattern.src` is narrowed by \
             `Guard::PermitExcept` and this is not, and the asymmetry is deliberate: a source \
             prefix names the expose whose traffic it is, and a destination prefix names whichever \
             of the peer's exposes a load happens to aim at -- which is `peer_of`'s choice, so \
             predicting the effect would mean keeping a copy of it.",
        ),
    ),
    (
        "AclPattern.src_any_ports",
        Reach::Fixed(
            "empty -- the survey renders it as a count of zero. A `match` naming ports but no \
             address is a shape the k8s converter produces and nothing generated does.",
        ),
    ),
    (
        "AclPattern.dst_any_ports",
        Reach::Fixed("empty, for the same reason as `AclPattern.src_any_ports`."),
    ),
    (
        "AclPattern.proto",
        Reach::Fixed(
            "`Any`. Narrowing a rule to a protocol is what `acl_filter`'s own generator is aimed \
             at, and a rule that discriminates is one a property here would have to evaluate.",
        ),
    ),
    (
        "VpcManifest.name",
        Reach::Determined("the side's vpc handle"),
    ),
    (
        "VpcManifest.exposes",
        Reach::Determined("one per `AddExpose`, in slot order"),
    ),
    (
        "VpcExpose.default",
        Reach::Fixed("false; neither `VpcExpose::empty` nor any operation sets it."),
    ),
    (
        "VpcExpose.ips",
        Reach::Determined("one prefix, from the expose's peering, side and slot"),
    ),
    ("VpcExpose.ips.ports", Reach::Spans(&["set", "unset"])),
    (
        "VpcExpose.nots",
        Reach::Fixed("empty; the algebra never excludes addresses from an expose."),
    ),
    ("VpcExpose.nat", Reach::Spans(&["absent", "present"])),
    (
        "VpcExposeNat.as_range",
        Reach::Determined("one prefix in the translated pool, from peering, side and slot"),
    ),
    (
        "VpcExposeNat.as_range.ports",
        Reach::Spans(&["set", "unset"]),
    ),
    (
        "VpcExposeNat.not_as",
        Reach::Fixed("empty, for the same reason as `VpcExpose.nots`."),
    ),
    (
        "VpcExposeNat.config",
        Reach::Spans(&["masquerade", "port-forwarding", "static"]),
    ),
    (
        "VpcExposeNat.proto",
        Reach::Fixed("`Any`; no operation restricts the protocol to TCP or UDP."),
    ),
    (
        "VpcExposeMasquerade.idle_timeout",
        Reach::Fixed(
            "absent; the algebra always calls `make_masquerade(None)`, leaving custom \
             timeouts untested.",
        ),
    ),
    ("VpcExposeStaticNat", Reach::Spans(&["constructed"])),
    (
        "VpcExposePortForwarding.idle_timeout",
        Reach::Fixed(
            "absent. `make_port_forwarding(None, ..)` is the only call, for the same reason \
             `VpcExposeMasquerade.idle_timeout` is absent: the flavour is reachable now, but \
             nothing asks for a timeout, so no flow ages out under a configuration that set one.",
        ),
    ),
];

#[derive(Default)]
struct Observed(BTreeMap<&'static str, BTreeSet<String>>);

impl Observed {
    fn note(&mut self, field: &'static str, value: impl Into<String>) {
        self.0.entry(field).or_default().insert(value.into());
    }

    fn count(&mut self, field: &'static str, n: usize) {
        self.note(field, n.to_string());
    }

    fn prefixes(&mut self, field: &'static str, set: &PrefixPortsSet) {
        let listed: Vec<String> = set
            .into_iter()
            .map(|entry| entry.prefix().to_string())
            .collect();
        self.note(field, listed.join(", "));
    }

    fn ports(&mut self, field: &'static str, set: &PrefixPortsSet) {
        self.note(
            field,
            if set.into_iter().any(|entry| entry.ports().is_some()) {
                "set"
            } else {
                "unset"
            },
        );
    }
}

fn survey(overlay: &Overlay, seen: &mut Observed) {
    let Overlay {
        vpc_table,
        peering_table,
    } = overlay;
    seen.count("Overlay.vpc_table", vpc_table.len());
    seen.count("Overlay.peering_table", peering_table.len());

    for vpc in vpc_table.values() {
        let Vpc {
            name,
            id,
            vni,
            interfaces,
            peerings,
        } = vpc;
        seen.note("Vpc.name", name.clone());
        seen.note("Vpc.id", id.to_string());
        seen.note("Vpc.vni", vni.as_u32().to_string());
        seen.count("Vpc.interfaces", interfaces.values().count());
        seen.count("Vpc.peerings", peerings.len());
    }

    for peering in peering_table.values() {
        let VpcPeering {
            name,
            left,
            right,
            gwgroup,
            acl,
            no_multipath,
        } = peering;
        seen.note("VpcPeering.name", name.clone());
        seen.note("VpcPeering.gwgroup", gwgroup.clone());
        seen.note(
            "VpcPeering.acl",
            if acl.is_some() { "present" } else { "absent" },
        );
        seen.note("VpcPeering.no_multipath", no_multipath.to_string());
        if let Some(acl) = acl {
            survey_acl(acl, seen);
        }
        for (side, manifest) in [("VpcPeering.left", left), ("VpcPeering.right", right)] {
            seen.note(side, manifest.name.clone());
            survey_manifest(manifest, seen);
        }
    }
}

fn survey_acl(acl: &Acl, seen: &mut Observed) {
    let Acl { default, rules } = acl;
    seen.note("Acl.default", action(*default));
    seen.count("Acl.rules", rules.len());
    for rule in rules {
        let AclRule {
            name,
            from,
            to,
            action: verdict,
            pattern,
            scope,
            log,
        } = rule;
        seen.note("AclRule.name", name.clone());
        seen.note("AclRule.from", from.clone());
        seen.note("AclRule.to", to.clone());
        seen.note("AclRule.action", action(*verdict));
        seen.note(
            "AclRule.scope",
            match scope {
                AclScope::Flow => "flow",
                AclScope::Packet => "packet",
            },
        );
        seen.note("AclRule.log", log.to_string());

        let AclPattern {
            src,
            dst,
            src_any_ports,
            dst_any_ports,
            proto,
        } = pattern;
        seen.prefixes("AclPattern.src", src);
        seen.prefixes("AclPattern.dst", dst);
        seen.count("AclPattern.src_any_ports", src_any_ports.len());
        seen.count("AclPattern.dst_any_ports", dst_any_ports.len());
        seen.note(
            "AclPattern.proto",
            match proto {
                AclProtoMatch::Tcp => "tcp".to_owned(),
                AclProtoMatch::Udp => "udp".to_owned(),
                AclProtoMatch::Other(number) => format!("other({number})"),
                AclProtoMatch::Any => "any".to_owned(),
            },
        );
    }
}

fn action(action: AclAction) -> &'static str {
    match action {
        AclAction::Allow => "allow",
        AclAction::Deny => "deny",
    }
}

fn survey_manifest(manifest: &VpcManifest, seen: &mut Observed) {
    let VpcManifest { name, exposes } = manifest;
    seen.note("VpcManifest.name", name.clone());
    seen.count("VpcManifest.exposes", exposes.len());
    for expose in exposes {
        let VpcExpose {
            default,
            ips,
            nots,
            nat,
        } = expose;
        seen.note("VpcExpose.default", default.to_string());
        seen.prefixes("VpcExpose.ips", ips);
        seen.ports("VpcExpose.ips.ports", ips);
        seen.prefixes("VpcExpose.nots", nots);
        seen.note(
            "VpcExpose.nat",
            if nat.is_some() { "present" } else { "absent" },
        );
        if let Some(nat) = nat {
            survey_nat(nat, seen);
        }
    }
}

fn survey_nat(nat: &VpcExposeNat, seen: &mut Observed) {
    let VpcExposeNat {
        as_range,
        not_as,
        config,
        proto,
    } = nat;
    seen.prefixes("VpcExposeNat.as_range", as_range);
    seen.ports("VpcExposeNat.as_range.ports", as_range);
    seen.prefixes("VpcExposeNat.not_as", not_as);
    seen.note(
        "VpcExposeNat.proto",
        match proto {
            L4Protocol::Tcp => "tcp",
            L4Protocol::Udp => "udp",
            L4Protocol::Any => "any",
        },
    );
    match config {
        VpcExposeNatConfig::Masquerade(VpcExposeMasquerade { idle_timeout }) => {
            seen.note("VpcExposeNat.config", "masquerade");
            seen.note(
                "VpcExposeMasquerade.idle_timeout",
                if idle_timeout.is_some() {
                    "present"
                } else {
                    "absent"
                },
            );
        }
        VpcExposeNatConfig::Static(VpcExposeStaticNat {}) => {
            seen.note("VpcExposeNat.config", "static");
            seen.note("VpcExposeStaticNat", "constructed");
        }
        VpcExposeNatConfig::PortForwarding(VpcExposePortForwarding { idle_timeout }) => {
            seen.note("VpcExposeNat.config", "port-forwarding");
            seen.note(
                "VpcExposePortForwarding.idle_timeout",
                if idle_timeout.is_some() {
                    "present"
                } else {
                    "absent"
                },
            );
        }
    }
}

const CASES: usize = 512;

/// Survey up to `CASES` configurations and count the draws.
///
/// The count is an out-parameter because `check!()` can return early without a value.
fn survey_drawn(seen: &RefCell<Observed>, drawn: &std::cell::Cell<usize>) {
    let seen = std::panic::AssertUnwindSafe(seen);
    let counter = std::panic::AssertUnwindSafe(drawn);
    bolero::check!()
        .with_generator(Sequence::default())
        .with_iterations(CASES)
        .for_each(|ops| {
            counter.set(counter.get() + 1);
            let overlay = Sequence::fold(ops)
                .overlay()
                .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));
            survey(&overlay, &mut seen.borrow_mut());
        });
}

/// Return the observed values and draw count.
///
/// Bolero stops at either `CASES` or `BOLERO_RANDOM_TEST_TIME_MS`. Emulated runs may hit the
/// time limit before collecting enough samples for coverage assertions.
fn census() -> (Observed, usize) {
    let seen = RefCell::new(Observed::default());
    let drawn = std::cell::Cell::new(0usize);
    survey_drawn(&seen, &drawn);
    (seen.into_inner(), drawn.get())
}

/// Require the full sample count before asserting coverage.
///
/// Short runs may miss rare values without indicating a generator regression. They still
/// exercise the generator and survey.
fn enough_draws(drawn: usize) -> bool {
    if drawn >= CASES {
        return true;
    }
    eprintln!(
        "coverage assertions skipped: Bolero completed {drawn}/{CASES} draws. Increase \
         BOLERO_RANDOM_TEST_TIME_MS to collect the full sample."
    );
    false
}

#[test]
fn every_surveyed_field_is_classified() {
    let (seen, drawn) = census();
    let surveyed: BTreeSet<&str> = seen.0.keys().copied().collect();
    let classified: BTreeSet<&str> = REACH.iter().map(|(field, _)| *field).collect();

    let unclassified: Vec<&&str> = surveyed.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "surveyed fields lack a REACH classification: {unclassified:?}; classify each as \
         Spans, Determined, Derived, or Fixed"
    );

    let unreachable_by_construction: BTreeSet<&str> = REACH
        .iter()
        .filter(
            |(_, reach)| matches!(reach, Reach::Fixed(why) if why.contains("never constructed")),
        )
        .map(|(field, _)| *field)
        .collect();
    let missing: Vec<&&str> = classified
        .difference(&surveyed)
        .filter(|field| !unreachable_by_construction.contains(**field))
        .collect();
    // Short runs may miss classified fields. The unclassified-field check above is independent
    // of sample size.
    assert!(
        missing.is_empty() || !enough_draws(drawn),
        "classified fields were not surveyed: {missing:?}; check for removed fields or \
         incomplete survey code"
    );
}

#[test]
fn the_algebra_reaches_what_it_is_recorded_to_reach() {
    let (seen, drawn) = census();
    if !enough_draws(drawn) {
        return;
    }

    for (field, reach) in REACH {
        let Some(values) = seen.0.get(field) else {
            continue;
        };
        let rendered: Vec<&str> = values.iter().map(String::as_str).collect();
        match reach {
            Reach::Spans(expected) => assert_eq!(
                rendered, *expected,
                "`{field}` expected {expected:?}; observed {rendered:?} in {drawn} draws"
            ),
            Reach::Determined(by) => assert!(
                values.len() > 1,
                "`{field}` should vary with {by}, but {drawn} draws produced only \
                 {rendered:?}; check the generator and classification"
            ),
            Reach::Derived(_) => {}
            Reach::Fixed(why) => assert_eq!(
                values.len(),
                1,
                "`{field}` is classified as fixed ({why}), but {drawn} draws produced \
                 {rendered:?}; update the classification if the algebra changed"
            ),
        }
    }
}

#[test]
fn report_what_the_algebra_reaches() {
    let counted = |wanted: fn(&Reach) -> bool| -> usize {
        REACH.iter().filter(|(_, reach)| wanted(reach)).count()
    };
    eprintln!(
        "overlay fields: {} total, {} spanning, {} determined, {} derived, {} fixed:",
        REACH.len(),
        counted(|reach| matches!(reach, Reach::Spans(_))),
        counted(|reach| matches!(reach, Reach::Determined(_))),
        counted(|reach| matches!(reach, Reach::Derived(_))),
        counted(|reach| matches!(reach, Reach::Fixed(_))),
    );
    for (field, reach) in REACH {
        match reach {
            Reach::Spans(values) => eprintln!("  spans      {field}: {values:?}"),
            Reach::Determined(by) => eprintln!("  determined {field}: by {by}"),
            Reach::Derived(how) => eprintln!("  derived    {field}: {how}"),
            Reach::Fixed(why) => eprintln!("  FIXED      {field}: {why}"),
        }
    }
}
